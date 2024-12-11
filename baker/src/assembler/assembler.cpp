#include "assembler.h"
#include <algorithm>

uint32_t align_up(uint32_t val, uint32_t alignment) {
    uint32_t r = val % alignment;
    if (!r)
        return val;

    return val + alignment - r;
}

SECTION* new_sect(ASSEMBLED_BINARY* s, std::string name, uint64_t characteristics) {
    SECTION* sect = new SECTION{};
    assert(name.size() < IMAGE_SIZEOF_SHORT_NAME);
    memcpy(sect->hdr.Name, name.c_str(), name.size());
    sect->hdr.Characteristics = characteristics;

    s->sections.push_back(sect);
    return sect;
}

void update_sections(ASSEMBLED_BINARY* s) {
    for (int i = 0; i < s->sections.size(); i++) {
        SECTION*              sect = s->sections[i];
        IMAGE_SECTION_HEADER* hdr  = &sect->hdr;

        // size
        hdr->SizeOfRawData    = align_up(sect->bytes.size(), s->file_alignment);
        hdr->Misc.VirtualSize = sect->bytes.size() + sect->uninitialized_size;

        // file offset & rva
        if (i == 0) {
            hdr->PointerToRawData = 0x400;  // size of pe header
            hdr->VirtualAddress   = 0x1000;
        } else {
            SECTION* prev_sect = s->sections[i - 1];
            hdr->PointerToRawData = prev_sect->hdr.PointerToRawData + prev_sect->hdr.SizeOfRawData;
            hdr->VirtualAddress   = align_up(prev_sect->hdr.VirtualAddress + prev_sect->hdr.SizeOfRawData, s->section_alignment);
        }
    }
}

uint32_t calculate_pehdr_size(ASSEMBLED_BINARY* s) {
    return sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + (s->sections.size() * sizeof(IMAGE_SECTION_HEADER));
}

uint32_t calculate_binary_file_size(ASSEMBLED_BINARY* s) {
    size_t filesize = 0x400;
    for (SECTION* sect : s->sections) {
        if (sect->bytes.empty())
            continue;

        filesize += sect->hdr.SizeOfRawData;
    }
    return filesize;
}

uint32_t calculate_binary_virtual_size(ASSEMBLED_BINARY* s) {
    size_t filesize = 0x1000;
    for (SECTION* sect : s->sections) {
        if (empty(sect->bytes))
            continue;

        filesize += align_up(sect->hdr.SizeOfRawData, s->section_alignment);
    }
    return filesize;
}

ASSEMBLED_BINARY build_pe(const BINARY* bin_) {
    ASSEMBLED_BINARY s = {};

    binary_duplicate(bin_, &s.bin);
    s.entry_point        = 0;
    s.image_base         = 0x140000000;
    s.section_alignment  = 0x1000;
    s.file_alignment     = 0x200;

    auto& bin            = s.bin;
    auto& import_modules = bin.import_modules;
    auto& basic_blocks   = bin.basic_blocks;
    auto& data_blocks    = bin.data_blocks;
    auto& symbols        = bin.symbols;
    
    logger_reset_indentation();
    logger_log(WHITE, "", WHITE, "--------------------------------------------\n");
    logger_log(WHITE, "", WHITE, "-----------ASSEMBLING-PE--------------------\n");
    logger_log(WHITE, "", WHITE, "--------------------------------------------\n");


    logger_log(WHITE, "", WHITE, "applying fixes to moved away basic blocks..\n");

    // apply fixes to basic blocks
    // with fallthrough blocks that is not right after it
    for (int i = 0; i < basic_blocks.size(); i++) {
        BASIC_BLOCK* bb = basic_blocks[i];

        if (!bb->fallthrough_sym_id)
            continue;

        if (i < (basic_blocks.size() - 1) && basic_blocks[i + 1]->id == bb->fallthrough_sym_id)
            continue;

        bb->push(Jmp(ImmRel(bb->fallthrough_sym_id)));
    }

    //
    // generate IAT
    //

    sym_id_t iat_sym_id = nullsid;
    size_t   iat_size   = 0;

    if (!import_modules.empty()) {
        logger_reset_indentation();
        logger_log(
            WHITE, "BUILDING", 
            WHITE, "IMPORT TABLE\n");

        // import descriptors block
        DATA_BLOCK* descs = bin.data_block(
            (import_modules.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR), 
            true, "mod_descriptors");
        
        // module names block
        DATA_BLOCK* modnames = bin.data_block(0, true, "mod_names");

        for (int i = 0; i < import_modules.size(); i++) {
            IMPORT_MODULE* mod = import_modules[i];
            
            logger_reset_indentation();
            logger_log(
                WHITE, "", 
                WHITE, fmtf("import module: %s [\n", mod->name.c_str()));
            logger_indent();

            // descriptor struct
            auto desc = STRUCT_SCHEMA(IMAGE_IMPORT_DESCRIPTOR, i * sizeof(IMAGE_IMPORT_DESCRIPTOR));

            // module name
            SYMBOL* str_name = modnames->push_str(mod->name);
            descs->data_sym(SS_MEMBER(desc, Name), TARGET_TYPE_RVA, str_name->id);
            // thunk tables

            DATA_BLOCK* name_thunks   = bin.data_block((mod->routines.size() + 1) * 8, true, "name_thunks");
            DATA_BLOCK* routine_names = bin.data_block(0, true, "routine_names");
            DATA_BLOCK* thunks        = bin.data_block((mod->routines.size() + 1) * 8, true, "thunks");
            
            // convert import symbols to data symbols
            for (int j = 0; j < mod->routines.size(); j++) {
                SYMBOL* sym = bin.symbols[mod->routines[j]->id];
                assert(sym != nullptr && sym->type == SYMBOL_TYPE_IMPORT);
                sym->type      = SYMBOL_TYPE_DATA;
                sym->db        = thunks;
                sym->db_offset = j * 8;
                sym->db->dboffset_to_sym[sym->db_offset] = sym;

                logger_log(
                    WHITE, "converted",
                    WHITE, fmtf("import sym: { %d, %s }, to data symbol\n", sym->id, sym->name.c_str()));
            }

            // routine
            for (int j = 0; j < mod->routines.size(); j++) {
                const auto& name = mod->routines[j]->name;

                logger_log(
                    WHITE, "", 
                    WHITE, fmtf("--> %s[\n", name.c_str()));
                logger_indent();

                SYMBOL* imp_by_name = routine_names->push_val(0, 2);
                routine_names->push_str(name);
                
                name_thunks->data_sym(j * 8, TARGET_TYPE_RVA, imp_by_name->id);
                thunks     ->data_sym(j * 8, TARGET_TYPE_RVA, imp_by_name->id);
            
                logger_unindent();
                logger_log(
                    WHITE, "", 
                    WHITE, "]\n");
            }

            descs->data_sym(SS_MEMBER(desc, OriginalFirstThunk), TARGET_TYPE_RVA, name_thunks->data_sym(0)->id);
            descs->data_sym(SS_MEMBER(desc, FirstThunk),         TARGET_TYPE_RVA, thunks->data_sym(0)->id);

            iat_size += name_thunks->bytes.size();
            iat_size += routine_names->bytes.size();
            iat_size += thunks->bytes.size();

            logger_unindent();
            logger_log(
                WHITE, "", 
                WHITE, "]\n");
        }

        iat_size += descs->bytes.size();
        iat_size += modnames->bytes.size();

        iat_sym_id = descs->data_sym(0)->id;
    }

    //
    // generate sections
    //

    s.text_sect  = new_sect(&s, ".text",  IMAGE_SCN_CNT_CODE             | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
    s.rdata_sect = new_sect(&s, ".rdata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    s.data_sect  = new_sect(&s, ".data",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    update_sections(&s);

    // insert and map code
    // .text section
    // re-encode all immediates to use largest branch size (rel32)
    logger_log(WHITE, "", WHITE, "mapping and writing code to .text\n");
    for (BASIC_BLOCK* bb : basic_blocks) {
        SECTION* sect       = s.text_sect;
        uint32_t file_start = sect->hdr.PointerToRawData + sect->bytes.size();
        uint32_t rva_start  = sect->hdr.VirtualAddress   + sect->bytes.size();

        s.sym_to_offset[bb->id] = file_start;
        s.sym_to_rva   [bb->id] = rva_start;

        logger_log(
            WHITE, "",
            BRIGHT_BLUE, fmtf("basic block: %d   %s\n",
                bb->id, bin.symbols[bb->id]->name.c_str()));

        for (uint32_t instr_offset = 0; instr_t& instr : bb->instrs) {
            uint32_t instr_rva     = rva_start + instr_offset;
            uint64_t curr_instr_va = s.image_base + instr_rva;
            
            // decode
            auto [dec_ctx, dec_instr] = decode_instr(&s.bin.decoder, instr.bytes, instr.len);

            if (dec_instr.raw.imm[0].is_relative) {
                assert(dec_instr.operand_count_visible == 1);

                logger_log(
                    WHITE, fmtf("<+%04X>", 
                        rva_start + instr_offset),
                    WHITE, fmtf("bb + %-4d : %s\t <forced rel32 branch size> \n",
                        instr_offset,  serialize_instr(&s.bin, &instr).c_str()));

                // have to retrieve it like this to avoid weird sign bugs with zydis
                sym_id_t target_sym_id = nullsid;
                memcpy(&target_sym_id, instr.bytes + dec_instr.raw.imm[0].offset,
                    dec_instr.raw.imm[0].size / 8);

                assert(target_sym_id < bin.symbols.size());

                // force extend to 32 bit branch width
                instr_store_val(&instr, 0x12345678,
                    &s.bin.decoder, &dec_instr, &dec_ctx, curr_instr_va);

                // copy in symbol id
                memcpy(instr.bytes + instr.len - 4, &target_sym_id, 4);
            } else {
                logger_log(
                    WHITE, fmtf("<+%04X>",
                        rva_start + instr_offset),
                    WHITE, fmtf("bb + %-4d : %s\n",
                        instr_offset, serialize_instr(&s.bin, &instr).c_str()));
            }

            sect->bytes.insert(end(sect->bytes),
                instr.bytes,
                instr.bytes + instr.len);

            instr_offset += instr.len;
        }
    }
    update_sections(&s);

    // insert and map data
    // .rdata & .data sections
    std::sort(begin(data_blocks), end(data_blocks), 
        [&](const DATA_BLOCK* a, const DATA_BLOCK* b) {
            // read only before readwrite
            if (a->read_only != b->read_only)
                return a->read_only > b->read_only; // true > false

            // initialized before uninitialized
            if (a->uninitialized != b->uninitialized)
                return a->uninitialized < b->uninitialized; // false < true
            
            return false;
        });

    for (DATA_BLOCK* db : bin.data_blocks) {
        SECTION* sect       = db->read_only ? s.rdata_sect : s.data_sect;
        uint32_t file_start = sect->hdr.PointerToRawData + sect->bytes.size();
        uint32_t rva_start  = sect->hdr.VirtualAddress + sect->bytes.size();

        s.db_to_sect[db] = sect;
        s.db_to_offset[db] = file_start;
        s.db_to_rva[db] = rva_start;

        logger_log(
            WHITE, "",
            BRIGHT_RED, fmtf("filebuf[0x%04X] <+0x%04X> %s, size: 0x%X\n",
                file_start, rva_start, db->name.c_str(), db->bytes.size()));

        if (db->uninitialized) {
            sect->uninitialized_size += db->bytes.size();
        } else {
            sect->bytes.insert(end(sect->bytes),
                db->bytes.begin(),
                db->bytes.end());
        }

        for (auto& [db_offset, sym] : db->dboffset_to_sym) {
            s.sym_to_offset[sym->id] = file_start + db_offset;
            s.sym_to_rva[sym->id]     = rva_start + db_offset;

            logger_log(
                WHITE, fmtf("<+%04X>", rva_start + db_offset),
                WHITE, fmtf("%s + %04X, db+%04X, sym_%d\n",
                    sect->hdr.Name, s.sym_to_rva[sym->id] - sect->hdr.VirtualAddress,
                    db_offset, sym->id));
        }
        update_sections(&s);
    }

    // allocate file buffer
    s.filebuf.insert(end(s.filebuf), calculate_binary_file_size(&s), 0);


    // create a unhooked formatter
    // since we are not printing instructions with symbol ids anymore
    ZydisFormatter unhooked_formatter = {};
    zy_expect_success(
        ZydisFormatterInit(&unhooked_formatter, ZYDIS_FORMATTER_STYLE_INTEL));

    zy_expect_success(
        ZydisFormatterSetProperty(&unhooked_formatter,
            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true)
    );

    zy_expect_success(
        ZydisFormatterSetProperty(&unhooked_formatter,
            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, true)
    );

    // resolve relative data symbols
    for (SYMBOL* sym : bin.symbols) {
        if (sym->type == SYMBOL_TYPE_RELATIVE_INFO) {
            s.sym_to_offset [sym->id] = sym->rel_offset;
            s.sym_to_rva    [sym->id] = sym->rel_offset;
        }
    }

    // resolve & write assembly to file buffer
    // instruction holding: symbol id --> rva delta
    logger_log(WHITE, "", WHITE, "resolving assembly and writing to file buffer\n");

    for (const BASIC_BLOCK* bb : basic_blocks) {
        uint32_t file_start = s.sym_to_offset[bb->id];
        uint32_t rva_start  = s.sym_to_rva[bb->id];

        logger_log(
            WHITE, "",
            BRIGHT_BLUE, fmtf("basic block: %d   %s\n",
                bb->id, bin.symbols[bb->id]->name.c_str()));

        for (uint32_t instr_offset = 0; const instr_t& instr : bb->instrs) {
            instr_t resolved_instr = instr;

            // decode
            auto [dec_ctx, dec_instr] = decode_instr(&s.bin.decoder, instr.bytes, instr.len);
            
            // resolve symbol id into rva delta
            sym_id_t target_sym_id = nullsid;

            if (dec_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
                if (dec_instr.raw.imm[0].is_relative) {
                    assert(dec_instr.raw.imm[0].size == 32);
                    target_sym_id = get_sym_id(&instr, &dec_instr);

                    uint32_t target_rva = s.sym_to_rva[target_sym_id];
                    uint32_t delta      = target_rva - (rva_start + instr_offset + instr.len);

                    memcpy(resolved_instr.bytes + instr.len - 4, &delta, 4);
                }

                else if (dec_instr.raw.disp.offset != 0
                    && dec_instr.raw.modrm.mod == 0
                    && dec_instr.raw.modrm.rm == 5) {
                    target_sym_id = get_sym_id(&instr, &dec_instr);

                    uint32_t target_rva = s.sym_to_rva[target_sym_id];
                    uint32_t delta      = target_rva - (rva_start + instr_offset + instr.len);

                    memcpy(resolved_instr.bytes + dec_instr.raw.disp.offset, &delta, 4);
                }
            }

            if (instr.flags & INSTR_FLAG_MEM_IDX) {
                assert(!(dec_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE));

                target_sym_id = get_sym_id(&instr, &dec_instr);
                uint32_t target_rva = s.sym_to_rva[target_sym_id];
                memcpy(resolved_instr.bytes + dec_instr.raw.disp.offset, &target_rva, 4);
            }

            memcpy(&s.filebuf[file_start + instr_offset], resolved_instr.bytes, resolved_instr.len);

            logger_log(
                WHITE, fmtf("<+%04X>", rva_start + instr_offset),
                WHITE, fmtf("bb + %-4d : %-30s  %s\n",
                    instr_offset,
                    serialize_instr_ex(
                        &s.bin.decoder,
                        &unhooked_formatter,
                        &resolved_instr).c_str(),
                    target_sym_id ? std::to_string(target_sym_id).c_str() : ""
                )
            );

            instr_offset += instr.len;
        }

    }

    // write data blocks to file buffer
    uint32_t last_file_start = 0;
    uint32_t last_file_end = 0;
    
    for (DATA_BLOCK* db : data_blocks) {
        uint32_t file_offset = s.db_to_offset[db];
        uint32_t rva         = s.db_to_rva[db];
        memcpy(&s.filebuf[file_offset], db->bytes.data(), db->bytes.size());
        
        // spot overlapping errors
        assert(file_offset + db->bytes.size() <= last_file_start 
            || file_offset >= last_file_end);

        logger_log(
            WHITE, fmtf("%s", db->name.c_str(), s.db_to_sect[db]->hdr.Name),
            WHITE, fmtf("inserted db: { %s, size: 0x%X, file offset: 0x%04X, rva: 0x%04X }\n",
                db->name.c_str(), db->bytes.size(), file_offset, rva));

        last_file_start = file_offset;
        last_file_end = file_offset + db->bytes.size();
    }


    // resolve data symbols
    // (resolving pointers or rvas to other symbols)

    // key: page frame number
    // val: block (set of information)
    std::map<uint32_t, std::set<uint16_t>> reloc_blocks = {};
    
    for (DATA_BLOCK* db : data_blocks) {
        for (auto& [db_offset, sym] : db->dboffset_to_sym) {
            if (!sym->target_sym_id)
                continue;

            uint32_t file_offset = s.sym_to_offset[sym->id];
            uint32_t rva         = s.sym_to_rva[sym->id];

            if (sym->target_type == TARGET_TYPE_POINTER) {
                assert(!db->uninitialized);
                assert(db_offset <= sym->db->bytes.size() - 8);

                uint64_t target_va = s.image_base + s.sym_to_rva[sym->target_sym_id];
                memcpy(&s.filebuf[file_offset], &target_va, 8);

                uint32_t pfn = rva >> 12;

                // get current block
                auto& block = reloc_blocks[pfn];
                block.emplace(rva & 0xFFF);

                logger_log(
                    WHITE, "pointer target",
                    WHITE, fmtf("(<%s+%d> --> 0x%X) marked for relocation\n",
                        db->name.c_str(), db_offset, sym->target_sym_id));
            }

            if (sym->target_type == TARGET_TYPE_RVA) {
                assert(!db->uninitialized);
                assert(db_offset <= sym->db->bytes.size() - 4);
                uint32_t target_rva = s.sym_to_rva[sym->target_sym_id];
                memcpy(&s.filebuf[file_offset], &target_rva, 4);

                logger_log(
                    WHITE, "rva target",
                    WHITE, fmtf("(%d --> %d) = 0x%X\n", 
                        sym->id, sym->target_sym_id, target_rva));
            }
        }
    }

    //
    // todo: generate exception table
    //


    //
    // generate the base relocation table
    //
    
    struct BASERELOC_ENTRY {
        uint16_t offset : 12;
        uint16_t type    : 4;
    };

    SECTION* reloc_sect = nullptr;
    if (!reloc_blocks.empty()) {
        reloc_sect = new_sect(&s, ".reloc", IMAGE_SCN_MEM_READ);
        auto& reloc_data = reloc_sect->bytes;

        for (const auto& [pfn, block] : reloc_blocks) {
            uint32_t block_offset = reloc_data.size();
            uint32_t padding      = (block.size() % 2) * sizeof(BASERELOC_ENTRY);
            uint32_t block_size   = sizeof(IMAGE_BASE_RELOCATION) 
                + (sizeof(BASERELOC_ENTRY) * block.size()) 
                + padding;

            reloc_data.insert(end(reloc_data), block_size, 0);
            auto* hdr        = reinterpret_cast<IMAGE_BASE_RELOCATION*>    (&reloc_data[block_offset]);
            auto* entries    = reinterpret_cast<BASERELOC_ENTRY*>        (&reloc_data[block_offset + sizeof(IMAGE_BASE_RELOCATION)]);

            hdr->VirtualAddress = pfn << 12;
            hdr->SizeOfBlock    = reloc_data.size() - block_offset;

            for (int i = 0; auto offset : block) {
                entries[i++] = { offset, IMAGE_REL_BASED_DIR64 };
            }
        }

        update_sections(&s);
        
        uint32_t file_offset = s.filebuf.size();
        s.filebuf.insert(end(s.filebuf), reloc_sect->hdr.SizeOfRawData, 0);
        memcpy(&s.filebuf[file_offset], reloc_data.data(), reloc_data.size());
    }

    // set entry point
    if (bin_->entry_point) {
        s.entry_point = s.sym_to_rva[bin_->entry_point->id];
    } else {
        s.entry_point = s.text_sect->hdr.VirtualAddress;
    }

    // generate pe headers
    auto doshdr = reinterpret_cast<IMAGE_DOS_HEADER*>(&s.filebuf[0]);
    *doshdr = {
        .e_magic  = IMAGE_DOS_SIGNATURE,
        .e_lfanew = sizeof(IMAGE_DOS_HEADER),
    };

    auto nthdrs = reinterpret_cast<IMAGE_NT_HEADERS*>(&s.filebuf[doshdr->e_lfanew]);
    *nthdrs = {
        .Signature = IMAGE_NT_SIGNATURE,
        .FileHeader = {
            .Machine              = IMAGE_FILE_MACHINE_AMD64,
            .NumberOfSections     = (WORD)s.sections.size(),
            .SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER),
            .Characteristics      = IMAGE_FILE_EXECUTABLE_IMAGE,
        },

        .OptionalHeader = {
            .Magic                = IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            .AddressOfEntryPoint  = s.entry_point,
            .BaseOfCode           = s.text_sect->hdr.VirtualAddress,
            .ImageBase            = s.image_base,
            .SectionAlignment     = s.section_alignment,
            .FileAlignment        = s.file_alignment,

            .MajorOperatingSystemVersion = 6,
            .MinorOperatingSystemVersion = 0,
            .MajorSubsystemVersion       = 6,
            .MinorSubsystemVersion       = 0,

            .SizeOfImage   = calculate_binary_virtual_size(&s),
            .SizeOfHeaders = calculate_pehdr_size(&s),

            .Subsystem          = IMAGE_SUBSYSTEM_WINDOWS_CUI,
            .DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_NO_SEH,

            .SizeOfStackReserve = 0x10000l,
            .SizeOfStackCommit  = 0x1000,
            .SizeOfHeapReserve  = 0x10000,
            .SizeOfHeapCommit   = 0x1000,

            .NumberOfRvaAndSizes = 16
        },
    };


    // set data directories
    if (!import_modules.empty()) {
        auto& dir           = nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        dir.VirtualAddress  = s.sym_to_rva[iat_sym_id];
        dir.Size            = iat_size;
    }

    if (!reloc_blocks.empty() && reloc_sect != NULL) {
        auto& dir = nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        dir.VirtualAddress    = reloc_sect->hdr.VirtualAddress;
        dir.Size            = reloc_sect->bytes.size();
    }

    // set section headers
    for (int i = 0; i < s.sections.size(); i++) {
        SECTION* sect = s.sections[i];

        if (sect->bytes.empty())
            continue;

        uint32_t hdr_offset = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));
        memcpy(&s.filebuf[hdr_offset], &sect->hdr, sizeof(IMAGE_SECTION_HEADER));
    }

    return s;
}



uint8_t* ASSEMBLED_BINARY::get_instr(BASIC_BLOCK* bb, instr_t* instr) {
    for (int bb_offset = 0; instr_t& curr_instr : bb->instrs) {
        if (&curr_instr == instr) {
            return &filebuf[sym_to_offset[bb->id] + bb_offset];
        }

        bb_offset += curr_instr.len;
    }
    return nullptr;
}

uint8_t* ASSEMBLED_BINARY::get_data(SYMBOL* data_sym) {
    return &filebuf[sym_to_offset[data_sym->id]];
}



void assembled_binary_print(ASSEMBLED_BINARY* asm_bin) {
    BINARY* bin = &asm_bin->bin;

    printf("--------------------------------------------\n");
    printf("--------ASSEMBLED-BINARY--------------------\n");
    printf("--------------------------------------------\n");

    printf_ex(BRIGHT_BLUE, "--------------CODE--------------------------\n");

    for (BASIC_BLOCK* bb : bin->basic_blocks) {
        printf_ex(BRIGHT_BLUE, "[basic block]: %d, size: %d   %s\n", bb->id, bb->size(), 
            bin->symbols[bb->id]->name.c_str());

        for (int bb_offset = 0; const instr_t& instr : bb->instrs) {
            printf("<+%0X>", asm_bin->sym_to_rva[bb->id] + bb_offset);
            printf("\t+%-4d: %s\n", bb_offset, serialize_instr(bin, &instr).c_str());

            bb_offset += instr.len;
        }

        printf("\t--> %d\n", bb->fallthrough_sym_id);
    }

    for (int sect_idx = 0; sect_idx < 2; sect_idx++) {
        // 0: .rdata
        // 1: .data

        if (sect_idx == 0)
            printf_ex(BRIGHT_RED, "----READ-ONLY-DATA--------------------------\n");

        if (sect_idx == 1)
            printf_ex(BRIGHT_MAGENTA, "--------------DATA--------------------------\n");

        for (DATA_BLOCK* db : bin->data_blocks) {
            if (sect_idx == 0 && db->read_only == false)
                continue;

            if (sect_idx == 1 && db->read_only == true)
                continue;

            printf_ex(sect_idx ? BRIGHT_MAGENTA : BRIGHT_RED,
                "[data block]: %s, size: %d\n", db->name.c_str(), db->bytes.size());

            struct LINE_INFO {
                SYMBOL* sym;
                int     rva;
                std::vector<uint8_t> bytes;
            };

            std::vector<LINE_INFO> lines = {};
            
            LINE_INFO line = {};
            for (int db_offset = 0; db_offset < db->bytes.size(); db_offset++) {
                uint8_t  byte = asm_bin->filebuf[asm_bin->db_to_offset[db] + db_offset];
                uint64_t rva  = asm_bin->db_to_rva[db] + db_offset;

                if (db_offset == 0) {
                    line.rva = rva;
                }

                if (db->dboffset_to_sym[db_offset]) {
                    if (db_offset) {
                        lines.push_back(line);
                        line     = {};
                        line.rva = rva;
                    }
                    line.sym = db->dboffset_to_sym[db_offset];
                }

                int line_max_len = 16;
                if (line.sym) {
                    if (line.sym->target_type == TARGET_TYPE_RVA) {
                        line_max_len = 4;
                    } else if (line.sym->target_type == TARGET_TYPE_POINTER) {
                        line_max_len = 8;
                    }
                }

                if (db_offset == db->bytes.size() - 1) {
                    line.bytes.push_back(byte);
                    lines.push_back(line);
                    line     = {};
                    line.rva = rva;
                } else {
                    if (line.bytes.size() == line_max_len) {
                        lines.push_back(line);
                        line     = {};
                        line.rva = rva;
                    }

                    line.bytes.push_back(byte);
                }
            }

            for (LINE_INFO& line : lines) {
                /*
                    tabing it out
                */
                printf("<+%0X>", line.rva);
                
                if (line.sym) {
                    SYMBOL* sym = line.sym;
                    if (sym->target_type == TARGET_TYPE_RVA)
                        printf("%-25s |", fmtf("[%-4d --rva-> %-4d]", sym->id, sym->target_sym_id).c_str());

                    if (sym->target_type == TARGET_TYPE_POINTER)
                        printf("%-25s |", fmtf("[%-4d --ptr-> %-4d]", sym->id, sym->target_sym_id).c_str());

                    if (sym->target_type == TARGET_TYPE_NONE)
                        printf("%-25s |", fmtf("[%d]", sym->id).c_str());
                } else {
                    printf("%-25s |", "");
                }

                /*
                    | 00 00 00 00 |text
                */
                std::string fmt = "";

                for (int j = 0; j < line.bytes.size(); j++)
                    fmt += fmtf("%02X ", line.bytes[j]);
                printf("%-48s|", fmt.c_str());

                for (int j = 0; j < line.bytes.size(); j++)
                    printf("%c", line.bytes[j]);

                printf("\n");
            }

            printf("\n");
        }
    }

    printf("--------------------------------------------\n");
    printf("--------------------------------------------\n");
}