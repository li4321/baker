#include "disassembler.h"
#include <queue>
#include <algorithm>



// spot bugs of rva_map not being synced with the symbols faster
void DISASSEMBLER::sym_rva_map_append(uint32_t rva) {
    if (bin.symbols.size())
        assert(sym_rva_map.size() == bin.symbols.size() - 1);
        
    sym_rva_map.push_back(rva);
}


RVA_MAP_ENTRY& DISASSEMBLER::queue_rva(uint32_t rva, sym_id_t label_id) {
    assert(rva_in_exec_sect(rva));
    assert(bin.symbols[label_id]->type == SYMBOL_TYPE_CODE);

    disasm_queue.push(rva);
    bin.basic_block(label_id);
    sym_rva_map_append(rva);

    return rva_map[rva] = { label_id, 0 };
}
    
RVA_MAP_ENTRY& DISASSEMBLER::queue_rva(uint32_t rva, std::string name) {
    assert(rva_in_exec_sect(rva));

    if (rva_map[rva].id) {
        // check if a symbol already exists for this rva
        auto& entry = queue_rva(rva, rva_map[rva].id);

        SYMBOL* sym = bin.symbols[entry.id];
        sym->name = name;

        return entry;
    } else {
        // create a new one
        disasm_queue.push(rva);
        BASIC_BLOCK* sym = bin.basic_block(name);
        sym_rva_map_append(rva);

        return rva_map[rva] = { sym->id, 0 };
    }
}

RVA_MAP_ENTRY& DISASSEMBLER::split_bb(uint32_t rva, std::string name) {
    int          instr_idx  = 0;
    BASIC_BLOCK* origbb = nullptr;

    // find the index to split at, by following the list backward
    for (int curr_rva = rva; true; instr_idx++) {
        auto& entry = rva_map[curr_rva];

        if (entry.blink) {
            curr_rva -= entry.blink;
            continue;
        }

        assert(entry.id);
        origbb = bin.symbols[entry.id]->bb;
        break;
    }

    logger_log(
        CYAN, "split_bb", 
        WHITE, fmtf("<+%X> sym_%d[%d -- %d] --> sym_%d\n", 
            rva, origbb->id, 
            instr_idx, origbb->instrs.size(), bin.symbols.size()));

    BASIC_BLOCK* newbb = bin.basic_block(name);
    sym_rva_map_append(rva);

    // change fallthrough
    newbb ->fall(origbb->fallthrough_sym_id);
    origbb->fall(newbb->id);
        
    // cut block
    newbb->instrs.insert(begin(newbb->instrs),
        begin(origbb->instrs) + instr_idx,
        end(origbb->instrs));
        
    origbb->instrs.erase(
        begin(origbb->instrs) + instr_idx,
        end(origbb->instrs));

    return rva_map[rva] = { newbb->id, 0 };
}

// main recursive disassembler function
void DISASSEMBLER::disassemble() {
    while (!disasm_queue.empty()) {
        uint32_t rva_start  = disasm_queue.front();
        uint32_t file_start = rva_to_offset(rva_start);
        assert(file_start);
        disasm_queue.pop();

        IMAGE_SECTION_HEADER* section  = rva_to_sect(rva_start);
        uint32_t              file_end = file_start + section->SizeOfRawData;
        assert(bin.symbols[rva_map[rva_start].id]->type == SYMBOL_TYPE_CODE);

        BASIC_BLOCK* currbb = bin.symbols[rva_map[rva_start].id]->bb;

        // instr_offset is offset of the instruction from file_start
        for (uint32_t instr_offset = 0; instr_offset < file_end;) {
            uint8_t* instr_ptr          = &filebuf[file_start + instr_offset];
            uint64_t curr_instr_va      = image_base + rva_start + instr_offset;
            int      remaining_sect_len = file_end - instr_offset;

            auto [dec_ctx, dec_instr] = 
                decode_instr(&bin.decoder, instr_ptr, remaining_sect_len);

            instr_t instr = {};
            instr.len = dec_instr.length;
            memcpy(instr.bytes, instr_ptr, instr.len);

            // if this is referencing something, we will store the target's symbol id into the instruction
            if (dec_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
                // immediate access (etc: jmp XX; call XX; ...), (code access)
                if (dec_instr.raw.imm[0].is_relative) {
                    assert(dec_instr.raw.imm[0].is_signed);

                    uint32_t target_rva = 
                        rva_start + instr_offset 
                        + dec_instr.length + dec_instr.raw.imm[0].value.s;
                        
                    auto& target_rva_entry = rva_map[target_rva];
                    assert(rva_in_exec_sect(target_rva));

                    // if the target is already in a discovered basic block
                    if (target_rva_entry.blink) {
                        target_rva_entry = split_bb(target_rva);

                        // if the target is in the same block, before this instruction
                        // we will add the instruction to the new basic block split off instead
                        if (rva_start <= target_rva && target_rva < rva_start + instr_offset)
                            currbb = bin.symbols[target_rva_entry.id]->bb;
                    } else if (!target_rva_entry.id) {
                        target_rva_entry = queue_rva(target_rva);
                    }

                    assert(!target_rva_entry.blink);
                    assert(target_rva_entry.id);

                    instr_store_val(&instr, target_rva_entry.id, 
                        &bin.decoder, &dec_instr, &dec_ctx, curr_instr_va);
                }

                // rip relative reference (etc: mov rax, [rip+XX]; ....) (code/data access)
                if (dec_instr.raw.disp.offset != 0
                    && dec_instr.raw.modrm.mod == 0
                    && dec_instr.raw.modrm.rm == 5) {
                    // in x86-64, the offset in rip relative instructions should be 4 bytes (i think)
                    assert(dec_instr.raw.disp.size == 32);

                    uint32_t target_rva    = 
                        rva_start + instr_offset 
                        + dec_instr.length + dec_instr.raw.disp.value;
                        
                    auto& target_rva_entry = rva_map[target_rva];

                    if (rva_in_exec_sect(target_rva)) {
                        if (target_rva_entry.blink) {
                            target_rva_entry = split_bb(target_rva);

                            // if we have splitted our own basic block
                            // then we will update currbb
                            if (rva_start <= target_rva && target_rva < rva_start + instr_offset)
                                currbb = bin.symbols[target_rva_entry.id]->bb;
                        }

                        if (dec_instr.mnemonic == ZYDIS_MNEMONIC_LEA && target_rva_entry.id == nullsid)
                            target_rva_entry = queue_rva(target_rva);
                    } else if (target_rva_entry.id == nullsid) {
                        assert(!target_rva_entry.blink);

                        uint32_t    db_offset = 0;
                        DATA_BLOCK* db = rva_to_containing_db(target_rva, &db_offset);
                        SYMBOL*        sym = nullptr;

                        if (db) {
                            sym = db->data_sym(db_offset);
                            sym_rva_map_append(target_rva);

                            // todo: should we analyze this data symbol?
                        }
                            
                        // addresses that does not land in a data block
                        // are marked as relative data symbols
                        // this should be a address within the PE header
                        else {
                            sym = bin.rel_info(target_rva);
                            sym_rva_map_append(target_rva);
                        }

                        target_rva_entry = rva_map[target_rva] = { sym->id, 0 };
                    }

                    assert(sizeof(target_rva_entry.id) == 4);
                    assert(target_rva_entry.id);
                    instr_store_val(&instr, target_rva_entry.id, 
                        &bin.decoder, &dec_instr, &dec_ctx, curr_instr_va);
                }
            }
            
            logger_log(WHITE, "", WHITE, fmtf("<+%04X>\t", rva_start + instr_offset));
            currbb->push(instr);

            // if this is a terminating instruction, end this block
            if (dec_instr.meta.category == ZYDIS_CATEGORY_RET ||
                dec_instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
                dec_instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                (dec_instr.meta.category == ZYDIS_CATEGORY_INTERRUPT && dec_instr.raw.imm[0].value.s == 0x29)) {
                
                // if this is a conditional branch
                // we will need to make this fall to the next block
                if (dec_instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
                    uint32_t fallthrough_rva = rva_start + instr_offset + dec_instr.length;

                    auto& rva_entry = rva_map[fallthrough_rva];
                    if (rva_entry.id) {
                            
                        if (rva_entry.blink)
                            rva_entry = split_bb(fallthrough_rva);

                        currbb->fall(rva_entry.id);
                    } else {
                        currbb->fall(queue_rva(fallthrough_rva).id);
                    }
                }
                    
                break;
            }
            
            instr_offset += dec_instr.length;

            // if we have entered into another discovered basic block
            // end the current block
            auto& rva_entry = rva_map[rva_start + instr_offset];
            if (rva_entry.id) {
                SYMBOL* sym = bin.symbols[rva_entry.id];

                // TODO: it *might* be possible to fall into a jump table
                //    (which would be marked as data, not code)
                assert(sym->type == SYMBOL_TYPE_CODE);
                currbb->fall(rva_entry.id);
                break;
            }

            // create rva entry for next instruction
            rva_entry = { 0, dec_instr.length };
        }
    }
}


void DISASSEMBLER::sort_basic_blocks() {
    // sort basic blocks
    // to be in order of rva
    auto& blocks = bin.basic_blocks;
    std::sort(begin(blocks), end(blocks),
        [&](BASIC_BLOCK* left, BASIC_BLOCK* right) {
            return (sym_rva_map[left->id] < sym_rva_map[right->id]);
        });
}


DISASSEMBLER* disassemble_pe(std::vector<uint8_t> filebuf) {
    DISASSEMBLER* s = new DISASSEMBLER{};
    s->filebuf    = filebuf;
    s->doshdr     = reinterpret_cast<IMAGE_DOS_HEADER*>(&s->filebuf[0]);
    s->nthdrs     = reinterpret_cast<IMAGE_NT_HEADERS*>(&s->filebuf[s->doshdr->e_lfanew]);
    s->datadir    = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(s->nthdrs->OptionalHeader.DataDirectory);
    s->sects      = IMAGE_FIRST_SECTION(s->nthdrs);
    s->image_base = s->nthdrs->OptionalHeader.ImageBase;

    // initialize rva map
    s->rva_map = std::vector<RVA_MAP_ENTRY>(
        s->nthdrs->OptionalHeader.SizeOfImage, RVA_MAP_ENTRY{});

    // sync sym_rva_map with the null symbol to placehold for symbol id 0
    s->sym_rva_map.push_back(0);
    
    s->create_section_dbs();
    s->parse_imports();
    s->parse_exceptions();
    s->parse_relocations();

    // disassemble starting from entry point
    uint32_t entry_rva   = s->nthdrs->OptionalHeader.AddressOfEntryPoint;
    auto&    entry_point = s->rva_map[entry_rva];
    if (entry_point.id == nullsid) 
        entry_point = s->queue_rva(entry_rva, "entrypoint");

    s->bin.set_entry(s->bin.symbols[entry_point.id]->bb);
    s->disassemble();
    s->sort_basic_blocks();

    s->collect_jump_tables();
    s->resolve_jpt_entries();
    s->disassemble();

    s->sort_basic_blocks();
    s->verify();
    return s;
}


DATA_BLOCK* DISASSEMBLED_BINARY::rva_to_db(uint32_t rva) {
    return rva_db_map[rva].db;
}

DATA_BLOCK* DISASSEMBLED_BINARY::rva_to_containing_db(uint32_t rva, uint32_t* db_offset) {
    auto it = std::lower_bound(begin(rva_db_map), end(rva_db_map),
        RVA_DB_ENTRY{ rva, nullptr },
        [](const RVA_DB_ENTRY& left, const RVA_DB_ENTRY& right) {
            return (left.rva + left.db->bytes.size()) < right.rva;
        });
    
    if (it == end(rva_db_map))
        return nullptr;

    if (rva < it->rva || rva > it->rva + it->db->bytes.size())
        return nullptr;

    // offset from start of data block
    if (db_offset)
        *db_offset = rva - it->rva;

    return it->db;
}

BASIC_BLOCK* DISASSEMBLED_BINARY::rva_to_bb(uint32_t rva) {
    return bin.symbols[rva_map[rva].id]->bb;
}

BASIC_BLOCK* DISASSEMBLED_BINARY::rva_to_containing_bb(uint32_t rva, int* instr_idx) {
    assert(rva <= rva_map.size());
    auto& entry = rva_map[rva];

    // this rva holds the root of a basic block
    if (!entry.blink) {
        assert(entry.id);
        if (instr_idx)
            *instr_idx = 0;

        return bin.symbols[entry.id]->bb;
    }

    int count = 0;
    for (int curr_rva = rva; true;) {
        auto& node = rva_map[curr_rva];
        if (!node.blink) {
            assert(node.id);
            SYMBOL* sym = bin.symbols[node.id];
            assert(sym->type == SYMBOL_TYPE_CODE);

            if (instr_idx)
                *instr_idx = count;

            return sym->bb;
        }

        curr_rva -= node.blink;
        count++;
    }

    return nullptr;
}


IMAGE_SECTION_HEADER* DISASSEMBLED_BINARY::rva_to_sect(uint32_t rva) {
    for (int i = 0; i < nthdrs->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* sect = &sects[i];
        
        if (sect->VirtualAddress <= rva && rva < sect->VirtualAddress + sect->Misc.VirtualSize) {
            return sect;
        }
    }
    return nullptr;
}

bool DISASSEMBLED_BINARY::rva_in_exec_sect(uint32_t rva) {
    IMAGE_SECTION_HEADER* sect = rva_to_sect(rva);
    if (!sect)
        return false;

    return sect->Characteristics & IMAGE_SCN_MEM_EXECUTE;
}

uint32_t DISASSEMBLED_BINARY::rva_to_offset(uint32_t rva) {
    IMAGE_SECTION_HEADER* sect = rva_to_sect(rva);
    if (!sect)
        return 0;

    return sect->PointerToRawData + (rva - sect->VirtualAddress);
}
