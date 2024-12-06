#include "disassembler.h"

void DISASSEMBLER::create_section_dbs() {
    const auto insert_into_rva_db_map = [&](uint32_t rva, DATA_BLOCK* db) {
        // insert into rva datablock map (while keeping map sorted)
        RVA_DB_ENTRY rva_db_entry = { rva, db };
        auto it = std::upper_bound(begin(rva_db_map), end(rva_db_map),
            rva_db_entry,
            [](const RVA_DB_ENTRY& left, const RVA_DB_ENTRY& right) {
                return left.rva < right.rva;
            });
        rva_db_map.insert(it, rva_db_entry);
    };

    for (int i = 0; i < nthdrs->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* secthdr = &sects[i];

        // ignore executable sections
        if (secthdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            continue;

        assert(secthdr->Characteristics & IMAGE_SCN_MEM_READ);

        std::string sect_name = (char*)secthdr->Name;
        bool        read_only = !(secthdr->Characteristics & IMAGE_SCN_MEM_WRITE);
        uint32_t    file_size = secthdr->SizeOfRawData;
        uint32_t    virt_size = secthdr->Misc.VirtualSize;

        DATA_BLOCK* db            = nullptr;
        DATA_BLOCK* uninit_db   = nullptr;

        if (virt_size > file_size) {
            uint32_t uninit_size = virt_size - file_size;
            db        = bin.data_block(file_size, read_only, sect_name);
            uninit_db = bin.data_block(uninit_size, read_only, sect_name + "_uninit");
            uninit_db->uninitialized = true;

            memcpy(db->bytes.data(), &filebuf[secthdr->PointerToRawData], file_size);
            memcpy(db->bytes.data(), &filebuf[secthdr->PointerToRawData + file_size], uninit_size);

            insert_into_rva_db_map(secthdr->VirtualAddress, db);
            insert_into_rva_db_map(secthdr->VirtualAddress + file_size, uninit_db);
        } else {
            db = bin.data_block(virt_size, read_only, sect_name);
            
            memcpy(db->bytes.data(), &filebuf[secthdr->PointerToRawData], secthdr->Misc.VirtualSize);
            insert_into_rva_db_map(secthdr->VirtualAddress, db);
        }
    }

    // print section mappings
    for (int i = 0; i < nthdrs->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* secthdr = &sects[i];

        logger_log(
            WHITE, (char*)secthdr->Name,
            WHITE, fmtf("%X - %X\n",
                secthdr->VirtualAddress,
                secthdr->VirtualAddress + secthdr->Misc.VirtualSize));
    }
}

void DISASSEMBLER::parse_imports() {
    IMAGE_DATA_DIRECTORY impdir = datadir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impdir.Size) {
        auto desc = rvacast<IMAGE_IMPORT_DESCRIPTOR*>(impdir.VirtualAddress);

        for (; desc->Characteristics; desc++) {
            IMPORT_MODULE* mod = bin.import_module(rvacast<char*>(desc->Name));

            uint32_t first_thunk_rva  = desc->FirstThunk;
            auto     orig_first_thunk = rvacast<IMAGE_THUNK_DATA*>(desc->OriginalFirstThunk);

            while (orig_first_thunk->u1.AddressOfData) {
                const auto imp_by_name = rvacast<IMAGE_IMPORT_BY_NAME*>(orig_first_thunk->u1.AddressOfData);

                // create import symbol
                IMPORT_ROUTINE* routine = bin.import_routine(mod, imp_by_name->Name);

                // point this rva to the import symbol
                assert(rva_map[first_thunk_rva].id == nullsid);
                rva_map[first_thunk_rva].id = routine->id;
                sym_rva_map_append(first_thunk_rva);

                first_thunk_rva += sizeof(IMAGE_THUNK_DATA);
                orig_first_thunk++;
            }
        }
    }
}

void DISASSEMBLER::parse_exceptions() {
    IMAGE_DATA_DIRECTORY pdata = datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pdata.Size) {
        logger_log(
            WHITE, "",
            WHITE, fmtf("parsing .pdata exception table\n"));

        const auto runtime_funcs      = rvacast<RUNTIME_FUNCTION*>(pdata.VirtualAddress);
        uint32_t   runtime_func_count = pdata.Size / sizeof(RUNTIME_FUNCTION);

        for (int i = 0; i < runtime_func_count; i++) {
            auto& rtfunc = runtime_funcs[i];

            // ignore addresses that do not land in a executable section
            // an example of this occuring is in ntoskrnl.exe
            // at the start of the INITDATA section
            if (!rva_in_exec_sect(rtfunc.BeginAddress)) {
                continue;
            }

            // queue the runtime function
            if (rva_map[rtfunc.BeginAddress].id == nullsid) {
                queue_rva(rtfunc.BeginAddress);
            }
        }
    }
}

void DISASSEMBLER::parse_relocations() {
    IMAGE_DATA_DIRECTORY relocdir = datadir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocdir.Size) {
        const auto starting_block_addr = rvacast<uint8_t*>(relocdir.VirtualAddress);

        for (uint8_t* block_addr = starting_block_addr;
            block_addr < starting_block_addr + relocdir.Size;) {

            const auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(block_addr);
            block_addr += block->SizeOfBlock;

            struct BASE_RELOC_ENTRY {
                uint16_t offset : 12;
                uint16_t type : 4;
            };

            const int  entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            const auto entries = reinterpret_cast<BASE_RELOC_ENTRY*>(block + 1);

            for (int i = 0; i < entry_count; i++) {
                BASE_RELOC_ENTRY& entry = entries[i];

                // rva where relocation occurs
                uint32_t reloc_rva = block->VirtualAddress + entry.offset;

                // padding, can ignore
                if (entry.type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;

                assert(entry.type == IMAGE_REL_BASED_DIR64);

                auto& rva_entry = rva_map[reloc_rva];

                // basic block creation should not have happened yet
                assert(rva_entry.blink == nullsid);

                // symbol has already been discovered
                if (rva_entry.id)
                    continue;

                // todo: handle rvas within executable sections
                assert(!rva_in_exec_sect(reloc_rva));

                uint32_t    db_offset = 0;
                DATA_BLOCK* db = rva_to_containing_db(reloc_rva, &db_offset);

                SYMBOL* sym = nullptr;
                // this could happen if the data is within the pe header
                if (!db)
                    sym = bin.rel_info(reloc_rva);
                else 
                    sym = db->data_sym(db_offset);
                
                rva_entry = { sym->id, 0 };
                sym_rva_map_append(reloc_rva);

                fully_analyze_data_symbol(sym);
            }
        }
    }
}