#include "../disassembler.h"

uint32_t DISASSEMBLER::calculate_potential_ptr(SYMBOL* sym) {
    assert(sym->type == SYMBOL_TYPE_DATA);
    assert(sym->db);

    // make sure there is enough space for a pointer to fit
    if (sym->db_offset + 8 > sym->db->bytes.size()) {
        return 0;
    }

    // read data symbol points to
    const uint64_t val = *reinterpret_cast<uint64_t*>(&sym->db->bytes[sym->db_offset]);

    const uint64_t image_base = nthdrs->OptionalHeader.ImageBase;
    const uint32_t image_size = nthdrs->OptionalHeader.SizeOfImage;

    // make sure rva is valid
    if (val < image_base || val >= image_base + image_size)
        return 0;

    return val - image_base;
}

// check data symbol for further memory reference
// symbol is updated to target the reference
// reference rva is returned if found
// 0 is returned if reference already found
uint32_t DISASSEMBLER::analyze_data_symbol(SYMBOL* sym) {
    assert(sym->type == SYMBOL_TYPE_DATA);
    assert(sym->db);

    uint32_t ptr_rva = calculate_potential_ptr(sym);
    if (ptr_rva) {
        sym->target_type = TARGET_TYPE_POINTER;
        auto& rva_entry = rva_map[ptr_rva];

        // target already discovered
        if (rva_entry.id) {
            sym->target_sym_id = rva_entry.id;
            return 0;
        }

        if (rva_in_exec_sect(ptr_rva)) {
            // middle of a basic block
            if (rva_entry.blink) {
                sym->target_sym_id = split_bb(ptr_rva).id;
                return ptr_rva;
            }

            // undiscovered code
            else {
                sym->target_sym_id = queue_rva(ptr_rva).id;
                return ptr_rva;
            }
        } else {
            // data pointer
            uint32_t db_offset = 0;
            DATA_BLOCK* db = rva_to_containing_db(ptr_rva, &db_offset);

            if (!db)
                return 0;

            SYMBOL* new_sym = db->data_sym(db_offset);
            rva_entry = { new_sym->id, 0 };
            sym_rva_map_append(ptr_rva);

            sym->target_sym_id = new_sym->id;
            return ptr_rva;
        }
    }
}

void DISASSEMBLER::fully_analyze_data_symbol(SYMBOL* sym) {
    while (true) {
        uint32_t target_rva = analyze_data_symbol(sym);
        if (!target_rva)
            break;

        sym = bin.symbols[rva_map[target_rva].id];
        if (sym->type != SYMBOL_TYPE_DATA)
            break;
    }
}