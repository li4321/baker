#include "disassembler.h"

void DISASSEMBLER::verify() {
    assert(sym_rva_map.size() == bin.symbols.size());

    for (BASIC_BLOCK* bb : bin.basic_blocks) {
        // we should not have empty basic blocks
        assert(!bb->instrs.empty());
    }

    for (int i = 0; i < bin.symbols.size(); i++) {
        SYMBOL* sym = bin.symbols[i];
        assert(sym->id == i);
    }

    int bb_count = 0;
    int sym_count = 0;

    for (uint32_t rva = 0; rva < rva_map.size(); rva++) {
        auto& entry = rva_map[rva];

        // there is nothing at this rva
        if (!entry.blink && entry.id == nullsid)
            continue;

        // this holds a non-root instruction
        // non root as in not the first instruction of the basic block
        if (entry.blink) {
            assert(!entry.id);

            int instr_count = 0;
            for (uint32_t curr_rva = rva; true;) {
                instr_count++;
                auto& curr_entry = rva_map[curr_rva];

                // we reached the root of the basic block
                if (!curr_entry.blink) {
                    assert(curr_entry.id != nullsid);

                    SYMBOL* root = bin.symbols[curr_entry.id];
                    assert(root);

                    assert(root->type = SYMBOL_TYPE_CODE);

                    // check instructions to be properly linked
                    assert(instr_count <= root->bb->instrs.size());

                    break;
                }

                curr_rva -= curr_entry.blink;
            }

            continue;
        }

        SYMBOL* sym = bin.symbols[entry.id];
        assert(sym);

        assert(sym_rva_map[sym->id] == rva);

        sym_count++;

        if (sym->type == SYMBOL_TYPE_CODE)
            bb_count++;
    }

    // the - 1 is to exclude the null symbol
    assert(sym_count == bin.symbols.size() - 1);
    assert(bb_count == bin.basic_blocks.size());
}