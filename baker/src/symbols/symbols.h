#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

#include "block.h"
#include "import.h"

typedef uint32_t sym_id_t;

enum SYMBOL_TYPE {
    SYMBOL_TYPE_NONE,
    SYMBOL_TYPE_CODE,
    SYMBOL_TYPE_DATA,
    SYMBOL_TYPE_IMPORT,
    SYMBOL_TYPE_RELATIVE_INFO
};

enum TARGET_TYPE {
    TARGET_TYPE_NONE,
    TARGET_TYPE_RVA,
    TARGET_TYPE_POINTER
};

struct SYMBOL {
    sym_id_t id;
    SYMBOL_TYPE type;
    std::string name;

    union {
        // basic block
        BASIC_BLOCK* bb;

        // data symbol
        struct {
            DATA_BLOCK* db;
            uint32_t    db_offset;

            // if this data symbol is a pointer that points to another symbol
            // which points to a absoulute address, base relocation will be needed
            TARGET_TYPE target_type;
            sym_id_t target_sym_id;
        };

        // import
        IMPORT_ROUTINE* import_routine;
    };

    // relocation info
    uint32_t rel_offset;
};

struct XREF {
    SYMBOL* sym;
    int instr_idx;
};