#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include "symbols/symbols.h"
#include "logging/logging.h"

#include <Zydis/Formatter.h>
#include <Zydis/Encoder.h>
#include <Zydis/Decoder.h>
#include <Zydis/Zydis.h>
#include <Zydis/Utils.h>

#include <Zycore/Zycore.h>
#include <Zycore/Format.h>

struct SECT_CONFIG {
    std::string name;
    uint32_t    characteristics;
};

struct BINARY {
    // binary
    std::vector<BASIC_BLOCK*>   basic_blocks;
    std::vector<DATA_BLOCK*>    data_blocks;
    std::vector<IMPORT_MODULE*> import_modules;
    
    // index of symbol = symbol id
    std::vector<SYMBOL*> symbols;
    BASIC_BLOCK*         entry_point;

    // section configs (optional)
    // std::vector<SECT_CONFIG> extra_sects;

    ZydisFormatter formatter;
    ZydisDecoder   decoder;
    BINARY();

    // imports
    IMPORT_MODULE*  import_module(std::string module_name);
    IMPORT_ROUTINE* import_routine(IMPORT_MODULE* mod, std::string routine_name);

    // forward declaration
    SYMBOL* label();

    // code
    BASIC_BLOCK* basic_block(std::string name = "");
    BASIC_BLOCK* basic_block(sym_id_t label_id, std::string name = "");
    BASIC_BLOCK* set_entry(BASIC_BLOCK* bb);

    // data
    DATA_BLOCK* data_block(uint32_t size, BOOL read_only, std::string name = "");

    // relative info
    SYMBOL* rel_info(uint32_t rel_offset, std::string name = "");

    // getters
    SYMBOL*     get_symbol(std::string name);
    DATA_BLOCK* get_data_block(std::string name);
};

void binary_duplicate(const BINARY* bin, BINARY* new_bin);
void binary_free(BINARY* bin);
void binary_print(BINARY* bin);

#define STRUCT_SCHEMA(struct_type, start_db_offset) reinterpret_cast<const struct_type*>(start_db_offset)
#define SS_MEMBER(schema, member) (uint32_t)(&schema->member)