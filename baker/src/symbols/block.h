#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>
#include <map>

#include "instruction.h"

typedef uint32_t sym_id_t;
const sym_id_t nullsid = 0;

struct BASIC_BLOCK {
    sym_id_t             id;
    std::vector<instr_t> instrs;
    sym_id_t             fallthrough_sym_id;
    struct BINARY* bin_;

    struct BASIC_BLOCK* insert(int idx, instr_t instr);
    struct BASIC_BLOCK* insert(int idx, std::vector<instr_t> instructions_array);
    struct BASIC_BLOCK* push(instr_t instr);
    struct BASIC_BLOCK* push(std::vector<instr_t> instructions_array);
    struct BASIC_BLOCK* fall(sym_id_t id);
    struct BASIC_BLOCK* fall_to_next();

    size_t   size();
    uint32_t get_instr_offset(int idx);
};

struct DATA_BLOCK {
    std::string          name;
    std::vector<uint8_t> bytes;
    bool                 read_only;
    int                  alignment;
    bool                 is_jump_table;
    bool                 uninitialized;
    std::string          parent_sect;
    std::map<uint32_t, struct SYMBOL*> dboffset_to_sym;

    struct BINARY* bin_;

    struct SYMBOL* data_sym(int db_offset,          enum TARGET_TYPE target_type = (enum TARGET_TYPE)0, sym_id_t target_id = nullsid);
    struct SYMBOL* push_val(uint64_t val, int len,  enum TARGET_TYPE target_type = (enum TARGET_TYPE)0, sym_id_t target_id = nullsid);
    struct SYMBOL* push_buf(const void* buf, int len);
    struct SYMBOL* push_str(std::string str, bool nullterm = true);

    struct DATA_BLOCK* align();
    struct DATA_BLOCK* map_to_sect(std::string sect_name);
};