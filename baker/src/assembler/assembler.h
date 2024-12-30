#pragma once
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <Windows.h>

#include "../binary.h"

struct SECTION {
    IMAGE_SECTION_HEADER hdr;
    std::vector<uint8_t> bytes;
    int                  uninitialized_size;
};

struct ASSEMBLED_BINARY {
    BINARY                 bin;
    std::vector<uint8_t> filebuf;

    // .text
    // .rdata <-- .idata, .reloc
    // .data
    std::vector<SECTION*> sections;
    SECTION* text_sect;
    SECTION* rdata_sect;
    SECTION* data_sect;

    std::map<DATA_BLOCK*, uint32_t> db_to_offset;
    std::map<DATA_BLOCK*, uint32_t> db_to_rva;
    std::map<DATA_BLOCK*, SECTION*> db_to_sect;

    std::map<sym_id_t, uint32_t> sym_to_offset;
    std::map<sym_id_t, uint32_t> sym_to_rva;

    uint32_t entry_point;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;

    // get pointer to where instructin is mapped in the filebuf
    uint8_t* get_instr(BASIC_BLOCK* bb, instr_t* instr);

    // get pointer to where data is mapped in the filebuf
    uint8_t* get_data(SYMBOL* data_sym);
};

uint32_t align_up(uint32_t val, uint32_t alignment);
ASSEMBLED_BINARY* build_pe(const BINARY* bin_);

void assembled_binary_print(ASSEMBLED_BINARY* asm_bin);