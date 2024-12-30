#pragma once
#include "../binary.h"
#include <queue>
#include <set>

struct RVA_DB_ENTRY {
    // rva to data block
    uint32_t rva;

    // the data block
    DATA_BLOCK* db;
};

struct RVA_MAP_ENTRY {
    // if blink is 0, this is the symbol the rva lands in
    sym_id_t id;

    // if not 0, this is the number of bytes to previous rva entry
    // code         --> goes to last line of assembly in the same basic block
    // jpt entry --> goes ot last jump table entry
    uint32_t blink;
};

struct DISASSEMBLED_BINARY {    
    BINARY bin;
    
    std::vector<uint8_t>  filebuf;
    IMAGE_DOS_HEADER*     doshdr;
    IMAGE_NT_HEADERS*     nthdrs;
    IMAGE_DATA_DIRECTORY* datadir;
    IMAGE_SECTION_HEADER* sects;
    uint64_t              image_base;

    std::vector<RVA_MAP_ENTRY> rva_map;
    std::vector<RVA_DB_ENTRY>  rva_db_map;

    // [symbol id]: rva
    std::vector<uint32_t> sym_rva_map;

    DATA_BLOCK*  rva_to_db(uint32_t rva);
    DATA_BLOCK*  rva_to_containing_db(uint32_t rva, uint32_t* db_offset = nullptr);
    
    BASIC_BLOCK* rva_to_bb(uint32_t rva);
    BASIC_BLOCK* rva_to_containing_bb(uint32_t rva, int* instr_idx = nullptr);

    IMAGE_SECTION_HEADER*  rva_to_sect(uint32_t rva);
    bool                   rva_in_exec_sect(uint32_t rva);
    uint32_t               rva_to_offset(uint32_t rva);
    template<typename T> T rvacast(uint32_t rva) { return (T)&filebuf[rva_to_offset(rva)]; }
};

struct DISASSEMBLER : DISASSEMBLED_BINARY {
    // pe parsing
    void create_section_dbs();
    void parse_imports();
    void parse_exceptions();
    void parse_relocations();

    // main functionalities
    std::queue<uint32_t> disasm_queue;
    void           sym_rva_map_append(uint32_t rva);
    RVA_MAP_ENTRY& queue_rva(uint32_t rva, sym_id_t label_id);
    RVA_MAP_ENTRY& queue_rva(uint32_t rva, std::string name = "");
    RVA_MAP_ENTRY& split_bb(uint32_t rva, std::string name = "");

    // data symbol analysis
    uint32_t calculate_potential_ptr(SYMBOL* sym);
    uint32_t analyze_data_symbol(SYMBOL* sym);
    void     fully_analyze_data_symbol(SYMBOL* sym);

    // main recursive disassembler function
    void disassemble();
    void sort_basic_blocks();

    // jump table analysis
    std::map<sym_id_t, bool> bb_explored_map;
    std::set<uint32_t>       jpt_rva_list;
    void collect_jump_tables();
    void resolve_jpt_entries();

    // verification
    void verify();
};

DISASSEMBLER* disassemble_pe(std::vector<uint8_t> filebuf);