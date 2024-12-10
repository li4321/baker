#include "../binary.h"

// create a forward declaration
SYMBOL* BINARY::label() {
    SYMBOL* sym = new SYMBOL{};
    sym->id = symbols.size();
    symbols.push_back(sym);

    logger_log(
        YELLOW, "+label", 
        WHITE, fmtf("id: %d\n", sym->id));
    return sym;
}

//
// CODE
//

BASIC_BLOCK* BINARY::basic_block(std::string name) {
    SYMBOL* sym = new SYMBOL{};
    sym->id = symbols.size();
    symbols.push_back(sym);

    sym->type     = SYMBOL_TYPE_CODE;
    sym->bb       = basic_blocks.emplace_back(new BASIC_BLOCK{});
    sym->bb->id   = sym->id;
    sym->bb->bin_ = this;
    sym->name     = name;

    logger_log(
        BRIGHT_CYAN, "+basic_block",
        WHITE, fmtf("%s\n", serialize_sym(sym).c_str()));

    return sym->bb;
}

BASIC_BLOCK* BINARY::basic_block(sym_id_t label_id, std::string name) {
    SYMBOL* sym   = symbols[label_id];
    sym->type     = SYMBOL_TYPE_CODE;
    sym->bb       = basic_blocks.emplace_back(new BASIC_BLOCK{});
    sym->bb->id   = sym->id;
    sym->bb->bin_ = this;
    sym->name     = name;

    logger_log(
        WHITE, ">basic_block",
        WHITE, fmtf("%s\n", serialize_sym(sym).c_str()));
    return sym->bb;
}

BASIC_BLOCK* BINARY::set_entry(BASIC_BLOCK* bb) {
    logger_log(
        WHITE, "entry_point", 
        WHITE, fmtf("set to %d\n", bb->id));
    return entry_point = bb;
}

//
// DATA
//

DATA_BLOCK* BINARY::data_block(uint32_t size, BOOL read_only, std::string name) {
    DATA_BLOCK* db  = data_blocks.emplace_back(new DATA_BLOCK{});
    db->name        = name;
    db->bytes       = std::vector<uint8_t>(size, 0);
    db->read_only   = read_only;
    db->bin_        = this;

    logger_log(
        BRIGHT_RED, "+data_block", 
        WHITE, fmtf("name: %s, size: %d, read_only: %d\n", 
            name.c_str(), 
            size,
            read_only));
    return db;
}

//
// RELATIVE INFO
//

// to handle data references out of data blocks
// we create relative data symbols
// this should only work for addresses within the pe header
SYMBOL* BINARY::rel_info(uint32_t rel_offset, std::string name) {
    SYMBOL* sym     = new SYMBOL{};
    sym->type       = SYMBOL_TYPE_RELATIVE_INFO;
    sym->id         = symbols.size();
    sym->name       = name;
    sym->rel_offset = rel_offset;
    symbols.push_back(sym);

    logger_log(
        BRIGHT_GREEN, "+rel_info",
        WHITE, fmtf("sym_%d, name: %s, rel_offset: 0x%X\n",
            sym->id,
            name.c_str(),
            rel_offset));
    
    return sym;
}

//
// GETTERS
//

SYMBOL* BINARY::get_symbol(std::string name) {
    auto it = std::find_if(begin(symbols), end(symbols),
        [&](const SYMBOL* sym) {
            return sym->name == name;
        }
    );

    if (it == end(symbols))
        return nullptr;

    return *it;
}

DATA_BLOCK* BINARY::get_data_block(std::string name) {
    auto it = std::find_if(begin(data_blocks), end(data_blocks), 
        [&](const DATA_BLOCK* db) {
            return db->name == name;
        }
    );

    if (it == end(data_blocks))
        return nullptr;

    return *it;
}