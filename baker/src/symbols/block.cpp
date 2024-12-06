#include "../binary.h"

BASIC_BLOCK& BASIC_BLOCK::insert(int idx, instr_t instr) {
    SYMBOL* sym = bin_->symbols[this->id];

    logger_log(
        WHITE, "",
        WHITE, sym->name.empty()
        ? fmtf("%-3d: +%-3d: %s\n", this->id, this->size(), serialize_instr(bin_, &instr).c_str())
        : fmtf("%s, %-3d, +%-3d: %s\n", sym->name.c_str(), this->id, this->size(), serialize_instr(bin_, &instr).c_str())
    );

    instrs.insert(begin(instrs) + idx, instr);
    return *this;
}

BASIC_BLOCK& BASIC_BLOCK::insert(int idx, std::vector<instr_t> instructions_array) {
    for (int i = idx; auto & instr : instructions_array) {
        this->insert(i++, instr);
    }
    return *this;
}


BASIC_BLOCK& BASIC_BLOCK::push(instr_t instr) {
    this->insert(instrs.size(), instr);
    return *this;
}

BASIC_BLOCK& BASIC_BLOCK::push(std::vector<instr_t> instructions_array) {
    this->insert(instrs.size(), instructions_array);
    return *this;
}

BASIC_BLOCK& BASIC_BLOCK::fall(sym_id_t sym_id) {
    fallthrough_sym_id = sym_id;

    SYMBOL* sym = bin_->symbols[this->id];
    logger_log(
        WHITE, "",
        WHITE, sym->name.empty() 
        ? fmtf("%d --> %d\n", this->id, fallthrough_sym_id)
        : fmtf("%s, %d --> %d\n", sym->name.c_str(), this->id, fallthrough_sym_id));
    return *this;
}

size_t BASIC_BLOCK::size() {
    int size = 0;
    for (instr_t& ins : instrs) {
        size += ins.len;
    }
    return size;
}


SYMBOL* DATA_BLOCK::data_sym(int db_offset, enum TARGET_TYPE target_type, sym_id_t target_id) {
    SYMBOL* sym        = nullptr;
    bool    reusing    = false;

    if (dboffset_to_sym[db_offset]) {
        sym        = dboffset_to_sym[db_offset];
        reusing = true;
    } else {
        sym = new SYMBOL{};
        sym->id = bin_->symbols.size();
        bin_->symbols.push_back(sym);

        sym->type        = SYMBOL_TYPE_DATA;
        sym->db            = this;
        sym->db_offset    = db_offset;
        dboffset_to_sym[db_offset] = sym;
    }

    if (target_type) {
        sym->target_type   = target_type;
        sym->target_sym_id = target_id;
    }

    logger_log(
        WHITE, fmtf("%s %s", this->name.c_str(), reusing ? ">ds" : "+ds"),
        WHITE, fmtf("%d: +%d\n", sym->id, sym->db_offset));

    return sym;
}

SYMBOL* DATA_BLOCK::push_val(uint64_t val, int len) {
    SYMBOL* sym = data_sym(bytes.size());

    bytes.insert(end(bytes), len, 0);
    memcpy(bytes.data(), &val, len);

    logger_log(
        WHITE, fmtf("%s +val %d", this->name.c_str(), len),
        WHITE, fmtf("%d\n", val));

    return sym;
}

SYMBOL* DATA_BLOCK::push_buf(const void* buf, int len) {
    SYMBOL* sym = data_sym(bytes.size());

    bytes.insert(end(bytes), 
        (uint8_t*)buf, 
        (uint8_t*)buf + len);

#ifdef DEBUG_LOGGING
    std::string fmt = "";
    for (int i = 0; i < len; i++) {
        fmt.append(fmtf("%02X, ", ((uint8_t*)buf)[i]));
                    
        if (i > 10) {
            fmt.append("...");
            break;
        }
    }
    logger_log(
        WHITE, fmtf("%s +buf", this->name.c_str()), 
        WHITE, fmtf("%s\n", fmt.c_str()));
#endif
    
    return sym;
}

SYMBOL* DATA_BLOCK::push_str(std::string str, bool nullterm) {
    SYMBOL* sym = data_sym(bytes.size());

    bytes.insert(end(bytes),
        str.c_str(),
        str.c_str() + str.size());

    if (nullterm) {
        bytes.push_back('\0');
    }

    logger_log(
        WHITE, fmtf("%s +buf", this->name.c_str()), 
        WHITE, fmtf("%s\n", str.c_str()));

    return sym;
}