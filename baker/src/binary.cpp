#include "binary.h"

ZyanStatus hook_zydis_format_operand_mem(const ZydisFormatter* formatter, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context);
ZyanStatus hook_zydis_format_operand_imm(const ZydisFormatter* formatter, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context);

ZydisFormatterFunc orig_zydis_format_operand_mem = hook_zydis_format_operand_mem; // gets set to the original after the hook function
ZydisFormatterFunc orig_zydis_format_operand_imm = hook_zydis_format_operand_imm;

BINARY::BINARY() {
    zy_expect_success(ZydisDecoderInit(&decoder,
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

    zy_expect_success(ZydisFormatterInit(&formatter,
            ZYDIS_FORMATTER_STYLE_INTEL));

    /*
        makes relative instructions show as [rip+disp] 
        instead of the absoulute address
    */

    zy_expect_success(ZydisFormatterSetProperty(&formatter,
            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true));

    zy_expect_success(ZydisFormatterSetProperty(&formatter,
            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, true));

    /*
        sets the hooks to print symbols in the instructions
    */
    
    orig_zydis_format_operand_mem = hook_zydis_format_operand_mem;
    orig_zydis_format_operand_imm = hook_zydis_format_operand_imm;

    zy_expect_success(
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_MEM,
            (const void**)(&orig_zydis_format_operand_mem))
    );

    zy_expect_success(
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_IMM,
            (const void**)(&orig_zydis_format_operand_imm))
    );

    /*
        create a null symbol, so no symbols will hold the id 0
    */
    
    this->label();
}


ZyanStatus hook_zydis_format_operand_mem(
    const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer,
    ZydisFormatterContext* context) {

    if (context->operand->mem.base != ZYDIS_REGISTER_RIP) {
        return orig_zydis_format_operand_mem(formatter, buffer, context);
    }

    uint64_t mask      = (1ull << context->instruction->raw.disp.size) - 1;
    auto&    sym_table = *reinterpret_cast<std::vector<SYMBOL*>*>(context->user_data);
    sym_id_t sym_id    = (context->operand->mem.disp.value) & mask;
    SYMBOL*  sym       = sym_table[sym_id];

    ZyanString* str = nullptr;
    ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL);
    ZydisFormatterBufferGetString(buffer, &str);

    COLORS color = WHITE;

    if (sym->type == SYMBOL_TYPE_CODE)
        color = BRIGHT_BLUE;

    else if (sym->type == SYMBOL_TYPE_DATA)
        color = BRIGHT_RED;

    else if (sym->type == SYMBOL_TYPE_IMPORT)
        color = BRIGHT_MAGENTA;

    else if (sym->type == SYMBOL_TYPE_RELATIVE_INFO)
        color = BRIGHT_GREEN;

    if (!sym->name.empty()) {
        ZyanStringAppendFormat(str, "[\033[%dmsym_%u/%s\033[0m]", color, sym->id, sym->name.c_str());
    } else {
        ZyanStringAppendFormat(str, "[\033[%dmsym_%u\033[0m]", color, sym->id);
    }

    return ZYAN_STATUS_SUCCESS;
}

ZyanStatus hook_zydis_format_operand_imm(
    const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer,
    ZydisFormatterContext* context) {

    if (!context->operand->imm.is_relative) {
        return orig_zydis_format_operand_imm(formatter, buffer, context);
    }

    uint64_t mask      = (1ull << context->operand->size) - 1;
    auto&    sym_table = *reinterpret_cast<std::vector<SYMBOL*>*>(context->user_data);
    sym_id_t sym_id    = context->operand->imm.value.u & mask;
    SYMBOL*  sym       = sym_table[sym_id];

    ZyanString* str = nullptr;
    ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL);
    ZydisFormatterBufferGetString(buffer, &str);

    COLORS color = WHITE;

    if (sym->type == SYMBOL_TYPE_CODE)
        color = BRIGHT_BLUE;

    else if (sym->type == SYMBOL_TYPE_DATA)
        color = BRIGHT_RED;

    else if (sym->type == SYMBOL_TYPE_IMPORT)
        color = BRIGHT_MAGENTA;

    else if (sym->type == SYMBOL_TYPE_RELATIVE_INFO)
        color = BRIGHT_GREEN;

    if (!sym->name.empty()) {
        ZyanStringAppendFormat(str, "\033[%dmsym_%u/%s\033[0m", color, sym->id, sym->name.c_str());
    } else {
        ZyanStringAppendFormat(str, "\033[%dmsym_%u\033[0m", color, sym->id);
    }
    
    return ZYAN_STATUS_SUCCESS;
}


void binary_duplicate(const BINARY* bin, BINARY* new_bin) {
    std::map<IMPORT_ROUTINE*, IMPORT_ROUTINE*>  old_to_new_routine;
    std::map<DATA_BLOCK*, DATA_BLOCK*>            old_to_new_db;

    for (IMPORT_MODULE* old_mod : bin->import_modules) {
        IMPORT_MODULE* mod = new IMPORT_MODULE{};
        mod->name      = old_mod->name;
        mod->routines = {};

        for (IMPORT_ROUTINE* old_routine : old_mod->routines) {
            IMPORT_ROUTINE* routine = new IMPORT_ROUTINE{};
            routine->id        = old_routine->id;
            routine->name    = old_routine->name;

            mod->routines.push_back(routine);
            old_to_new_routine[old_routine] = routine;
        }

        new_bin->import_modules.push_back(mod);
    }

    for (DATA_BLOCK* old_db : bin->data_blocks) {
        DATA_BLOCK* db = new_bin->data_blocks.emplace_back(new DATA_BLOCK{});
        db->name      = old_db->name;
        db->bytes      = old_db->bytes;
        db->read_only = old_db->read_only;
        db->bin_      = new_bin;
        old_to_new_db[old_db] = db;
    }

    new_bin->symbols = bin->symbols;

    for (int i = 0; i < bin->symbols.size(); i++) {
        SYMBOL* old_sym = bin->symbols[i];
        SYMBOL* sym = new SYMBOL{};
        new_bin->symbols[i] = sym;

        sym->id = i;
        sym->type = old_sym->type;
        sym->name = old_sym->name;

        if (sym->type == SYMBOL_TYPE_CODE) {
            BASIC_BLOCK* old_bb = old_sym->bb;
            BASIC_BLOCK* bb = new_bin->basic_blocks.emplace_back(new BASIC_BLOCK{});
            bb->id                 = sym->id;
            bb->instrs             = old_bb->instrs;
            bb->fallthrough_sym_id = old_bb->fallthrough_sym_id;
            bb->bin_               = new_bin;
            sym->bb                = bb;
        }

        else if (sym->type == SYMBOL_TYPE_DATA) {
            DATA_BLOCK* db = old_to_new_db[old_sym->db];
            sym->db         = db;
            sym->db_offset  = old_sym->db_offset;
            db->dboffset_to_sym[sym->db_offset] = sym;

            sym->target_type   = old_sym->target_type;
            sym->target_sym_id = old_sym->target_sym_id;
        }

        else if (sym->type == SYMBOL_TYPE_RELATIVE_INFO) {
            sym->rel_offset = old_sym->rel_offset;
        }

        else if (sym->type == SYMBOL_TYPE_IMPORT) {
            IMPORT_ROUTINE* old_routine = old_sym->import_routine;
            IMPORT_ROUTINE* routine     = old_to_new_routine[old_routine];
            sym->import_routine = routine;
        }
        
        else if (sym->type == SYMBOL_TYPE_NONE) {
            // null symbol
            assert(i == 0);
        }
    }

    new_bin->formatter   = bin->formatter;
    new_bin->decoder     = bin->decoder;
    new_bin->entry_point = bin->entry_point;
}

void binary_free(BINARY* bin) {
    for (IMPORT_MODULE* mod : bin->import_modules) {
        for (IMPORT_ROUTINE* routine : mod->routines) {
            free(routine);
        }
        free(mod);
    }

    for (DATA_BLOCK* db : bin->data_blocks)
        free(db);
    
    for (BASIC_BLOCK* bb : bin->basic_blocks)
        free(bb);
    
    for (SYMBOL* sym : bin->symbols)
        free(sym);
}


void binary_print(BINARY* bin) {
    printf("--------------------------------------------\n");
    printf("----------------BINARY----------------------\n");
    printf("--------------------------------------------\n");

    printf_ex(BRIGHT_BLUE, "--------------CODE--------------------------\n");

    for (BASIC_BLOCK* bb : bin->basic_blocks) {
        printf_ex(BRIGHT_BLUE, "[basic block]: %d, size: %d\n", bb->id, bb->size());

        for (int bb_offset = 0; instr_t instr : bb->instrs) {
            printf("\t+%-4d: %s\n", bb_offset, serialize_instr(bin, &instr).c_str());

            bb_offset += instr.len;
        }

        printf("\t--> %d\n", bb->fallthrough_sym_id);
    }

    for (int sect_idx = 0; sect_idx < 2; sect_idx++) {
        // 0: .rdata
        // 1: .data

        if (sect_idx == 0)
            printf_ex(BRIGHT_RED, "----READ-ONLY-DATA--------------------------\n");

        if (sect_idx == 1)
            printf_ex(BRIGHT_MAGENTA, "--------------DATA--------------------------\n");

        for (DATA_BLOCK* db : bin->data_blocks) {
            if (sect_idx == 0 && db->read_only == false)
                continue;

            if (sect_idx == 1 && db->read_only == true)
                continue;
            
            printf_ex(sect_idx ? BRIGHT_MAGENTA : BRIGHT_RED,
                "[data block]: %s, size: %d\n", db->name.c_str(), db->bytes.size());

            struct LINE_INFO {
                SYMBOL* sym;
                std::vector<uint8_t> bytes;
            };

            std::vector<LINE_INFO> lines = {};

            LINE_INFO line = {};
            for (int db_offset = 0; db_offset < db->bytes.size(); db_offset++) {
                uint8_t  byte = db->bytes[db_offset];

                if (db->dboffset_to_sym[db_offset]) {
                    if (db_offset) {
                        lines.push_back(line);
                        line     = {};
                    }
                    line.sym = db->dboffset_to_sym[db_offset];
                }

                int line_max_len = 16;
                if (line.sym) {
                    if (line.sym->target_type == TARGET_TYPE_RVA) {
                        line_max_len = 4;
                    } else if (line.sym->target_type == TARGET_TYPE_POINTER) {
                        line_max_len = 8;
                    }
                }

                if (db_offset == db->bytes.size() - 1) {
                    line.bytes.push_back(byte);
                    lines.push_back(line);
                    line     = {};
                } else {
                    if (line.bytes.size() == line_max_len) {
                        lines.push_back(line);
                        line     = {};
                    }

                    line.bytes.push_back(byte);
                }
            }

            for (LINE_INFO& line : lines) {
                /*
                    tabing it out
                */
                if (line.sym) {
                    SYMBOL* sym = line.sym;
                    if (sym->target_type == TARGET_TYPE_RVA)
                        printf("%-25s |", fmtf("[%-4d --rva-> %-4d]", sym->id, sym->target_sym_id).c_str());
                    if (sym->target_type == TARGET_TYPE_POINTER)
                        printf("%-25s |", fmtf("[%-4d --ptr-> %-4d]", sym->id, sym->target_sym_id).c_str());
                    if (sym->target_type == TARGET_TYPE_NONE)
                        printf("%-25s |", fmtf("[%d]", sym->id).c_str());
                } else {
                    printf("%-25s |", "");
                }

                /*
                    | 00 00 00 |text
                */
                std::string fmt = "";

                for (int j = 0; j < line.bytes.size(); j++)
                    fmt += fmtf("%02X ", line.bytes[j]);
                printf("%-48s|", fmt.c_str());

                for (int j = 0; j < line.bytes.size(); j++)
                    printf("%c", line.bytes[j]);

                printf("\n");
            }

            printf("\n");
        }
    }

    printf("--------------------------------------------\n");
    printf("--------------------------------------------\n");
}