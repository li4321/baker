#include "../binary.h"


int indentation = 0;

void logger_indent() {
    indentation++;
}

void logger_unindent() {
    indentation--;
}

void logger_reset_indentation() {
    indentation = 0;
}

std::string fmtf(_Printf_format_string_ const char* format, ...) {
    va_list args;
    va_start(args, format);
    int size = vsnprintf(nullptr, 0, format, args) + 1;

    std::vector<char> buffer(size);
    vsnprintf(
        buffer.data(),
        size,
        format,
        args);

    va_end(args);

    return std::string(buffer.data());
}

std::string serialize_sym(SYMBOL* sym) {
    std::string result = "";
    result.append(fmtf("{ id: %d", sym->id));

    if (!sym->name.empty())
        result.append(fmtf(", %s", sym->name.c_str()));

    if (sym->type == SYMBOL_TYPE_CODE)
        result.append(fmtf(", bb: 0x%p", sym->bb));

    if (sym->type == SYMBOL_TYPE_DATA) {
        if (!sym->db->name.empty()) {
            result.append(fmtf(", %s", sym->db->name.c_str()));
        }

        result.append(fmtf(", db: 0x%p", sym->db));

        if (sym->db_offset)
            result.append(fmtf(" + %d", sym->db_offset));

        if (sym->target_type == TARGET_TYPE_RVA)
            result.append(fmtf(", (rva target: %d)", sym->target_sym_id));
    }

    result.append(" }");
    return result;
}

std::string serialize_instr_ex(ZydisDecoder* decoder, ZydisFormatter* formatter, const instr_t* instr, void* user_data) {
    char buffer[256];

    ZydisDecodedInstruction decoded_instr = {};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};
    ZydisDecoderDecodeFull(decoder, instr->bytes, instr->len, &decoded_instr, operands);

    ZydisFormatterFormatInstruction(formatter, &decoded_instr, operands,
        decoded_instr.operand_count_visible,
        buffer, sizeof(buffer), 0, user_data);

    return buffer;
}

std::string serialize_instr(BINARY* bin, const instr_t* instr) {
    return serialize_instr_ex(&bin->decoder, &bin->formatter, instr, &bin->symbols);
}

void printf_ex(int color, _Printf_format_string_  const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    printf("\033[%dm", color);
    vprintf(fmt, args);
    printf("\033[0m");

    va_end(fmt);
}

void logger_log__(int action_color, std::string action, int msg_color, std::string msg) {
    for (int i = 0; i < indentation; i++)
        printf("\t");

    if (!action.empty()) {
        printf_ex(action_color, "%-20s", ("[" + action + "]").c_str());
    }

    if (!msg.empty()) {
        printf_ex(msg_color, msg.c_str());
    }
}

void logger_warn__(std::string msg) {
    printf_ex(RED, "[!warning!]");
    printf_ex(WHITE, msg.c_str());
}

void print_bb(BASIC_BLOCK* bb, uint32_t rva) {
    BINARY* bin = bb->bin_;

    printf_ex(BRIGHT_BLUE, "[basic block]: %d, size: %d   %s\n", bb->id, bb->size(),
        bin->symbols[bb->id]->name.c_str());

    for (int bb_offset = 0; const instr_t& instr : bb->instrs) {
        if (rva) {
            printf("<+%0X>", rva + bb_offset);
        }

        printf("\t+%-4d: %s\n", bb_offset, serialize_instr(bin, &instr).c_str());

        bb_offset += instr.len;
    }

    printf("\t--> %d\n", bb->fallthrough_sym_id);
}