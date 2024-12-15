#include "../symbols/symbols.h"
#include <format>
#pragma once

std::string serialize_sym(SYMBOL* sym);
std::string serialize_instr_ex(ZydisDecoder* decoder, ZydisFormatter* formatter, const instr_t* instr, void* user_data = nullptr);
std::string serialize_instr(struct BINARY* bin, const instr_t* instr);

// #define DEBUG_LOGGING

std::string fmtf(_Printf_format_string_ const char* format, ...);
void printf_ex(int color, _Printf_format_string_  const char* fmt, ...);

void logger_indent();
void logger_unindent();
void logger_reset_indentation();

void logger_log__(int action_color, std::string action, int msg_color, std::string msg);
void logger_warn__(std::string msg);

#ifdef DEBUG_LOGGING
    #define logger_log(action_color, action, msg_color, msg) logger_log__(action_color, action, msg_color, msg)
#else
    #define logger_log(action_color, action, msg_color, msg)
#endif

#define logger_warn(msg) logger_warn__(msg);

enum COLORS {
    BLACK           = 30,
    RED             = 31,
    GREEN           = 32,
    YELLOW          = 33,
    BLUE            = 34,
    MAGENTA         = 35,
    CYAN            = 36,
    WHITE           = 37,
    BRIGHT_BLACK    = 90,
    BRIGHT_RED      = 91,
    BRIGHT_GREEN    = 92,
    BRIGHT_YELLOW   = 93,
    BRIGHT_BLUE     = 94,
    BRIGHT_MAGENTA  = 95,
    BRIGHT_CYAN     = 96,
    BRIGHT_WHITE    = 97,
};