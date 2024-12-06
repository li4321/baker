#include "../disassembler.h"
#include <functional>
#pragma once

struct INSTR_TRACE_FRAME {
    int                                    instr_idx;
    instr_t*                            instr;
    ZydisDecodedInstruction                dec_instr;
    std::vector<ZydisDecodedOperand>    dec_ops;
};


INSTR_TRACE_FRAME init_instr_trace_frame(BASIC_BLOCK* bb, int idx);

using backtrace_func_t = std::function<bool(
    ZydisDecodedOperand&, 
    INSTR_TRACE_FRAME)>;

/*
    trace_comp_func(target_reg, trace_frame):
        return false --> continue
        return true  --> break
*/
void bb_backtrace(
    BASIC_BLOCK*            bb,
    int                        begin_idx,
    ZydisDecodedOperand        target_op,
    const backtrace_func_t    comp);