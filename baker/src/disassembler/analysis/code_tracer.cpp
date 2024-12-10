#include "code_tracer.h"
#include <functional>
#include <memory>

INSTR_TRACE_FRAME init_instr_trace_frame(BASIC_BLOCK* bb, int idx) {
    INSTR_TRACE_FRAME frame = {};
    frame.instr_idx = idx;
    frame.instr     = &bb->instrs[idx];
    const auto [dec_instr, dec_ops] = 
        decode_full(&bb->bin_->decoder, frame.instr->bytes, frame.instr->len);
    frame.dec_instr = dec_instr;
    frame.dec_ops   = dec_ops;
    return frame;
}

bool compare_operands(const ZydisDecodedOperand& op_1, const ZydisDecodedOperand& op_2) {
    if (op_1.type == op_2.type) {
        if (op_1.type == ZYDIS_OPERAND_TYPE_REGISTER
            && op_1.reg.value != op_2.reg.value)
            return false;

        if (op_1.type == ZYDIS_OPERAND_TYPE_MEMORY
            && (op_1.mem.base != op_2.mem.base
                || op_1.mem.index != op_2.mem.index
                || op_1.mem.scale != op_2.mem.scale
                || op_1.mem.disp.value != op_2.mem.disp.value))
            return false;
    }
    return true;
}

/*
    only_target_reg: only go through instructions where the left reg is the target reg
    trace_comp_func:
        return false --> continue
        return true  --> break
*/
void bb_backtrace(
    BASIC_BLOCK*             bb,
    int                      begin_idx,
    ZydisDecodedOperand      target_op,
    const backtrace_func_t   comp
) {
    for (int i = begin_idx; i >= 0; i--) {
        INSTR_TRACE_FRAME frame = init_instr_trace_frame(bb, i);
        auto& dec_instr = frame.dec_instr;
        auto& dec_ops   = frame.dec_ops;
        
        if (comp(target_op, frame) == true)
            break;

        /*
            add resilience towards these situations:
            -- scanning for `lea {jmp_reg}, sym_123`
            lea rcx, sym_123
            mov rax, rcx
            jmp rax
            ------------------
            -- scanning for `lea {jmp_reg}, sym_123`
            lea rcx, sym_123
            mov [rsp+0x18], rcx
            mov rax, [rsp+0x18]
            jmp rax
        */
        if (dec_instr.mnemonic == ZYDIS_MNEMONIC_MOV && compare_operands(dec_ops[0], target_op)) {
            // we will switch the target operand, to the operand moved in
            target_op = dec_ops[1];
        }
    }
}