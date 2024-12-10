#include "../binary.h"

OPERAND Reg(ZydisRegister reg) { 
    OPERAND op = {};
    op.type = OP_REG;
    op.reg  = reg;
    return op;
}

OPERAND Imm(int64_t immediate) {
    OPERAND op = {};
    op.type = OP_IMM;
    op.imm  = immediate;
    return op;
}

OPERAND ImmRel(sym_id_t symbol_id) {
    OPERAND op = {};
    op.type          = OP_IMMREL;
    op.target_sym_id = symbol_id;
    return op;
}

OPERAND RipRel(sym_id_t symbol_id, int len) {
    OPERAND op = {};
    op.type          = OP_RIPREL;
    op.target_sym_id = symbol_id;
    op.len           = len;
    return op;
}

OPERAND Mem(OPERAND base_reg, int disp, int len) {
    OPERAND op = {};
    op.type         = OP_MEM;
    op.mem.base_reg = base_reg.reg;
    op.mem.disp     = disp;
    op.len          = len;
    return op;
}

OPERAND MemIdx(OPERAND base_reg, OPERAND idx_reg, int scale, sym_id_t table_sym_id, int len) {
    OPERAND op = {};
    op.type                = OP_MEM_IDX;
    op.memidx.base_reg     = base_reg.reg;
    op.memidx.idx_reg      = idx_reg.reg;
    op.memidx.scale        = scale;
    op.memidx.table_sym_id = table_sym_id;
    op.len                 = len;
    return op;
}

instr_t Instr(ZydisMnemonic mnemonic, OPERAND op1, OPERAND op2) {
    instr_t instr = {
        .len = sizeof(instr.bytes)
    };

    ZydisEncoderRequest request = {
        .machine_mode    = ZYDIS_MACHINE_MODE_LONG_64,
        .mnemonic        = mnemonic,
    };
    
    OPERAND* ops[2] = { &op1, &op2 };

    for (int i = 0; OPERAND* op : ops) {
        ZydisEncoderOperand* req_op   = &request.operands[i];
        OPERAND*             other_op = i ? &op1 : &op2;

        if (op->type != OP_NONE) {
            if (op->type == OP_RIPREL || op->type == OP_MEM || op->type == OP_MEM_IDX) {
                if (other_op->type == OP_REG)
                    op->len = reg_width(other_op->reg) / 8;
                if (other_op->type == OP_IMM)
                    assert(op->len);
            }

            switch (op->type) {
            case OP_REG:
                req_op->type      = ZYDIS_OPERAND_TYPE_REGISTER;
                req_op->reg.value = op->reg;
                break;

            case OP_IMM:
                req_op->type  = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req_op->imm.s = op->imm;
                break;

            case OP_IMMREL:
                req_op->type  = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req_op->imm.s = op->target_sym_id;
                break;

            case OP_RIPREL:
                req_op->type     = ZYDIS_OPERAND_TYPE_MEMORY;
                req_op->mem.base = ZYDIS_REGISTER_RIP;
                req_op->mem.displacement = op->target_sym_id;
                req_op->mem.size         = op->len;
                break;

            case OP_MEM:
                req_op->type     = ZYDIS_OPERAND_TYPE_MEMORY;
                req_op->mem.base = op->mem.base_reg;
                req_op->mem.size = op->len;
                req_op->mem.displacement = op->mem.disp;
                break;

            case OP_MEM_IDX:
                req_op->type      = ZYDIS_OPERAND_TYPE_MEMORY;
                req_op->mem.base  = op->memidx.base_reg;
                req_op->mem.index = op->memidx.idx_reg;
                req_op->mem.scale = op->memidx.scale;
                req_op->mem.size  = op->len;
                if (op->memidx.table_sym_id) {
                    req_op->mem.displacement = op->memidx.table_sym_id;
                    instr.flags |= INSTR_FLAG_MEM_IDX;
                }
                break;
            }

            request.operand_count++;
        }
        i++;
    }

    zy_expect_success(ZydisEncoderEncodeInstruction(&request, instr.bytes, &instr.len));
    return instr;
}


void instr_store_val(instr_t* instr, uint32_t val, ZydisDecoder* decoder, ZydisDecodedInstruction* dec_instr, ZydisDecoderContext* dec_ctx, uint64_t instr_va) {
    assert(dec_instr->attributes & ZYDIS_ATTRIB_IS_RELATIVE);

    if (dec_instr->raw.imm[0].is_relative) {
        // store target symbol id
        if (val < (1ull << dec_instr->raw.imm[0].size)) {
            // can fit
            memcpy(instr->bytes + dec_instr->raw.imm[0].offset, &val,
                dec_instr->raw.imm[0].size / 8);
        } else { 
            // cannot fit, re-encode with rel32 branch size
            // and then write value into instruction
            
            ZydisDecodedOperand dec_ops[10] = {};
            zy_expect_success(
                ZydisDecoderDecodeOperands(decoder,
                    dec_ctx, dec_instr, dec_ops, dec_instr->operand_count_visible)
            );

            ZydisEncoderRequest req = {};
            zy_expect_success(
                ZydisEncoderDecodedInstructionToEncoderRequest(dec_instr,
                    dec_ops, dec_instr->operand_count_visible, &req)
            );

            req.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
            req.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
            req.operands[0].imm.u = instr_va + 0x12345678;

            instr->len = sizeof(instr->bytes);
            zy_expect_success(
                ZydisEncoderEncodeInstructionAbsolute(&req, instr->bytes, &instr->len, instr_va)
            );

            assert(sizeof(val) == 4);
            memcpy(instr->bytes + instr->len - 4, &val, 4);
        }
    } else if (dec_instr->raw.disp.offset != 0
        && dec_instr->raw.modrm.mod == 0
        && dec_instr->raw.modrm.rm == 5) {

        // in x86-64, the offset in rip relative instructions should be 4 bytes (i think)
        assert(dec_instr->raw.disp.size == 32);
        
        memcpy(instr->bytes + dec_instr->raw.disp.offset, &val, 4);
    }
}

sym_id_t get_sym_id(const instr_t* instr, const ZydisDecodedInstruction* dec_instr) {
    sym_id_t sym_id = nullsid;
    if (dec_instr->raw.imm[0].is_relative) {
        memcpy(&sym_id, 
            instr->bytes + dec_instr->raw.imm[0].offset, 
            dec_instr->raw.imm[0].size / 8);
    } else if (dec_instr->raw.disp.size == 32) {
        memcpy(&sym_id,
            instr->bytes + dec_instr->raw.disp.offset,
            4);
    }
    return sym_id;
}


void zy_expect_success(ZyanStatus zystatus) {
    assert(ZYAN_SUCCESS(zystatus));
}

ZydisRegister reg_root(ZydisRegister reg) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
}

ZydisRegisterWidth reg_width(ZydisRegister reg) {
    return ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg);
}

std::tuple<
    ZydisDecoderContext, 
    ZydisDecodedInstruction
> decode_instr(const ZydisDecoder* decoder, const uint8_t* raw_instr, const size_t len) {
    ZydisDecoderContext     dec_ctx = {};
    ZydisDecodedInstruction dec_instr = {};

    zy_expect_success(
        ZydisDecoderDecodeInstruction(decoder, 
            &dec_ctx, raw_instr, len, &dec_instr)
    );

    return { dec_ctx, dec_instr };
}

std::vector<ZydisDecodedOperand> decode_ops(const ZydisDecoder* decoder, 
    const ZydisDecodedInstruction* dec_instr, const ZydisDecoderContext* dec_ctx) {
    ZydisDecodedOperand dec_ops[10] = {};
    
    zy_expect_success(
        ZydisDecoderDecodeOperands(decoder,
            dec_ctx, dec_instr, dec_ops, dec_instr->operand_count_visible)
    );

    return std::vector<ZydisDecodedOperand>(dec_ops, dec_ops + dec_instr->operand_count_visible);
}

std::tuple<
    ZydisDecodedInstruction, 
    std::vector<ZydisDecodedOperand>
> decode_full(const ZydisDecoder* decoder, const uint8_t* raw_instr, const size_t len) {
    ZyanStatus              zystatus    = 0;
    ZydisDecodedInstruction dec_instr   = {};
    ZydisDecodedOperand     dec_ops[10] = {};

    zy_expect_success(
        ZydisDecoderDecodeFull(decoder, raw_instr, len, &dec_instr, dec_ops)
    );

    return {
        dec_instr,
        std::vector<ZydisDecodedOperand>(dec_ops, dec_ops + dec_instr.operand_count_visible)
    };
}

#define DEFINE_REG(reg_name, mnemonic) const OPERAND reg_name##_ = { OP_REG, mnemonic, };

DEFINE_REG(rax, ZYDIS_REGISTER_RAX);
DEFINE_REG(rbx, ZYDIS_REGISTER_RBX);
DEFINE_REG(rcx, ZYDIS_REGISTER_RCX);
DEFINE_REG(rdx, ZYDIS_REGISTER_RDX);
DEFINE_REG(rsi, ZYDIS_REGISTER_RSI);
DEFINE_REG(rdi, ZYDIS_REGISTER_RDI);
DEFINE_REG(rbp, ZYDIS_REGISTER_RBP);
DEFINE_REG(rsp, ZYDIS_REGISTER_RSP);
DEFINE_REG(r8, ZYDIS_REGISTER_R8);
DEFINE_REG(r9, ZYDIS_REGISTER_R9);
DEFINE_REG(r10, ZYDIS_REGISTER_R10);
DEFINE_REG(r11, ZYDIS_REGISTER_R11);
DEFINE_REG(r15, ZYDIS_REGISTER_R15);
DEFINE_REG(r12, ZYDIS_REGISTER_R12);
DEFINE_REG(r13, ZYDIS_REGISTER_R13);
DEFINE_REG(r14, ZYDIS_REGISTER_R14);

DEFINE_REG(eax, ZYDIS_REGISTER_EAX);
DEFINE_REG(ebx, ZYDIS_REGISTER_EBX);
DEFINE_REG(ecx, ZYDIS_REGISTER_ECX);
DEFINE_REG(edx, ZYDIS_REGISTER_EDX);
DEFINE_REG(esi, ZYDIS_REGISTER_ESI);
DEFINE_REG(edi, ZYDIS_REGISTER_EDI);
DEFINE_REG(ebp, ZYDIS_REGISTER_EBP);
DEFINE_REG(esp, ZYDIS_REGISTER_ESP);
DEFINE_REG(r8d, ZYDIS_REGISTER_R8D);
DEFINE_REG(r9d, ZYDIS_REGISTER_R9D);
DEFINE_REG(r10d, ZYDIS_REGISTER_R10D);
DEFINE_REG(r11d, ZYDIS_REGISTER_R11D);
DEFINE_REG(r15d, ZYDIS_REGISTER_R15D);
DEFINE_REG(r12d, ZYDIS_REGISTER_R12D);
DEFINE_REG(r13d, ZYDIS_REGISTER_R13D);
DEFINE_REG(r14d, ZYDIS_REGISTER_R14D);

DEFINE_REG(ax, ZYDIS_REGISTER_AX);
DEFINE_REG(bx, ZYDIS_REGISTER_BX);
DEFINE_REG(cx, ZYDIS_REGISTER_CX);
DEFINE_REG(dx, ZYDIS_REGISTER_DX);
DEFINE_REG(si, ZYDIS_REGISTER_SI);
DEFINE_REG(di, ZYDIS_REGISTER_DI);
DEFINE_REG(bp, ZYDIS_REGISTER_BP);
DEFINE_REG(sp, ZYDIS_REGISTER_SP);
DEFINE_REG(r8w, ZYDIS_REGISTER_R8W);
DEFINE_REG(r9w, ZYDIS_REGISTER_R9W);
DEFINE_REG(r10w, ZYDIS_REGISTER_R10W);
DEFINE_REG(r11w, ZYDIS_REGISTER_R11W);

DEFINE_REG(al, ZYDIS_REGISTER_AL);
DEFINE_REG(bl, ZYDIS_REGISTER_BL);
DEFINE_REG(cl, ZYDIS_REGISTER_CL);
DEFINE_REG(dl, ZYDIS_REGISTER_DL);
DEFINE_REG(sil, ZYDIS_REGISTER_SIL);
DEFINE_REG(dil, ZYDIS_REGISTER_DIL);
DEFINE_REG(bpl, ZYDIS_REGISTER_BPL);
DEFINE_REG(spl, ZYDIS_REGISTER_SPL);
DEFINE_REG(r8b, ZYDIS_REGISTER_R8B);
DEFINE_REG(r9b, ZYDIS_REGISTER_R9B);
DEFINE_REG(r10b, ZYDIS_REGISTER_R10B);
DEFINE_REG(r11b, ZYDIS_REGISTER_R11B);