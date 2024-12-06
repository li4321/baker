#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

#include "../../ext/zydis.h"

typedef uint32_t sym_id_t;

#define INSTR_FLAG_MEM_IDX (1U << 0)

struct instr_t {
    uint8_t  bytes[15];
    size_t   len;
    uint32_t flags;
};

enum INSTR_OP_TYPE {
    OP_NONE,
    OP_REG,

    OP_IMM8,
    OP_IMM32,
    OP_IMM64,
    
    OP_SID,

    OP_MEM_IDX
};

struct OPERAND {
    INSTR_OP_TYPE type;
    
    union {
        uint8_t       imm8;
        uint32_t      imm32;
        uint64_t      imm64;
        sym_id_t      target_sym_id;
        ZydisRegister reg;
    
        struct {
            ZydisRegister base_reg;
            ZydisRegister idx_reg;
            uint32_t      scale;
            sym_id_t      table_sym_id;
        } memidx;
    };
};


OPERAND Reg   (ZydisRegister reg);
OPERAND Imm8  (uint8_t immediate);
OPERAND Imm32 (uint32_t immediate);
OPERAND Imm64 (uint64_t immediate);
OPERAND Sid   (sym_id_t symbol_id);
OPERAND MemIdx(OPERAND base_reg, OPERAND idx_reg, int scale, sym_id_t table_sym_id = 0);

instr_t Instr(ZydisMnemonic mnemonic, OPERAND op1, OPERAND op2);

void instr_store_val(instr_t* instr, uint32_t val, ZydisDecoder* decoder, ZydisDecodedInstruction* dec_instr, ZydisDecoderContext* dec_ctx, uint64_t instr_va = NULL);
sym_id_t get_sym_id(const instr_t* instr, const ZydisDecodedInstruction* dec_instr);

//
// zydis wrappers
//

void zy_expect_success(ZyanStatus zystatus);

ZydisRegister reg_root(ZydisRegister reg);
ZydisRegisterWidth reg_width(ZydisRegister reg);

std::tuple<
    ZydisDecoderContext, 
    ZydisDecodedInstruction> decode_instr(
        const ZydisDecoder* decoder, 
        const uint8_t* raw_instr, 
        const size_t len);

std::vector<ZydisDecodedOperand> decode_ops(
    const ZydisDecoder* decoder, 
    const ZydisDecodedInstruction* dec_instr, 
    const ZydisDecoderContext* dec_ctx);

std::tuple<
    ZydisDecodedInstruction,
    std::vector<ZydisDecodedOperand>> decode_full(
        const ZydisDecoder* decoder, 
        const uint8_t* raw_instr, 
        const size_t len);


#define DECLARE_instr_t0(func_name, mnemonic) inline instr_t func_name()                            { return Instr(mnemonic, {},  {});  }
#define DECLARE_instr_t1(func_name, mnemonic) inline instr_t func_name(OPERAND op1)                    { return Instr(mnemonic, op1, {});  }
#define DECLARE_instr_t2(func_name, mnemonic) inline instr_t func_name(OPERAND op1, OPERAND op2)    { return Instr(mnemonic, op1, op2); }

// data movement
DECLARE_instr_t2(Mov, ZYDIS_MNEMONIC_MOV);
DECLARE_instr_t2(Lea, ZYDIS_MNEMONIC_LEA);
DECLARE_instr_t1(Push, ZYDIS_MNEMONIC_PUSH);
DECLARE_instr_t1(Pop, ZYDIS_MNEMONIC_POP);
DECLARE_instr_t2(Xchg, ZYDIS_MNEMONIC_XCHG);
DECLARE_instr_t2(Movsx, ZYDIS_MNEMONIC_MOVSX);
DECLARE_instr_t2(Movzx, ZYDIS_MNEMONIC_MOVZX);
DECLARE_instr_t2(Cmpxchg, ZYDIS_MNEMONIC_CMPXCHG);

// control
DECLARE_instr_t1(Call, ZYDIS_MNEMONIC_CALL);
DECLARE_instr_t0(Ret, ZYDIS_MNEMONIC_RET);
DECLARE_instr_t1(Jmp, ZYDIS_MNEMONIC_JMP);

// conditional
DECLARE_instr_t2(Cmp, ZYDIS_MNEMONIC_CMP);

// control-flow
DECLARE_instr_t1(Jz, ZYDIS_MNEMONIC_JZ);
DECLARE_instr_t1(Jnz, ZYDIS_MNEMONIC_JNZ);
DECLARE_instr_t1(Jl, ZYDIS_MNEMONIC_JL);
DECLARE_instr_t1(Jle, ZYDIS_MNEMONIC_JLE);
DECLARE_instr_t1(Jnl, ZYDIS_MNEMONIC_JNL);
DECLARE_instr_t1(Jnle, ZYDIS_MNEMONIC_JNLE);

// logical operation
DECLARE_instr_t2(And, ZYDIS_MNEMONIC_AND);
DECLARE_instr_t2(Xor, ZYDIS_MNEMONIC_XOR);
DECLARE_instr_t2(Or, ZYDIS_MNEMONIC_OR);

// arithmatic operation
DECLARE_instr_t2(Add, ZYDIS_MNEMONIC_ADD);
DECLARE_instr_t2(Sub, ZYDIS_MNEMONIC_SUB);

// other
DECLARE_instr_t0(Nop, ZYDIS_MNEMONIC_NOP);


#define DECLARE_REG(reg_name, mnemonic) extern const OPERAND reg_name##_;

DECLARE_REG(rax, ZYDIS_REGISTER_RAX);
DECLARE_REG(rbx, ZYDIS_REGISTER_RBX);
DECLARE_REG(rcx, ZYDIS_REGISTER_RCX);
DECLARE_REG(rdx, ZYDIS_REGISTER_RDX);
DECLARE_REG(rsi, ZYDIS_REGISTER_RSI);
DECLARE_REG(rdi, ZYDIS_REGISTER_RDI);
DECLARE_REG(rbp, ZYDIS_REGISTER_RBP);
DECLARE_REG(rsp, ZYDIS_REGISTER_RSP);
DECLARE_REG(r8, ZYDIS_REGISTER_R8);
DECLARE_REG(r9, ZYDIS_REGISTER_R9);
DECLARE_REG(r10, ZYDIS_REGISTER_R10);
DECLARE_REG(r11, ZYDIS_REGISTER_R11);
DECLARE_REG(r15, ZYDIS_REGISTER_R15);
DECLARE_REG(r12, ZYDIS_REGISTER_R12);
DECLARE_REG(r13, ZYDIS_REGISTER_R13);
DECLARE_REG(r14, ZYDIS_REGISTER_R14);

DECLARE_REG(eax, ZYDIS_REGISTER_EAX);
DECLARE_REG(ebx, ZYDIS_REGISTER_EBX);
DECLARE_REG(ecx, ZYDIS_REGISTER_ECX);
DECLARE_REG(edx, ZYDIS_REGISTER_EDX);
DECLARE_REG(esi, ZYDIS_REGISTER_ESI);
DECLARE_REG(edi, ZYDIS_REGISTER_EDI);
DECLARE_REG(ebp, ZYDIS_REGISTER_EBP);
DECLARE_REG(esp, ZYDIS_REGISTER_ESP);
DECLARE_REG(r8d, ZYDIS_REGISTER_R8D);
DECLARE_REG(r9d, ZYDIS_REGISTER_R9D);
DECLARE_REG(r10d, ZYDIS_REGISTER_R10D);
DECLARE_REG(r11d, ZYDIS_REGISTER_R11D);
DECLARE_REG(r15d, ZYDIS_REGISTER_R15D);
DECLARE_REG(r12d, ZYDIS_REGISTER_R12D);
DECLARE_REG(r13d, ZYDIS_REGISTER_R13D);
DECLARE_REG(r14d, ZYDIS_REGISTER_R14D);

DECLARE_REG(ax, ZYDIS_REGISTER_AX);
DECLARE_REG(bx, ZYDIS_REGISTER_BX);
DECLARE_REG(cx, ZYDIS_REGISTER_CX);
DECLARE_REG(dx, ZYDIS_REGISTER_DX);
DECLARE_REG(si, ZYDIS_REGISTER_SI);
DECLARE_REG(di, ZYDIS_REGISTER_DI);
DECLARE_REG(bp, ZYDIS_REGISTER_BP);
DECLARE_REG(sp, ZYDIS_REGISTER_SP);

DECLARE_REG(al, ZYDIS_REGISTER_AL);
DECLARE_REG(bl, ZYDIS_REGISTER_BL);
DECLARE_REG(cl, ZYDIS_REGISTER_CL);
DECLARE_REG(dl, ZYDIS_REGISTER_DL);
DECLARE_REG(sil, ZYDIS_REGISTER_SIL);
DECLARE_REG(dil, ZYDIS_REGISTER_DIL);
DECLARE_REG(bpl, ZYDIS_REGISTER_BPL);
DECLARE_REG(spl, ZYDIS_REGISTER_SPL);