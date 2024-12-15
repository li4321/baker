#include "examples.h"
#include <math.h>

void opaque_predicates(BINARY* bin) {
    for (int bb_idx = bin->basic_blocks.size() - 1; bb_idx >= 0; bb_idx--) {
        BASIC_BLOCK* bb = bin->basic_blocks[bb_idx];

        for (int instr_idx = 0; instr_idx < bb->instrs.size(); instr_idx++) {
            instr_t* instr = &bb->instrs[instr_idx];
            auto [dec_instr, dec_ops] =
                decode_full(&bin->decoder, instr->bytes, instr->len);
            
            if (dec_instr.mnemonic != ZYDIS_MNEMONIC_MOV)
                continue;
            if (dec_ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;

            // split basic block
            BASIC_BLOCK* new_bb = bin->basic_block();
            new_bb->fall(bb->fallthrough_sym_id);
            
            new_bb->instrs.insert(begin(new_bb->instrs),
                begin(bb->instrs) + instr_idx + 1,
                end(bb->instrs));
            
            bb->instrs.erase(
                begin(bb->instrs) + instr_idx + 1,
                end(bb->instrs));

            // x = reg
            OPERAND reg = {
                .type = OP_REG,
                .reg  = dec_ops[0].reg.value
            };

            OPERAND root_reg = {
                .type = OP_REG,
                .reg  = reg_root(dec_ops[0].reg.value)
            };

            BASIC_BLOCK* even_branch = bin->basic_block();
            BASIC_BLOCK* odd_branch  = bin->basic_block();

            bb->push({
                Pushfq(),                // save flags
                Push(root_reg),          // save register
                Test(reg, Imm(1)),     // check if even
                Jz(ImmRel(even_branch->id))
            })->fall(odd_branch->id);

            // even branch
            // (x/2) * 2 == x
            even_branch->push({
                Shr(reg, Imm(1)),     // (x/2)
                Shl(reg, Imm(1)),     // (x/2) * 2
                Cmp(reg, Mem(rsp_, 0)), // (x/2) * 2 == x
                Jz(ImmRel(new_bb->id))
            });

            // odd branch
            // (x*x) % 8 == 1
            odd_branch->push({
                Imul(reg, reg),       // x*x
                Test(reg, Imm(7)),  // (x*x) % 8
                Jnz(ImmRel(new_bb->id))  // (x*x) % 8 == 1
            });

            new_bb->insert(0, { Pop(root_reg), Popfq()});
        }
    }
}

void control_flow_flattening(BINARY* bin) {
    SYMBOL*     sym_image_base = bin->rel_info(0, "__ImageBase");
    DATA_BLOCK* rva_table      = bin->data_block(0, false, "cff_data");
    SYMBOL*     sym_rva_table  = rva_table->data_sym(0);
    rva_table->alignment = 4;

    BASIC_BLOCK* dispatch_block = bin->basic_block("dispatch_block");
    dispatch_block->push({
        // rax -> index
        Lea(rcx_, RipRel(sym_image_base->id)),
        Mov(eax_, MemIdx(rcx_, rax_, 4, sym_rva_table->id)),
        
        Add(ecx_, eax_),
        Jmp(rcx_)
    });

    for (int i = bin->basic_blocks.size() - 1; i >= 0; i--) {
        BASIC_BLOCK* bb = bin->basic_blocks[i];

        instr_t* end_instr = &bb->instrs[bb->instrs.size() - 1];
        auto [end_dec_ctx, end_dec_instr] = 
            decode_instr(&bin->decoder, end_instr->bytes, end_instr->len);
        
        if (end_dec_instr.meta.category != ZYDIS_CATEGORY_COND_BR) {
            continue;
        }

        sym_id_t target_sym_id = get_sym_id(end_instr, &end_dec_instr);

        BASIC_BLOCK* in_proxy_block  = bin->basic_block();
        BASIC_BLOCK* out_proxy_block = bin->basic_block();
        
        // push a entry, which turns into the target rva
        int     entry_idx    = rva_table->bytes.size() / 4;
        SYMBOL* entry        = rva_table->push_val(0, sizeof(uint32_t));
        entry->target_type   = TARGET_TYPE_RVA;
        entry->target_sym_id = out_proxy_block->id;

        instr_store_val(end_instr, in_proxy_block->id,
            &bin->decoder, &end_dec_instr, &end_dec_ctx);

        in_proxy_block->push({
            Push(rax_),
            Push(rcx_),
            Mov(rax_, Imm(entry_idx)),
            Jmp(ImmRel(dispatch_block->id))
        });

        out_proxy_block->push({
            Pop(rcx_),
            Pop(rax_),
            Jmp(ImmRel(target_sym_id))
        });
    }
}

void spam_nops_1337(BINARY* bin) {
    for (BASIC_BLOCK* bb : bin->basic_blocks) {
        for (int i = bb->instrs.size(); i > 0; i--) {
            bb->instrs.insert(begin(bb->instrs) + i - 1, Nop());
        }
    }
}

void rewrite_crackme() {
    // disassemble ExampleCrackMe.exe
    auto filebuf = read_file_to_buffer("C:\\Users\\li\\source\\repos\\baker\\x64\\Release\\ExampleCrackMe.exe");
    const DISASSEMBLED_BINARY disasm_bin = disassemble_pe(filebuf);

    BINARY bin = {};
    binary_duplicate(&disasm_bin.bin, &bin);

    opaque_predicates(&bin);
    spam_nops_1337(&bin);
    control_flow_flattening(&bin);

    ASSEMBLED_BINARY asm_bin = build_pe(&bin);
    assembled_binary_print(&asm_bin);

    output_file(asm_bin.filebuf.data(), asm_bin.filebuf.size(),
        "C:\\Users\\li\\source\\repos\\baker\\x64\\Release\\reassembled_crack_me.exe");
}
