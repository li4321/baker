#include "examples.h"

void control_flow_flattening(BINARY* bin) {
    SYMBOL*     sym_image_base = bin->rel_info(0, "__ImageBase");
    DATA_BLOCK* rva_table      = bin->data_block(0, false, "cff_data");
    SYMBOL*     sym_rva_table  = rva_table->data_sym(0);
    rva_table->alignment = 4;

    BASIC_BLOCK* dispatch_block = bin->basic_block("dispatch_block");
    dispatch_block->push({
        // rax -> index
        Lea(rcx_, Sid(sym_image_base->id)),
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
        int        entry_idx     = rva_table->bytes.size() / 4;
        SYMBOL* entry         = rva_table->push_val(0, sizeof(uint32_t));
        entry->target_type   = TARGET_TYPE_RVA;
        entry->target_sym_id = out_proxy_block->id;

        instr_store_val(end_instr, in_proxy_block->id,
            &bin->decoder, &end_dec_instr, &end_dec_ctx);

        in_proxy_block->push({
            Push(rax_),
            Push(rcx_),
            Mov(rax_, Imm32(entry_idx)),
            Jmp(Sid(dispatch_block->id))
        });

        out_proxy_block->push({
            Pop(rcx_),
            Pop(rax_),
            Jmp(Sid(target_sym_id))
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
    binary_print(&bin);

    // spam nops
    spam_nops_1337(&bin);
    
    // flatten control flow with dispatch block
    control_flow_flattening(&bin);


    ASSEMBLED_BINARY asm_bin = build_pe(&bin);
    assembled_binary_print(&asm_bin);

    output_file(asm_bin.filebuf.data(), asm_bin.filebuf.size(),
        "C:\\Users\\li\\source\\repos\\baker\\x64\\Release\\reassembled_crack_me.exe");
}