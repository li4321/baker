# binary rewriter/reassembler for x64 PE binaries [WIP]

takes in a binary and lifts the assembly into a very basic intermediate representation.
you can then modify this intermediate representation, and reassemble it into a new binary.

## currently works on:
  - C binary with no CRT
  - C binary with CRT

## currently supports:
  - jump tables

## work in progress:
  - .pdata exception directory
  - partial binary rewriting option to eliminate certain "unsolvable" issues

## example usage

in this example, it will show rewriting the binary with basic CFF and nops
![image](https://github.com/user-attachments/assets/ddc639b3-8101-4531-a850-b4f74ff2611f)

```cpp

    // disassemble exe
    auto filebuf = read_file_to_buffer("path_to_exe");
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
        "path_to_reassembled_exe");

```

flatten control flow
```cpp
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

```

spam nops
```cpp
void spam_nops_1337(BINARY* bin) {
    for (BASIC_BLOCK* bb : bin->basic_blocks) {
        for (int i = bb->instrs.size(); i > 0; i--) {
            bb->instrs.insert(begin(bb->instrs) + i - 1, Nop());
        }
    }
}
```

## current issues:
  - differentiating code (callback functions never called within binary itself) and data within executable sections, if there are also data in there
  - exceptions

## inspirations from:
https://github.com/jonomango/chum
