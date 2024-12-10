#include "examples.h"

void create_beep_program() {
    BINARY bin = {};

    IMPORT_MODULE* mod_k32  = bin.import_module("kernel32.dll");
    sym_id_t       imp_Beep = bin.import_routine(mod_k32, "Beep")->id;

    DATA_BLOCK* rdata           = bin.data_block(0, true, "rdata");
    sym_id_t    str_hello_world = rdata->push_str("Hello, World!\n")->id;

    DATA_BLOCK* data = bin.data_block(1000, false, "data");

    BASIC_BLOCK* bb_main      = bin.set_entry(bin.basic_block());
    BASIC_BLOCK* bb_call_beep = bin.basic_block();
    BASIC_BLOCK* bb_junk      = bin.basic_block();
    BASIC_BLOCK* bb_end       = bin.basic_block();

    bb_main->push({
        Lea(rax_, RipRel(str_hello_world)),
        }).fall(bb_call_beep->id);

    // Beep(1000, 1000);
    
    bb_call_beep->push({
        Mov(rax_, RipRel(imp_Beep)),
        Mov(rcx_, Imm(1000)),
        Mov(rdx_, Imm(1000)),
        Sub(rsp_, Imm(0x28)),
        Call(rax_),
        Add(rsp_, Imm(0x28)),
        }).fall(bb_end->id);

    bb_junk->push({
        Nop(),
        Nop(),
        Nop(),
        });

    bb_end->push({
        Mov(rax_, Imm(1234)),
        Ret()
        });

    binary_print(&bin);

    ASSEMBLED_BINARY asm_bin = build_pe(&bin);

    output_file(asm_bin.filebuf.data(), asm_bin.filebuf.size(),
        "C:\\Users\\li\\source\\repos\\baker\\x64\\release\\assemble_beep_test.exe");

    assembled_binary_print(&asm_bin);
}