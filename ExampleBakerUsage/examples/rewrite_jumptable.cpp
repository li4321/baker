#include "examples.h"

void rewrite_jumptable() {
	// disassemble .exe
	auto filebuf = read_file_to_buffer("C:\\Users\\li\\source\\repos\\baker\\x64\\Release\\ExampleJumpTable.exe");
	const DISASSEMBLED_BINARY disasm_bin = disassemble_pe(filebuf);

	BINARY bin = {};
	binary_duplicate(&disasm_bin.bin, &bin);
	binary_print(&bin);

	ASSEMBLED_BINARY asm_bin = build_pe(&bin);
	assembled_binary_print(&asm_bin);

	output_file(asm_bin.filebuf.data(), asm_bin.filebuf.size(),
		"C:\\Users\\li\\source\\repos\\baker\\x64\\Release\\reassembled_JumpTable.exe");
}