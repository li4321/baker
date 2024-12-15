#include "../disassembler.h"
#include "code_tracer.h"
#include <algorithm>

void DISASSEMBLER::collect_jump_tables() {
    for (BASIC_BLOCK* bb : bin.basic_blocks) {
        if (bb_explored_map[bb->id])
            continue;
        bb_explored_map[bb->id] = true;

        instr_t* end_instr = 
            &bb->instrs[bb->instrs.size() - 1];
        
        auto [end_dec_ctx, end_dec_instr] = 
            decode_instr(&bin.decoder, end_instr->bytes, end_instr->len);

        if (end_dec_instr.meta.category != ZYDIS_CATEGORY_COND_BR
            && end_dec_instr.meta.category != ZYDIS_CATEGORY_UNCOND_BR
            && end_dec_instr.meta.category != ZYDIS_CATEGORY_CALL)
            continue;

        auto end_dec_ops = decode_ops(&bin.decoder, &end_dec_instr, &end_dec_ctx);
        
        if (end_dec_ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;

        // lea base_reg, jpt
        // lea base_reg, __ImageBase
        ZydisRegister        base_reg = {};
        INSTR_TRACE_FRAME    load_base = {};

        // mov dst_reg, [base_reg + idx_reg * (4 or 8) + jump_table_rva]
        // mov dst_reg, [base_reg + idx_reg * (4 or 8)]
        INSTR_TRACE_FRAME    load_idx        = {};
        ZydisDecodedOperand* load_idx_mem_op = nullptr;
        uint32_t             jpt_rva         = 0;
        int                  jpt_alignment   = 0;

        // mov dst_reg, [base_reg:image_base + idx_reg * 4 + jump_table_rva]
        // mov dst_reg, [base_reg:jpt_rva     + idx_reg * 4]
        bb_backtrace(bb, bb->instrs.size() - 1, end_dec_ops[0],
            [&](ZydisDecodedOperand& target_op, INSTR_TRACE_FRAME f) -> bool {
                if (f.dec_instr.mnemonic == ZYDIS_MNEMONIC_MOV
                    && f.dec_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && reg_root(f.dec_ops[0].reg.value) == reg_root(target_op.reg.value)
                    && f.dec_ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && f.dec_ops[1].mem.base 
                    && f.dec_ops[1].mem.index 
                    && f.dec_ops[1].mem.scale) {
                    load_idx        = f;
                    base_reg        = load_idx.dec_ops[1].mem.base;
                    jpt_alignment   = load_idx.dec_ops[1].mem.scale;
                    load_idx_mem_op = &load_idx.dec_ops[1];
                    return true;
                }
            });

        if (!load_idx.instr)
            continue;

        // todo: handle other alignments later
        // but make sure they arent pointers, by comparing to the relocation table
        assert(load_idx.dec_ops[1].mem.scale == 4);

        // now we will trace for the instruction loading the base
        ZydisDecodedOperand base_reg_op = {
            .type = ZYDIS_OPERAND_TYPE_REGISTER,
            .reg = { .value = base_reg }
        };

        bb_backtrace(bb, load_idx.instr_idx - 1, base_reg_op,
            [&](ZydisDecodedOperand& target_op, INSTR_TRACE_FRAME f) -> bool {
                if (f.dec_instr.mnemonic == ZYDIS_MNEMONIC_LEA
                    && f.dec_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && reg_root(f.dec_ops[0].reg.value) == reg_root(target_op.reg.value)) {
                    load_base = f;
                    return true; // break out of the trace
                }
            });

        if (!load_base.instr)
            continue;

        sym_id_t base_sym_id = nullsid;
        assert(load_base.dec_instr.raw.disp.size == 32);
        memcpy(&base_sym_id, load_base.instr->bytes + load_base.dec_instr.raw.disp.offset, 4);
        
        SYMBOL* sym = bin.symbols[base_sym_id];

        // if there was a displacement within the index load
        // then the base should be the image base
        if (load_idx_mem_op->mem.disp.value) {
            if (sym->type != SYMBOL_TYPE_RELATIVE_INFO && sym->rel_offset != 0) {
                logger_warn("load_idx had displacement, but base was not the image base\n");
                continue;
            }
            jpt_rva = load_idx_mem_op->mem.disp.value;

        } else {
            if (sym->type == SYMBOL_TYPE_RELATIVE_INFO && sym->rel_offset == 0) {
                logger_warn("load_idx did not have displacement, but base was not the the jump table\n");
                continue;
            }
            jpt_rva = sym_rva_map[sym->id];
        }

        logger_log(WHITE, "", WHITE,
            fmtf("<analysis> found jump table at sym_%d -> 0x%X\n", bb->id, jpt_rva));
        
        auto&    rva_entry    = rva_map[jpt_rva];
        SYMBOL* jpt_sym        = nullptr;
        
        if (!rva_entry.id) {
            if (rva_in_exec_sect(jpt_rva)) {
                jpt_sym             = new SYMBOL{};
                jpt_sym->type       = SYMBOL_TYPE_RELATIVE_INFO;
                jpt_sym->rel_offset = jpt_rva;
                jpt_sym->id         = rva_entry.id = bin.symbols.size();
                bin.symbols.push_back(jpt_sym);
                sym_rva_map_append(jpt_rva);
            } else {
                uint32_t    db_offset = 0;
                DATA_BLOCK* jpt_db = rva_to_containing_db(jpt_rva, &db_offset);
                jpt_sym = jpt_db->data_sym(db_offset);
            }
        } else {
            jpt_sym = bin.symbols[rva_entry.id];
        }

        if (load_idx_mem_op->mem.disp.value) {
            // replace the displacement with the jump table symbol id
            assert(load_idx.dec_instr.raw.disp.size == 32);
            memcpy(load_idx.instr->bytes + load_idx.dec_instr.raw.disp.offset,
                &jpt_sym->id, 4);

            logger_log(WHITE, "", WHITE,
                fmtf("%s <changed displacement to jpt first entry id>\n", serialize_instr(&bin, load_idx.instr).c_str()));

            load_idx.instr->flags |= INSTR_FLAG_MEM_IDX;
        } else {
            assert(sym->id == jpt_sym->id);

            logger_log(WHITE, "", WHITE,
                fmtf("sym_%d converted to first data symbol of the jump table\n", sym->id));
        }

        jpt_rva_list.insert(jpt_rva);
    }
}

void DISASSEMBLER::resolve_jpt_entries() {
    for (uint32_t jpt_rva : jpt_rva_list) {
        auto& jpt_rva_entry = rva_map[jpt_rva];
        assert(jpt_rva_entry.id);

        SYMBOL*     jpt_sym   = bin.symbols[jpt_rva_entry.id];
        uint32_t    db_offset = 0;
        DATA_BLOCK* db        = nullptr;

        if (rva_in_exec_sect(jpt_rva)) {
            db = bin.data_block(0, true, fmtf("code_data_%x", jpt_rva));
        } else {
            db = rva_to_containing_db(jpt_rva, &db_offset);
        }

        for (int i = 0; true; i++) {
            uint32_t offset     = i * 4;
            uint32_t entry_rva  = jpt_rva + offset;
            uint32_t target_rva = *rvacast<uint32_t*>(entry_rva);

            // if we ran into another jump table
            if (offset && jpt_rva_list.find(entry_rva) != jpt_rva_list.end()) {
                logger_log(WHITE, "", WHITE, 
                    fmtf("jump table runs into another at idx: %d\n", i));
                break;
            }

            // if this is not a valid rva towards code
            if (!rva_in_exec_sect(target_rva)) {
                logger_log(WHITE, "", WHITE,
                    fmtf("jump table invalid target rva at idx: %d\n", i));
                break;
            }

            sym_id_t target_sym_id = queue_rva(target_rva).id;
            auto&   rva_entry = rva_map[entry_rva];
            SYMBOL* sym       = nullptr;
            if (rva_entry.id) {
                sym = bin.symbols[rva_entry.id];
                if (rva_in_exec_sect(entry_rva)) {
                    assert(sym->type == SYMBOL_TYPE_RELATIVE_INFO && sym->rel_offset == entry_rva);
                    sym->type      = SYMBOL_TYPE_DATA;
                    sym->db        = db;
                    sym->db_offset = offset;
                }
            } else {
                sym = db->data_sym(offset);
                rva_map[entry_rva].id = sym->id;
                sym_rva_map_append(entry_rva);
            }

            db->bytes.insert(end(db->bytes), 4, 0);

            sym->target_type   = TARGET_TYPE_RVA;
            sym->target_sym_id = target_sym_id;
        }
    }
}