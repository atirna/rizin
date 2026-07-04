// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// Pure consumer of a decoded C6xInsn: fills the RzAnalysisOp fields that come
// from the instruction alone (type, size and control-flow targets). A predicated
// instruction (creg != 0) is conditional, which turns a branch into a CJMP.

RZ_IPI void c6x_fill_analysis(const C6xArchDesc *desc, const C6xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op) {
	rz_return_if_fail(desc && insn && op);
	op->size = insn->size; // 4 for a normal word, 2 for a compact instruction
	op->type = insn->op_type;
	op->family = insn->is_fp ? RZ_ANALYSIS_OP_FAMILY_FPU : RZ_ANALYSIS_OP_FAMILY_CPU;
	// An instruction is predicated only when it names a predicate register
	// (creg != 0). z is the test sense and is meaningful only alongside creg;
	// creg == 0 with z == 1 is an opcode bit (CALLP, the C66x complex ops),
	// not a predicate.
	bool conditional = insn->creg != 0;

	// Expose a constant operand as the op value, and treat an ADD/SUB that
	// writes the stack pointer (B15 in the C6000 EABI) as a frame adjustment.
	for (ut8 i = 0; i < insn->nops; i++) {
		if (insn->ops[i].kind == C6X_OP_IMM) {
			op->val = insn->ops[i].imm;
			break;
		}
	}
	if ((insn->op_type == RZ_ANALYSIS_OP_TYPE_ADD || insn->op_type == RZ_ANALYSIS_OP_TYPE_SUB) && insn->nops >= 2) {
		const C6xOperand *dst = &insn->ops[insn->nops - 1];
		bool sp_dst = dst->kind == C6X_OP_REG && dst->side == 1 && dst->num == 15;
		bool sp_src = insn->nops == 2; // 2-op ADDK/SUBK operate on dst in place
		st64 k = 0;
		bool has_imm = false;
		for (ut8 i = 0; i + 1 < insn->nops; i++) {
			if (insn->ops[i].kind == C6X_OP_IMM) {
				k = insn->ops[i].imm;
				has_imm = true;
			} else if (insn->ops[i].kind == C6X_OP_REG && insn->ops[i].side == 1 && insn->ops[i].num == 15) {
				sp_src = true;
			}
		}
		if (sp_dst && sp_src && has_imm) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = insn->op_type == RZ_ANALYSIS_OP_TYPE_SUB ? -k : k;
		}
	}

	switch (insn->op_type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
		// B displacement is relative to the fetch-packet base (PCE1), i.e. the
		// address masked to the 32-byte packet, not to the branch instruction.
		if (insn->nops > 0 && insn->ops[0].kind == C6X_OP_PCREL) {
			op->jump = (addr & ~(ut64)0x1f) + insn->ops[0].imm;
		}
		if (conditional) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + insn->size;
		}
		// A branch has five delay slots; the transfer is not immediate, but the
		// jump target is what matters for the CFG.
		op->delay = 5;
		break;
	case RZ_ANALYSIS_OP_TYPE_RJMP:
		// B to a register (e.g. B B3 return); target is data-dependent. B3 is the
		// return-address register in the C6x ABI, so an unconditional B .S2 B3 is
		// a function return.
		if (insn->nops > 0 && insn->ops[0].kind == C6X_OP_REG &&
			insn->ops[0].side == 1 && insn->ops[0].num == 3) {
			op->type = conditional ? RZ_ANALYSIS_OP_TYPE_CRET : RZ_ANALYSIS_OP_TYPE_RET;
		} else if (conditional) {
			op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
			op->fail = addr + insn->size;
		}
		op->delay = 5;
		break;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
		// BDEC/BPOS resolve a PC-relative target (PCE1 + scst10*4) like B, but
		// the branch is taken on a register test, so it is always two-way -- the
		// fall-through is the next execute packet.
		if (insn->nops > 0 && insn->ops[0].kind == C6X_OP_PCREL) {
			op->jump = (addr & ~(ut64)0x1f) + insn->ops[0].imm;
			op->fail = addr + insn->size;
		}
		op->delay = 5;
		break;
	default:
		if (conditional && insn->op_type != RZ_ANALYSIS_OP_TYPE_NOP) {
			op->cond = RZ_TYPE_COND_AL; // predicated, but not a branch
		}
		break;
	}
}
