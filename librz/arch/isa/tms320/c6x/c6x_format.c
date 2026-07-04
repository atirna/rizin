// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// Pure consumer of a decoded C6xInsn: emits the TI-style assembly text. The
// decoder has already resolved every field, so this only concerns syntax.

// Predicate register named by the creg field (SPRU733 Table 3-9). A0 (creg 110)
// is a C64x+ addition; naming it on older parts is harmless as the encoding is
// otherwise reserved there.
static const char *pred_reg(ut8 creg) {
	static const char *const names[8] = {
		NULL, "b0", "b1", "b2", "a1", "a2", "a0", NULL
	};
	return names[creg & 7];
}

static void fmt_reg(RzStrBuf *sb, ut8 side, ut8 num) {
	rz_strbuf_appendf(sb, "%c%u", side ? 'b' : 'a', num);
}

// Register pair is written odd:even (high:low), e.g. a1:a0.
static void fmt_regpair(RzStrBuf *sb, ut8 side, ut8 num) {
	char c = side ? 'b' : 'a';
	rz_strbuf_appendf(sb, "%c%u:%c%u", c, (num | 1u), c, (num & ~1u));
}

// Register quad is written high-to-low over four aligned registers, e.g.
// a7:a6:a5:a4 (base is a multiple of four).
static void fmt_regquad(RzStrBuf *sb, ut8 side, ut8 num) {
	char c = side ? 'b' : 'a';
	num &= ~3u;
	rz_strbuf_appendf(sb, "%c%u:%c%u:%c%u:%c%u", c, num + 3, c, num + 2, c, num + 1, c, num);
}

// Memory operand: base register with the addressing-mode decoration and either a
// register or (scaled) constant offset (SPRU733 Table 3-11).
static void fmt_mem(RzStrBuf *sb, const C6xOperand *o) {
	const char *pre = "", *post = "", *sign = "+";
	bool reg = false;
	switch (o->mode) {
	case C6X_AM_NEG_CST: sign = "-"; break;
	case C6X_AM_POS_CST: sign = "+"; break;
	case C6X_AM_NEG_REG: sign = "-", reg = true; break;
	case C6X_AM_POS_REG: sign = "+", reg = true; break;
	case C6X_AM_PREDEC_CST: pre = "--"; break;
	case C6X_AM_PREINC_CST: pre = "++"; break;
	case C6X_AM_POSTDEC_CST: post = "--"; break;
	case C6X_AM_POSTINC_CST: post = "++"; break;
	case C6X_AM_PREDEC_REG: pre = "--", reg = true; break;
	case C6X_AM_PREINC_REG: pre = "++", reg = true; break;
	case C6X_AM_POSTDEC_REG: post = "--", reg = true; break;
	case C6X_AM_POSTINC_REG: post = "++", reg = true; break;
	default: break;
	}
	// plain positive constant offset of zero collapses to *baseR
	bool plain = (o->mode == C6X_AM_POS_CST && o->off_cst == 0);
	rz_strbuf_append(sb, "*");
	if (pre[0]) {
		rz_strbuf_append(sb, pre);
	} else if (!post[0] && !plain) {
		rz_strbuf_append(sb, sign);
	}
	fmt_reg(sb, o->base_side, o->base);
	if (post[0]) {
		rz_strbuf_append(sb, post);
	}
	if (plain) {
		return;
	}
	rz_strbuf_append(sb, "[");
	if (reg) {
		fmt_reg(sb, o->base_side, o->off_reg);
	} else {
		rz_strbuf_appendf(sb, "0x%x", o->off_cst);
	}
	rz_strbuf_append(sb, "]");
}

static void fmt_operand(RzStrBuf *sb, const C6xInsn *insn, ut64 pc, const C6xOperand *o) {
	switch (o->kind) {
	case C6X_OP_REG:
		fmt_reg(sb, o->side, o->num);
		break;
	case C6X_OP_REGPAIR:
		fmt_regpair(sb, o->side, o->num);
		break;
	case C6X_OP_REGQUAD:
		fmt_regquad(sb, o->side, o->num);
		break;
	case C6X_OP_IMM:
		// NOP cycle counts, bit counts, and short signed constants read best
		// in decimal; wider move/address immediates in hex.
		if (o->imm_dec || o->imm < 0 || (insn->unit == C6X_UNIT_NONE)) {
			rz_strbuf_appendf(sb, "%" PFMT64d, (st64)o->imm);
		} else {
			rz_strbuf_appendf(sb, "0x%" PFMT64x, (ut64)o->imm);
		}
		break;
	case C6X_OP_CTRLREG:
		rz_strbuf_append(sb, o->name ? o->name : "?");
		break;
	case C6X_OP_MEM:
		fmt_mem(sb, o);
		break;
	case C6X_OP_PCREL:
		// Branch displacements are relative to the fetch-packet base (PCE1),
		// i.e. the address masked to the 32-byte packet, not the instruction.
		rz_strbuf_appendf(sb, "0x%" PFMT64x, (ut64)((pc & ~(ut64)0x1f) + o->imm));
		break;
	default:
		break;
	}
}

RZ_IPI RZ_OWN char *c6x_format(const C6xArchDesc *desc, const C6xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(desc && insn, NULL);
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}
	// Compact fetch-packet header (SPRUFE8 3.10.2): render the layout (which
	// of the seven words hold two 16-bit compact instructions) and the
	// expansion field (protection, register set, LD/ST data sizes, branch,
	// saturation). None of the predicate/parallel framing applies here.
	if (insn->is_header) {
		ut32 w = insn->word;
		// Table 3-15: primary/secondary LD/ST data size from DSZ bits 18:16.
		static const char *sec_dsz[8] = { "bu", "b", "hu", "h", "w", "b", "nw", "h" };
		ut8 dsz = (w >> 16) & 0x7;
		rz_strbuf_appendf(sb, ".fphead %s, %s, %s, %s, %s, %s, ",
			(w >> 20) & 1 ? "p" : "n", // PROT: protected loads
			(w >> 19) & 1 ? "h" : "l", // RS: high/low register set
			dsz < 4 ? "w" : "dw", // primary data size
			sec_dsz[dsz], // secondary data size
			(w >> 15) & 1 ? "br" : "nobr", // BR: S-unit compact are branches
			(w >> 14) & 1 ? "sat" : "nosat"); // SAT: compact saturate
		for (int b = 27; b >= 21; b--) { // layout field L7..L1
			rz_strbuf_append(sb, (w >> b) & 1 ? "1" : "0");
		}
		rz_strbuf_append(sb, "b");
		return rz_strbuf_drain(sb);
	}
	if (insn->cont) {
		rz_strbuf_append(sb, "|| ");
	}
	const char *pr = pred_reg(insn->creg);
	if (pr) {
		rz_strbuf_appendf(sb, "[%s%s] ", insn->z ? "!" : "", pr);
	}
	if (!insn->mnemonic) {
		rz_strbuf_append(sb, "invalid");
		return rz_strbuf_drain(sb);
	}
	rz_strbuf_append(sb, insn->mnemonic);
	if (insn->unit != C6X_UNIT_NONE) {
		char u = insn->unit == C6X_UNIT_L ? 'l' : insn->unit == C6X_UNIT_S ? 's'
			: insn->unit == C6X_UNIT_M                                 ? 'm'
										   : 'd';
		rz_strbuf_appendf(sb, " .%c%u%s", u, insn->unit_side, insn->cross ? "x" : "");
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		rz_strbuf_append(sb, i == 0 ? " " : ",");
		fmt_operand(sb, insn, pc, &insn->ops[i]);
	}
	return rz_strbuf_drain(sb);
}
