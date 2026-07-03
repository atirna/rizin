// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c6x_il.c
 * TMS320C6000 RzIL lifting.
 *
 * Lifts a decoded \ref C6xInsn (from c6x_decode.c) to RzIL: the register / IL-VM
 * configuration and the per-instruction lifter wired into the analysis op via
 * op->il_op. Kept separate from the disassembler so decode and IL are
 * independent. The scalar move / ALU / shift / multiply / load / store core is
 * lifted; forms not yet handled return NULL and simply leave op->il_op unset.
 *
 * Two architectural notes bound what is modelled here. C6000 is a VLIW: every
 * instruction of an execute packet reads its sources at the packet start and
 * writes at its end, so within a packet an instruction never sees another's
 * result. The RzIL VM steps sequentially, so a "|| mv a,b || mv b,a" swap is
 * not modelled exactly; ordinary (non-swapping) parallel code lifts correctly.
 * Branches have five delay slots and are left unlifted for now, so IL covers
 * straight-line data flow.
 */

#include <rz_util.h>
#include "c6x.h"

/* RzIL VM */

// IL-VM register bindings: the 32+32 general-purpose registers (a0-a31,
// b0-b31), pce1 (the program counter, named as the register profile does), then
// the control registers MVC reaches -- the set common to every C6000, followed
// by the C64x+ extension. A single flat table doubles as the name lookup for a
// general-register operand: side A occupies indices 0-31 and side B 32-63, so
// c6x_reg_name(side, num) indexes it directly and never reaches pce1 or the
// control registers past it. Names are borrowed by the IL ops (never copied),
// so the table must outlive them -- hence static const.
static const char *const c6x_il_regs[] = {
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
	"a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23",
	"a24", "a25", "a26", "a27", "a28", "a29", "a30", "a31",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
	"pce1",
	// control registers common to all C6000 variants
	"amr", "csr", "gfpgfr", "icr", "ier", "ifr", "irp", "isr", "istp", "nrp",
	// C64x+ control-register extension
	"dier", "dnum", "ecr", "efr", "gplya", "gplyb", "ierr", "ilc", "itsr",
	"ntsr", "rep", "rilc", "ssr", "tsch", "tscl", "tsr",
	NULL
};

// C62x/C67x expose only the low 16 registers per side and lack the C64x+
// control-register extension; their register profile omits a16-a31/b16-b31 and
// that extension, so bind only the matching subset -- the IL-VM setup fails if
// asked to bind a register the profile never declares.
static const char *const c6x_il_regs16[] = {
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
	"pce1",
	"amr", "csr", "gfpgfr", "icr", "ier", "ifr", "irp", "isr", "istp", "nrp",
	NULL
};

RZ_IPI RzAnalysisILConfig *tms320_c6x_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// 32-bit PC over a byte-addressed space, little-endian.
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	if (!cfg) {
		return NULL;
	}
	const C6xArchDesc *desc = c6x_desc_from_cpu(rz_analysis_get_cpu(analysis));
	cfg->reg_bindings = (const char **)((desc && desc->num_regs <= 16) ? c6x_il_regs16 : c6x_il_regs);
	return cfg;
}

#include <rz_il/rz_il_opbuilder_begin.h>

// Global-variable name of register `num` on side `side` (0 = A, 1 = B).
static const char *c6x_reg_name(ut8 side, ut8 num) {
	return c6x_il_regs[(side & 1) * 32 + (num & 31)];
}

// Predicate register named by the creg field (SPRU733 Table 3-9), or NULL when
// unconditional. Mirrors the disassembler's pred_reg().
static const char *c6x_pred_name(ut8 creg) {
	static const char *const names[8] = {
		NULL, "b0", "b1", "b2", "a1", "a2", "a0", NULL
	};
	return names[creg & 7];
}

// 32-bit value of a register or immediate source operand, or NULL for kinds
// this core does not model as a scalar (pairs, quads, control regs, memory).
static RzILOpPure *c6x_src(const C6xOperand *o) {
	switch (o->kind) {
	case C6X_OP_REG:
		return VARG(c6x_reg_name(o->side, o->num));
	case C6X_OP_IMM:
		return S32(o->imm);
	default:
		return NULL;
	}
}

// Write `v` to a register destination, or free it and fail for other kinds.
static RzILOpEffect *c6x_wr(const C6xOperand *o, RzILOpPure *v) {
	if (o->kind == C6X_OP_REG) {
		return SETG(c6x_reg_name(o->side, o->num), v);
	}
	rz_il_op_pure_free(v);
	return NULL;
}

// dst = src1 OP src2, the shared shape of the register/immediate ALU ops. `mk`
// builds the value from the two decoded sources.
static RzILOpEffect *c6x_alu3(const C6xInsn *insn, rz_il_pure_2args_op *mk) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&insn->ops[2], mk(s1, s2));
}

// dst = (src1 CMP src2) ? 1 : 0, the shared shape of the compare ops.
static RzILOpEffect *c6x_cmp(const C6xInsn *insn, rz_il_bool_2args_op *mk) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&insn->ops[2], ITE(mk(s1, s2), U32(1), U32(0)));
}

// Low 16 bits of `v`, sign-extended back to 32 -- the operand form shared by
// the 16x16 multiplies and the *L half selectors.
static RzILOpPure *c6x_low16s(RzILOpPure *v) {
	return SIGNED(32, UNSIGNED(16, v));
}

// High 16 bits of `v`, sign-extended to 32.
static RzILOpPure *c6x_high16s(RzILOpPure *v) {
	return SIGNED(32, UNSIGNED(16, SHIFTR0(v, U32(16))));
}

// Clamp a 32-bit signed value to the signed n-bit range, returned as n bits --
// the saturation shared by the saturating packed ops. The wide value is bound
// once so both bound checks and the pass-through see the same operand.
static RzILOpBitVector *c6x_sat_s(RzILOpPure *x, ut8 n) {
	st64 hi = (1LL << (n - 1)) - 1;
	st64 lo = -(1LL << (n - 1));
	return LET("_sat", x,
		ITE(SGT(VARLP("_sat"), S32(hi)), SN(n, hi),
			ITE(SLT(VARLP("_sat"), S32(lo)), SN(n, lo),
				UNSIGNED(n, VARLP("_sat")))));
}

// Absolute value of one signed 16-bit lane, saturating 0x8000 to 0x7fff (it is
// its own negation). The lane is bound once so the sign test, the endpoint test
// and the negation all see it.
static RzILOpBitVector *c6x_abs16(RzILOpBitVector *lane) {
	return LET("_h", lane,
		ITE(SGE(VARLP("_h"), SN(16, 0)), VARLP("_h"),
			ITE(EQ(VARLP("_h"), UN(16, 0x8000)), UN(16, 0x7fff), NEG(VARLP("_h")))));
}

// Packed add/sub (ADD2/SUB2 over two halfwords, ADD4/SUB4 over four bytes):
// `lanes` equal-width lanes computed independently, with no carry across a lane
// boundary -- RzIL ADD/SUB is modular at the operand width, so each lane wraps
// on its own. APPEND stacks the lanes back with the highest on top.
static RzILOpEffect *c6x_packed(const C6xInsn *insn, ut8 lanes, bool sub) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBitVector *lane = sub ? SUB(la, lb) : ADD(la, lb);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&insn->ops[2], acc);
}

// Packed signed saturating add/sub (SADD2/SSUB2): each 16-bit lane is summed in
// 32-bit signed and clamped back to the signed 16-bit range, so a lane that
// overflows sticks at the endpoint instead of wrapping.
static RzILOpEffect *c6x_sat_packed(const C6xInsn *insn, ut8 lanes, bool sub) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = SIGNED(32, UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a));
		RzILOpBitVector *lb = SIGNED(32, UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b));
		RzILOpBitVector *lane = c6x_sat_s(sub ? SUB(la, lb) : ADD(la, lb), width);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&insn->ops[2], acc);
}

// Packed per-lane min/max (MIN2/MAX2 signed halfwords, MINU4/MAXU4 unsigned
// bytes). Each lane compares src1 against src2 (signed or unsigned) and keeps
// the smaller or larger; the compared value is duplicated so the winning lane
// is still available to write.
static RzILOpEffect *c6x_minmax(const C6xInsn *insn, ut8 lanes, bool sgned, bool is_min) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBool *le = sgned ? SLE(DUP(la), DUP(lb)) : ULE(DUP(la), DUP(lb));
		// min keeps src1 when src1 <= src2; max keeps src2 in that case
		RzILOpBitVector *lane = is_min ? ITE(le, la, lb) : ITE(le, lb, la);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&insn->ops[2], acc);
}

// Four-way byte dot product: sum of the four byte-lane products into a 32-bit
// result. `s1_signed` sign-extends src1's bytes (DOTPSU4); src2's bytes are
// always unsigned, as is DOTPU4's src1.
static RzILOpEffect *c6x_dotp4(const C6xInsn *insn, bool s1_signed) {
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < 4; i++) {
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *ba = UNSIGNED(8, i ? SHIFTR0(a, U32(i * 8)) : a);
		RzILOpBitVector *bb = UNSIGNED(8, i ? SHIFTR0(b, U32(i * 8)) : b);
		RzILOpBitVector *prod = MUL(s1_signed ? SIGNED(32, ba) : UNSIGNED(32, ba), UNSIGNED(32, bb));
		acc = acc ? ADD(acc, prod) : prod;
	}
	return c6x_wr(&insn->ops[2], acc);
}

// Packed compare to a bit-per-lane mask (CMPEQ2/CMPGT2 halfwords, CMPEQ4/CMPGTU4
// bytes): lane i sets bit i when it satisfies `mk`, and the mask is
// zero-extended to 32 bits. The comparison reads each lane at its own width, so
// SGT/UGT there give the signed or unsigned relation the mnemonic wants.
static RzILOpEffect *c6x_cmp_packed(const C6xInsn *insn, ut8 lanes, rz_il_bool_2args_op *mk) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *mask = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(mask);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBitVector *bit = ITE(mk(la, lb), UN(1, 1), UN(1, 0));
		mask = mask ? APPEND(bit, mask) : bit;
	}
	return c6x_wr(&insn->ops[2], UNSIGNED(32, mask));
}

// A binary single-precision float constructor (fadd/fsub/fmul), mirroring the
// pure/bool 2-arg op typedefs for the shared shape of the float arithmetic.
typedef RzILOpFloat *(c6x_fbin_op)(RzFloatRMode, RzILOpFloat *, RzILOpFloat *);

// Single-precision float op: read src1/src2 as binary32, apply `mk` rounding to
// nearest-even (the C6000 reset default), and write the result's bits back.
static RzILOpEffect *c6x_fsp(const C6xInsn *insn, c6x_fbin_op *mk) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&insn->ops[2], F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV32(s1), FLOATV32(s2))));
}

// Read a register pair as one 64-bit value: the even member is the low word and
// the odd member the high word, matching how LDDW loads a doubleword.
static RzILOpBitVector *c6x_pair64(const C6xOperand *o) {
	if (o->kind != C6X_OP_REGPAIR) {
		return NULL;
	}
	return APPEND(VARG(c6x_reg_name(o->side, o->num + 1)), VARG(c6x_reg_name(o->side, o->num)));
}

// Write a 64-bit value into a register pair (low word -> even, high -> odd),
// binding it to a local so both halves read the same result.
static RzILOpEffect *c6x_wr_pair64(const C6xOperand *o, RzILOpBitVector *v) {
	if (o->kind != C6X_OP_REGPAIR) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SEQ3(SETL("_d", v),
		SETG(c6x_reg_name(o->side, o->num), UNSIGNED(32, VARL("_d"))),
		SETG(c6x_reg_name(o->side, o->num + 1), UNSIGNED(32, SHIFTR0(VARL("_d"), U32(32)))));
}

// Read a 40-bit long from a register pair, sign-extended from bit 39 to 64 bits
// (the even register holds bits [31:0], the odd register bits [39:32]).
static RzILOpBitVector *c6x_long40(const C6xOperand *o) {
	RzILOpBitVector *p = c6x_pair64(o);
	if (!p) {
		return NULL;
	}
	return SHIFTRA(SHIFTL0(p, U32(24)), U32(24));
}

// Double-precision float op over register pairs (binary64, round to nearest
// even).
static RzILOpEffect *c6x_fdp(const C6xInsn *insn, c6x_fbin_op *mk) {
	RzILOpBitVector *a = c6x_pair64(&insn->ops[0]);
	RzILOpBitVector *b = c6x_pair64(&insn->ops[1]);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return c6x_wr_pair64(&insn->ops[2], F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV64(a), FLOATV64(b))));
}

// The high or low halfword of a source, as a 16-bit value -- the halfword
// selector shared by the PACK2 family.
static RzILOpBitVector *c6x_half(const C6xOperand *o, bool high) {
	RzILOpPure *s = c6x_src(o);
	return s ? UNSIGNED(16, high ? SHIFTR0(s, U32(16)) : s) : NULL;
}

// dst = (halfword of src1) : (halfword of src2); PACK2/PACKH2/PACKLH2/PACKHL2
// differ only in which halfword each source contributes.
static RzILOpEffect *c6x_pack(const C6xInsn *insn, bool hi_from_high, bool lo_from_high) {
	RzILOpBitVector *hi = c6x_half(&insn->ops[0], hi_from_high);
	RzILOpBitVector *lo = c6x_half(&insn->ops[1], lo_from_high);
	if (!hi || !lo) {
		rz_il_op_pure_free(hi);
		rz_il_op_pure_free(lo);
		return NULL;
	}
	return c6x_wr(&insn->ops[2], APPEND(hi, lo));
}

// Byte `idx` of a source, zero-extended to 16 bits -- the lane selector shared
// by the UNPK*U4 unpacks.
static RzILOpBitVector *c6x_byte_zx16(const C6xOperand *o, ut8 idx) {
	RzILOpPure *s = c6x_src(o);
	return s ? UNSIGNED(16, UNSIGNED(8, idx ? SHIFTR0(s, U32(idx * 8)) : s)) : NULL;
}

// dst = zero-extend two bytes of src to two halfwords. UNPKLU4 takes bytes 0,1;
// UNPKHU4 takes bytes 2,3. The lower byte lands in the lower halfword.
static RzILOpEffect *c6x_unpku4(const C6xInsn *insn, bool high) {
	ut8 base = high ? 2 : 0;
	RzILOpBitVector *hw0 = c6x_byte_zx16(&insn->ops[0], base);
	RzILOpBitVector *hw1 = c6x_byte_zx16(&insn->ops[0], base + 1);
	if (!hw0 || !hw1) {
		rz_il_op_pure_free(hw0);
		rz_il_op_pure_free(hw1);
		return NULL;
	}
	return c6x_wr(&insn->ops[1], APPEND(hw1, hw0));
}

// Effective address of a memory operand. When the mode modifies the base
// register, *wb receives that update and *pre says whether it applies before
// the access (pre-increment) or after it (post-increment). `bytes` scales a
// register/constant offset written with the scaled (bracket) syntax.
static RzILOpPure *c6x_ea(const C6xOperand *m, ut8 bytes, RzILOpEffect **wb, bool *pre) {
	*wb = NULL;
	*pre = false;
	const char *base = c6x_reg_name(m->base_side, m->base);
	ut32 scale = m->scaled ? bytes : 1;
	bool reg_off = false, dec = false, modify = false, ispre = false;
	switch (m->mode) {
	case C6X_AM_NEG_REG:
		reg_off = true;
		dec = true;
		break;
	case C6X_AM_POS_REG: reg_off = true; break;
	case C6X_AM_NEG_CST: dec = true; break;
	case C6X_AM_POS_CST:
	case C6X_AM_BASE_LONG: break;
	case C6X_AM_PREDEC_REG:
		reg_off = true;
		dec = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_PREINC_REG:
		reg_off = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_POSTDEC_REG:
		reg_off = true;
		dec = true;
		modify = true;
		break;
	case C6X_AM_POSTINC_REG:
		reg_off = true;
		modify = true;
		break;
	case C6X_AM_PREDEC_CST:
		dec = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_PREINC_CST:
		modify = true;
		ispre = true;
		break;
	case C6X_AM_POSTDEC_CST:
		dec = true;
		modify = true;
		break;
	case C6X_AM_POSTINC_CST: modify = true; break;
	default:
		return NULL;
	}
	RzILOpPure *off = reg_off
		? (scale > 1 ? MUL(VARG(c6x_reg_name(m->base_side, m->off_reg)), U32(scale)) : VARG(c6x_reg_name(m->base_side, m->off_reg)))
		: U32(m->off_cst * scale);
	if (modify) {
		// pre/post modify: base <- base +/- off; EA reads the base, before the
		// update for pre-modify and (unchanged) after it for post-modify.
		*wb = SETG(base, dec ? SUB(VARG(base), off) : ADD(VARG(base), off));
		*pre = ispre;
		return VARG(base);
	}
	return dec ? SUB(VARG(base), off) : ADD(VARG(base), off);
}

// Order a memory access against its base write-back: pre-modify updates first,
// post-modify updates after, and a plain offset has no write-back.
static RzILOpEffect *c6x_mem_seq(RzILOpEffect *access, RzILOpEffect *wb, bool pre) {
	if (!wb) {
		return access;
	}
	return pre ? SEQ2(wb, access) : SEQ2(access, wb);
}

// Load: dst = extend(mem[EA]). `sign` selects sign- vs zero-extension to 32.
static RzILOpEffect *c6x_load(const C6xInsn *insn, ut8 bytes, bool sign) {
	if (insn->ops[1].kind != C6X_OP_REG || bytes > 4) {
		return NULL; // single-register widths only; pairs use c6x_load_pair
	}
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&insn->ops[0], bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	RzILOpPure *val = bytes == 4 ? LOADW(32, ea) : (sign ? SIGNED(32, LOADW(bytes * 8, ea)) : UNSIGNED(32, LOADW(bytes * 8, ea)));
	RzILOpEffect *set = SETG(c6x_reg_name(insn->ops[1].side, insn->ops[1].num), val);
	return c6x_mem_seq(set, wb, pre);
}

// Store: mem[EA] = truncate(src). Pairs use c6x_store_pair.
static RzILOpEffect *c6x_store(const C6xInsn *insn, ut8 bytes) {
	if (insn->ops[0].kind != C6X_OP_REG || bytes > 4) {
		return NULL;
	}
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&insn->ops[1], bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	RzILOpPure *src = VARG(c6x_reg_name(insn->ops[0].side, insn->ops[0].num));
	RzILOpEffect *st = bytes == 4 ? STOREW(ea, src) : STOREW(ea, UNSIGNED(bytes * 8, src));
	return c6x_mem_seq(st, wb, pre);
}

// Doubleword load into a register pair: the even member gets mem[EA] and the
// odd member mem[EA+4] (little-endian keeps the low word at the lower address).
// The address is bound to a local so both accesses share one base computation.
// LDNDW behaves the same here; only its alignment requirement differs.
static RzILOpEffect *c6x_load_pair(const C6xInsn *insn) {
	if (insn->ops[1].kind != C6X_OP_REGPAIR) {
		return NULL;
	}
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&insn->ops[0], 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(insn->ops[1].side, insn->ops[1].num);
	const char *hi = c6x_reg_name(insn->ops[1].side, insn->ops[1].num + 1);
	RzILOpEffect *body = SEQ3(SETL("ea", ea),
		SETG(lo, LOADW(32, VARL("ea"))),
		SETG(hi, LOADW(32, ADD(VARL("ea"), U32(4)))));
	return c6x_mem_seq(body, wb, pre);
}

// Doubleword store from a register pair: mem[EA] <- even member, mem[EA+4] <-
// odd member. STDW and the non-aligned STNDW share this data path.
static RzILOpEffect *c6x_store_pair(const C6xInsn *insn) {
	if (insn->ops[0].kind != C6X_OP_REGPAIR) {
		return NULL;
	}
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&insn->ops[1], 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(insn->ops[0].side, insn->ops[0].num);
	const char *hi = c6x_reg_name(insn->ops[0].side, insn->ops[0].num + 1);
	RzILOpEffect *body = SEQ3(SETL("ea", ea),
		STOREW(VARL("ea"), VARG(lo)),
		STOREW(ADD(VARL("ea"), U32(4)), VARG(hi)));
	return c6x_mem_seq(body, wb, pre);
}

// One 16-bit half of `v` widened to 32 bits: the high or low halfword, sign- or
// zero-extended per the multiply variant.
static RzILOpPure *c6x_half16(RzILOpPure *v, bool high, bool sign) {
	RzILOpBitVector *h = UNSIGNED(16, high ? SHIFTR0(v, U32(16)) : v);
	return sign ? SIGNED(32, h) : UNSIGNED(32, h);
}

// dst = half16(src1) x half16(src2), the shared shape of the 16x16 multiplies.
// Each half is widened to 32 bits by its own signedness; the true product fits
// in 32 bits, so the modular MUL yields the exact result for every sign mix.
static RzILOpEffect *c6x_mpy16(const C6xInsn *insn, bool s1_hi, bool s1_sgn, bool s2_hi, bool s2_sgn) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&insn->ops[2], MUL(c6x_half16(s1, s1_hi, s1_sgn), c6x_half16(s2, s2_hi, s2_sgn)));
}

// dst = sat((signed half16(src1) x signed half16(src2)) << 1). The doubled
// product overflows 32-bit signed only for (-0x8000)^2, whose product is
// 0x40000000; that one case saturates to 0x7fffffff, every other doubles in place.
static RzILOpEffect *c6x_smpy(const C6xInsn *insn, bool s1_hi, bool s2_hi) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	RzILOpBitVector *p = MUL(c6x_half16(s1, s1_hi, true), c6x_half16(s2, s2_hi, true));
	return c6x_wr(&insn->ops[2],
		LET("_p", p,
			ITE(EQ(VARLP("_p"), U32(0x40000000)), U32(0x7fffffff), SHIFTL0(VARLP("_p"), U32(1)))));
}

// 32x32 multiply, signedness per source. A pair dst takes the full 64-bit
// product (each source widened to 64 by its signedness); a single dst keeps the
// low 32 bits, which are signedness-independent.
static RzILOpEffect *c6x_mpy32(const C6xInsn *insn, bool s1_sgn, bool s2_sgn) {
	RzILOpPure *s1 = c6x_src(&insn->ops[0]);
	RzILOpPure *s2 = c6x_src(&insn->ops[1]);
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	const C6xOperand *dst = &insn->ops[2];
	if (dst->kind == C6X_OP_REGPAIR) {
		RzILOpBitVector *w1 = s1_sgn ? SIGNED(64, s1) : UNSIGNED(64, s1);
		RzILOpBitVector *w2 = s2_sgn ? SIGNED(64, s2) : UNSIGNED(64, s2);
		return c6x_wr_pair64(dst, MUL(w1, w2));
	}
	return c6x_wr(dst, MUL(s1, s2));
}

// Clamp a 64-bit signed intermediate to the 32-bit signed range and return the
// 32-bit result -- the saturation shared by SADD/SSUB/SSHL, which compute the
// exact result in 64 bits first so the overflow the 32-bit op would hide is
// visible to the bound checks.
static RzILOpBitVector *c6x_sats32(RzILOpBitVector *x) {
	return LET("_s", x,
		ITE(SGT(VARLP("_s"), SN(64, 0x7fffffff)), U32(0x7fffffff),
			ITE(SLT(VARLP("_s"), SN(64, -0x80000000LL)), U32(0x80000000),
				UNSIGNED(32, VARLP("_s")))));
}

// Count leading zero bits of a 32-bit value (clz(0) == 32), by binary search:
// each stage tests whether the current high bits are all zero and, if so, shifts
// the value up and contributes that stage's weight. The value is threaded through
// LET bindings and the per-stage weights summed at the end.
static RzILOpPure *c6x_clz32(RzILOpPure *x) {
#define HI_ZERO(vn, sh) IS_ZERO(SHIFTR0(VARLP(vn), U32(sh)))
	return LET("_z0", x,
		LET("_z1", ITE(HI_ZERO("_z0", 16), SHIFTL0(VARLP("_z0"), U32(16)), VARLP("_z0")),
			LET("_z2", ITE(HI_ZERO("_z1", 24), SHIFTL0(VARLP("_z1"), U32(8)), VARLP("_z1")),
				LET("_z3", ITE(HI_ZERO("_z2", 28), SHIFTL0(VARLP("_z2"), U32(4)), VARLP("_z2")),
					LET("_z4", ITE(HI_ZERO("_z3", 30), SHIFTL0(VARLP("_z3"), U32(2)), VARLP("_z3")),
						LET("_z5", ITE(HI_ZERO("_z4", 31), SHIFTL0(VARLP("_z4"), U32(1)), VARLP("_z4")),
							ADD(ADD(ADD(ADD(ADD(ITE(HI_ZERO("_z0", 16), U32(16), U32(0)),
										ITE(HI_ZERO("_z1", 24), U32(8), U32(0))),
									    ITE(HI_ZERO("_z2", 28), U32(4), U32(0))),
									ITE(HI_ZERO("_z3", 30), U32(2), U32(0))),
								    ITE(HI_ZERO("_z4", 31), U32(1), U32(0))),
								ITE(HI_ZERO("_z5", 31), U32(1), U32(0)))))))));
#undef HI_ZERO
}

// Count leading zero bits of a 64-bit value (clz(0) == 64); the 64-bit analogue
// of c6x_clz32, used for the 40-bit long NORM.
static RzILOpPure *c6x_clz64(RzILOpPure *x) {
#define HI_ZERO(vn, sh) IS_ZERO(SHIFTR0(VARLP(vn), U32(sh)))
	return LET("_q0", x,
		LET("_q1", ITE(HI_ZERO("_q0", 32), SHIFTL0(VARLP("_q0"), U32(32)), VARLP("_q0")),
			LET("_q2", ITE(HI_ZERO("_q1", 48), SHIFTL0(VARLP("_q1"), U32(16)), VARLP("_q1")),
				LET("_q3", ITE(HI_ZERO("_q2", 56), SHIFTL0(VARLP("_q2"), U32(8)), VARLP("_q2")),
					LET("_q4", ITE(HI_ZERO("_q3", 60), SHIFTL0(VARLP("_q3"), U32(4)), VARLP("_q3")),
						LET("_q5", ITE(HI_ZERO("_q4", 62), SHIFTL0(VARLP("_q4"), U32(2)), VARLP("_q4")),
							LET("_q6", ITE(HI_ZERO("_q5", 63), SHIFTL0(VARLP("_q5"), U32(1)), VARLP("_q5")),
								ADD(ADD(ADD(ADD(ADD(ADD(ITE(HI_ZERO("_q0", 32), U32(32), U32(0)),
											    ITE(HI_ZERO("_q1", 48), U32(16), U32(0))),
											ITE(HI_ZERO("_q2", 56), U32(8), U32(0))),
										    ITE(HI_ZERO("_q3", 60), U32(4), U32(0))),
										ITE(HI_ZERO("_q4", 62), U32(2), U32(0))),
									    ITE(HI_ZERO("_q5", 63), U32(1), U32(0))),
									ITE(HI_ZERO("_q6", 63), U32(1), U32(0))))))))));
#undef HI_ZERO
}

// Reverse the 32 bits of a value (bit i becomes bit 31 - i), by the standard
// butterfly that swaps adjacent bits, then pairs, nibbles, bytes and halfwords.
static RzILOpPure *c6x_bitrev32(RzILOpPure *x) {
#define REVSTAGE(vn, s, m) LOGOR(SHIFTL0(LOGAND(VARLP(vn), U32(m)), U32(s)), LOGAND(SHIFTR0(VARLP(vn), U32(s)), U32(m)))
	return LET("_r0", x,
		LET("_r1", REVSTAGE("_r0", 1, 0x55555555),
			LET("_r2", REVSTAGE("_r1", 2, 0x33333333),
				LET("_r3", REVSTAGE("_r2", 4, 0x0f0f0f0f),
					LET("_r4", REVSTAGE("_r3", 8, 0x00ff00ff),
						REVSTAGE("_r4", 16, 0x0000ffff))))));
#undef REVSTAGE
}

// Per-byte population count (BITC4): each result byte holds the number of set
// bits in the matching src2 byte, via SWAR reduction stopped at the byte level.
static RzILOpPure *c6x_bitc4(RzILOpPure *x) {
	return LET("_b0", x,
		LET("_b1", SUB(VARLP("_b0"), LOGAND(SHIFTR0(VARLP("_b0"), U32(1)), U32(0x55555555))),
			LET("_b2", ADD(LOGAND(VARLP("_b1"), U32(0x33333333)), LOGAND(SHIFTR0(VARLP("_b1"), U32(2)), U32(0x33333333))),
				LOGAND(ADD(VARLP("_b2"), SHIFTR0(VARLP("_b2"), U32(4))), U32(0x0f0f0f0f)))));
}

// Deinterleave (DEAL): the even bits of src2 are packed into the lower halfword
// of the result and the odd bits into the upper, each compacted by folding the
// kept bits down (the even chain works on src2, the odd chain on src2 >> 1).
static RzILOpPure *c6x_deal(RzILOpPure *x) {
#define CMPR(vn, sh, m) LOGAND(LOGOR(VARLP(vn), SHIFTR0(VARLP(vn), U32(sh))), U32(m))
	return LET("_dx", x,
		LET("_e0", LOGAND(VARLP("_dx"), U32(0x55555555)),
			LET("_e1", CMPR("_e0", 1, 0x33333333),
				LET("_e2", CMPR("_e1", 2, 0x0f0f0f0f),
					LET("_e3", CMPR("_e2", 4, 0x00ff00ff),
						LET("_elo", CMPR("_e3", 8, 0x0000ffff),
							LET("_o0", LOGAND(SHIFTR0(VARLP("_dx"), U32(1)), U32(0x55555555)),
								LET("_o1", CMPR("_o0", 1, 0x33333333),
									LET("_o2", CMPR("_o1", 2, 0x0f0f0f0f),
										LET("_o3", CMPR("_o2", 4, 0x00ff00ff),
											LET("_ohi", CMPR("_o3", 8, 0x0000ffff),
												LOGOR(SHIFTL0(VARLP("_ohi"), U32(16)), VARLP("_elo")))))))))))));
#undef CMPR
}

// Interleave (SHFL): the lower halfword of src2 is spread into the even bit
// positions of the result and the upper halfword into the odd positions, each
// spread by folding the bits up (the high chain is then shifted left by one).
static RzILOpPure *c6x_shfl(RzILOpPure *x) {
#define SPRD(vn, sh, m) LOGAND(LOGOR(VARLP(vn), SHIFTL0(VARLP(vn), U32(sh))), U32(m))
	return LET("_sx", x,
		LET("_l0", LOGAND(VARLP("_sx"), U32(0x0000ffff)),
			LET("_l1", SPRD("_l0", 8, 0x00ff00ff),
				LET("_l2", SPRD("_l1", 4, 0x0f0f0f0f),
					LET("_l3", SPRD("_l2", 2, 0x33333333),
						LET("_llo", SPRD("_l3", 1, 0x55555555),
							LET("_h0", LOGAND(SHIFTR0(VARLP("_sx"), U32(16)), U32(0x0000ffff)),
								LET("_h1", SPRD("_h0", 8, 0x00ff00ff),
									LET("_h2", SPRD("_h1", 4, 0x0f0f0f0f),
										LET("_h3", SPRD("_h2", 2, 0x33333333),
											LET("_hhi", SPRD("_h3", 1, 0x55555555),
												LOGOR(SHIFTL0(VARLP("_hhi"), U32(1)), VARLP("_llo")))))))))))));
#undef SPRD
}

// arithmetic (ADDA*/SUBA*). The addressing syntax lists the base (src2) first,
// so ops[0] is the base and ops[1] the index; scale is 0/1/2/3.
static RzILOpEffect *c6x_addr(const C6xInsn *insn, bool sub, ut8 scale) {
	RzILOpPure *base = c6x_src(&insn->ops[0]);
	RzILOpPure *off = c6x_src(&insn->ops[1]);
	if (!base || !off) {
		rz_il_op_pure_free(base);
		rz_il_op_pure_free(off);
		return NULL;
	}
	if (scale) {
		off = SHIFTL0(off, U32(scale));
	}
	return c6x_wr(&insn->ops[2], sub ? SUB(base, off) : ADD(base, off));
}

// Build the (unconditional) effect for one instruction, or NULL if the form is
// not lifted. Predication is applied by the caller.
static RzILOpEffect *c6x_lift_core(const C6xInsn *insn, ut64 pc) {
	const char *m = insn->mnemonic;
	if (!m) {
		return NULL;
	}
	if (!strcmp(m, "nop") || !strcmp(m, "idle")) {
		return NOP();
	}
	if (!strcmp(m, "b") || !strcmp(m, "bnop") || !strcmp(m, "callp")) {
		// Control transfer. The target is either a register or a PC-relative
		// displacement off the fetch-packet-aligned address (PCE1). The five
		// delay slots are not modelled -- the sequential VM takes the branch at
		// once -- but the target is exact. Call forms (a link register in
		// ops[1]) also record the return address, the word after the branch.
		const C6xOperand *t = &insn->ops[0];
		RzILOpBitVector *tgt;
		if (t->kind == C6X_OP_PCREL) {
			tgt = U32((ut32)((pc & ~(ut64)0x1f) + t->imm));
		} else if (t->kind == C6X_OP_REG) {
			tgt = VARG(c6x_reg_name(t->side, t->num));
		} else if (t->kind == C6X_OP_CTRLREG) {
			tgt = VARG(t->name); // e.g. b irp / b nrp (return from interrupt)
		} else {
			return NULL;
		}
		if (insn->nops > 1 && insn->ops[1].kind == C6X_OP_REG) {
			return SEQ2(SETG(c6x_reg_name(insn->ops[1].side, insn->ops[1].num), U32((ut32)(pc + insn->size))), JMP(tgt));
		}
		return JMP(tgt);
	}
	if (!strcmp(m, "addkpc")) {
		// dst = PCE1 (the fetch-packet-aligned address) + displacement; a pure
		// address computation, no control transfer
		return c6x_wr(&insn->ops[1], U32((ut32)((pc & ~(ut64)0x1f) + insn->ops[0].imm)));
	}
	if (!strcmp(m, "mv")) {
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], s) : NULL;
	}
	if (!strcmp(m, "mvd")) {
		// the .M-unit move; its extra latency is timing, not data flow
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], s) : NULL;
	}
	if (!strcmp(m, "mvk")) {
		// sign-extended 16-bit move (imm already extended by the decoder)
		return c6x_wr(&insn->ops[1], S32(insn->ops[0].imm));
	}
	if (!strcmp(m, "mvkh")) {
		// replace the top 16 bits, keep the low 16
		const C6xOperand *d = &insn->ops[1];
		RzILOpPure *hi = U32(((ut64)(insn->ops[0].imm & 0xffff)) << 16);
		RzILOpPure *lo = LOGAND(VARG(c6x_reg_name(d->side, d->num)), U32(0xffff));
		return c6x_wr(d, LOGOR(lo, hi));
	}
	if (!strcmp(m, "mvc")) {
		// move between a control register (named by the decoder) and a general
		// register; a plain copy, so status-register side effects are not modelled
		const C6xOperand *s = &insn->ops[0];
		const C6xOperand *d = &insn->ops[1];
		const char *sn = s->kind == C6X_OP_CTRLREG ? s->name : (s->kind == C6X_OP_REG ? c6x_reg_name(s->side, s->num) : NULL);
		const char *dn = d->kind == C6X_OP_CTRLREG ? d->name : (d->kind == C6X_OP_REG ? c6x_reg_name(d->side, d->num) : NULL);
		return sn && dn ? SETG(dn, VARG(sn)) : NULL;
	}
	if (!strcmp(m, "add") || !strcmp(m, "addu")) {
		return c6x_alu3(insn, rz_il_op_new_add);
	}
	if (!strcmp(m, "sub") || !strcmp(m, "subu")) {
		return c6x_alu3(insn, rz_il_op_new_sub);
	}
	if (!strcmp(m, "and")) {
		return c6x_alu3(insn, rz_il_op_new_log_and);
	}
	if (!strcmp(m, "andn")) {
		// dst = src2 & ~src1 (src1 is the complemented operand)
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], LOGAND(s2, LOGNOT(s1)));
	}
	if (!strcmp(m, "or")) {
		return c6x_alu3(insn, rz_il_op_new_log_or);
	}
	if (!strcmp(m, "xor")) {
		return c6x_alu3(insn, rz_il_op_new_log_xor);
	}
	if (!strcmp(m, "cmpeq")) {
		return c6x_cmp(insn, rz_il_op_new_eq);
	}
	if (!strcmp(m, "cmpgt") || !strcmp(m, "cmpgtu")) {
		bool uns = m[5] == 'u';
		if (insn->ops[1].kind == C6X_OP_REGPAIR) {
			// long form: a 32-bit src1 compared against a 40-bit long src2
			RzILOpPure *s1 = c6x_src(&insn->ops[0]);
			if (!s1) {
				return NULL;
			}
			RzILOpBool *cmp = uns
				? UGT(UNSIGNED(64, s1), LOGAND(c6x_pair64(&insn->ops[1]), SN(64, 0xffffffffffLL)))
				: SGT(SIGNED(64, s1), c6x_long40(&insn->ops[1]));
			return c6x_wr(&insn->ops[2], ITE(cmp, U32(1), U32(0)));
		}
		return c6x_cmp(insn, uns ? rz_il_op_new_ugt : rz_il_op_new_sgt);
	}
	if (!strcmp(m, "cmplt")) {
		return c6x_cmp(insn, rz_il_op_new_slt);
	}
	if (!strcmp(m, "cmpltu")) {
		return c6x_cmp(insn, rz_il_op_new_ult);
	}
	if (!strcmp(m, "cmpeq2")) {
		return c6x_cmp_packed(insn, 2, rz_il_op_new_eq);
	}
	if (!strcmp(m, "cmpgt2")) {
		return c6x_cmp_packed(insn, 2, rz_il_op_new_sgt);
	}
	if (!strcmp(m, "cmpeq4")) {
		return c6x_cmp_packed(insn, 4, rz_il_op_new_eq);
	}
	if (!strcmp(m, "cmpgtu4")) {
		return c6x_cmp_packed(insn, 4, rz_il_op_new_ugt);
	}
	if (!strcmp(m, "zero")) {
		// clear a register or a register pair
		const C6xOperand *d = &insn->ops[0];
		if (d->kind == C6X_OP_REG) {
			return SETG(c6x_reg_name(d->side, d->num), U32(0));
		}
		if (d->kind == C6X_OP_REGPAIR) {
			return SEQ2(SETG(c6x_reg_name(d->side, d->num), U32(0)),
				SETG(c6x_reg_name(d->side, d->num + 1), U32(0)));
		}
		return NULL;
	}
	if (!strcmp(m, "neg")) {
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], NEG(s)) : NULL;
	}
	if (!strcmp(m, "not")) {
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], LOGNOT(s)) : NULL;
	}
	if (!strcmp(m, "abs")) {
		// dst = |src|, saturating INT_MIN (0x80000000) to INT_MAX (0x7fffffff).
		// The 40-bit long form saturates -2^39 to 2^39-1 over a register pair.
		if (insn->ops[0].kind == C6X_OP_REGPAIR) {
			RzILOpBitVector *v = c6x_long40(&insn->ops[0]);
			if (!v) {
				return NULL;
			}
			return c6x_wr_pair64(&insn->ops[1],
				LET("_a", v,
					ITE(SGE(VARLP("_a"), SN(64, 0)), VARLP("_a"),
						ITE(EQ(VARLP("_a"), SN(64, -0x8000000000LL)), SN(64, 0x7fffffffffLL), NEG(VARLP("_a"))))));
		}
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], LET("_a", s, ITE(SGE(VARLP("_a"), S32(0)), VARLP("_a"), ITE(EQ(VARLP("_a"), U32(0x80000000)), U32(0x7fffffff), NEG(VARLP("_a"))))));
	}
	if (!strcmp(m, "sat")) {
		// saturate a 40-bit long in a register pair to a signed 32-bit int
		RzILOpBitVector *v = c6x_long40(&insn->ops[0]);
		if (!v) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], c6x_sats32(v));
	}
	if (!strcmp(m, "abssp")) {
		// single-precision float abs: clear the sign bit
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], LOGAND(s, U32(0x7fffffff)));
	}
	if (!strcmp(m, "absdp")) {
		// double-precision float abs: clear the sign bit of the 64-bit pair
		RzILOpBitVector *s = c6x_pair64(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr_pair64(&insn->ops[1], LOGAND(s, SN(64, 0x7fffffffffffffffLL)));
	}
	if (!strcmp(m, "abs2")) {
		// per-halfword absolute value with 0x8000 -> 0x7fff saturation
		RzILOpPure *slo = c6x_src(&insn->ops[0]);
		RzILOpPure *shi = c6x_src(&insn->ops[0]);
		if (!slo || !shi) {
			rz_il_op_pure_free(slo);
			rz_il_op_pure_free(shi);
			return NULL;
		}
		RzILOpBitVector *lo = c6x_abs16(UNSIGNED(16, slo));
		RzILOpBitVector *hi = c6x_abs16(UNSIGNED(16, SHIFTR0(shi, U32(16))));
		return c6x_wr(&insn->ops[1], APPEND(hi, lo));
	}
	if (!strcmp(m, "extu") || !strcmp(m, "ext")) {
		// field extract: dst = (src << csta) >> cstb, right shift logical for
		// extu and arithmetic (sign-extending) for ext
		if (insn->ops[1].kind != C6X_OP_IMM || insn->ops[2].kind != C6X_OP_IMM) {
			return NULL;
		}
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		RzILOpPure *shl = SHIFTL0(s, U32((ut32)insn->ops[1].imm));
		RzILOpPure *v = m[3] == 'u'
			? SHIFTR0(shl, U32((ut32)insn->ops[2].imm))
			: SHIFTRA(shl, U32((ut32)insn->ops[2].imm));
		return c6x_wr(&insn->ops[3], v);
	}
	if (!strcmp(m, "set") || !strcmp(m, "clr")) {
		// bit field set/clear: dst = src2 set/cleared over bits [csta, cstb].
		// Only the constant form is modeled; the register form takes the field
		// bounds from src1 at run time.
		if (insn->ops[1].kind != C6X_OP_IMM || insn->ops[2].kind != C6X_OP_IMM) {
			return NULL;
		}
		ut32 csta = (ut32)insn->ops[1].imm & 0x1f;
		ut32 cstb = (ut32)insn->ops[2].imm & 0x1f;
		if (cstb < csta) {
			return NULL;
		}
		ut32 width = cstb - csta + 1;
		ut32 mask = width >= 32 ? 0xffffffff : (((ut32)1 << width) - 1) << csta;
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = m[0] == 's' ? LOGOR(s, U32(mask)) : LOGAND(s, U32(~mask));
		return c6x_wr(&insn->ops[3], v);
	}
	if (!strcmp(m, "lmbd")) {
		// leftmost bit detection: src1[0] selects whether to find the leftmost 1
		// (count leading zeros of src2) or the leftmost 0 (count leading zeros of
		// its complement); dst is that count.
		RzILOpPure *src1 = c6x_src(&insn->ops[0]);
		RzILOpPure *src2 = c6x_src(&insn->ops[1]);
		if (!src1 || !src2) {
			rz_il_op_pure_free(src1);
			rz_il_op_pure_free(src2);
			return NULL;
		}
		RzILOpPure *arg = LET("_lm", src2,
			ITE(IS_ZERO(LOGAND(src1, U32(1))), LOGNOT(VARLP("_lm")), VARLP("_lm")));
		return c6x_wr(&insn->ops[2], c6x_clz32(arg));
	}
	if (!strcmp(m, "norm")) {
		// redundant sign bits: clz(src2 ^ (src2 >>a 31)) - 1. XOR by the sign turns
		// the leading run of sign bits into leading zeros; subtract the sign bit.
		// The 40-bit long form uses the sign-extended value and a 64-bit count.
		if (insn->ops[0].kind == C6X_OP_REGPAIR) {
			RzILOpBitVector *v = c6x_long40(&insn->ops[0]);
			if (!v) {
				return NULL;
			}
			RzILOpPure *arg = LET("_nl", v, LOGXOR(VARLP("_nl"), SHIFTRA(VARLP("_nl"), U32(63))));
			return c6x_wr(&insn->ops[1], SUB(c6x_clz64(arg), U32(25)));
		}
		RzILOpPure *src = c6x_src(&insn->ops[0]);
		if (!src) {
			return NULL;
		}
		RzILOpPure *arg = LET("_nm", src, LOGXOR(VARLP("_nm"), SHIFTRA(VARLP("_nm"), U32(31))));
		return c6x_wr(&insn->ops[1], SUB(c6x_clz32(arg), U32(1)));
	}
	if (!strcmp(m, "deal")) {
		// dst = src2 deinterleaved: even bits to the low halfword, odd to the high
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], c6x_deal(s));
	}
	if (!strcmp(m, "shfl")) {
		// dst = src2 interleaved: low halfword to even bits, high to odd
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], c6x_shfl(s));
	}
	if (!strcmp(m, "bitr")) {
		// dst = src2 with its 32 bits reversed
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], c6x_bitrev32(s));
	}
	if (!strcmp(m, "bitc4")) {
		// dst = per-byte population count of src2
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1], c6x_bitc4(s));
	}
	if (!strcmp(m, "xpnd2")) {
		// expand src2[1:0] into two halfword masks: bit 0 fills the lower
		// halfword, bit 1 the upper, each 0x0000 or 0xffff
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = LET("_x", s,
			LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(1)), U32(1)), U32(0xffff)), U32(16)),
				MUL(LOGAND(VARLP("_x"), U32(1)), U32(0xffff))));
		return c6x_wr(&insn->ops[1], v);
	}
	if (!strcmp(m, "xpnd4")) {
		// expand src2[3:0] into four byte masks, each 0x00 or 0xff
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = LET("_x",
			s,
			LOGOR(LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(3)), U32(1)), U32(0xff)), U32(24)),
				      SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(2)), U32(1)), U32(0xff)), U32(16))),
				LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(1)), U32(1)), U32(0xff)), U32(8)),
					MUL(LOGAND(VARLP("_x"), U32(1)), U32(0xff)))));
		return c6x_wr(&insn->ops[1], v);
	}
	if (!strcmp(m, "subc")) {
		// subtract-conditional divide step: d = src1 - src2;
		// dst = d >= 0 ? (d << 1) | 1 : src1 << 1
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *v = LET("_s1", s1,
			LET("_df", SUB(VARLP("_s1"), s2),
				ITE(SGE(VARLP("_df"), S32(0)),
					LOGOR(SHIFTL0(VARLP("_df"), U32(1)), U32(1)),
					SHIFTL0(VARLP("_s1"), U32(1)))));
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "rpack2")) {
		// shift src1 and src2 left by 1 with saturation, then pack their 16 MSBs
		// into the upper and lower halfword of dst
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *hi = SHIFTR0(c6x_sats32(SHIFTL0(SIGNED(64, s1), U32(1))), U32(16));
		RzILOpPure *lo = SHIFTR0(c6x_sats32(SHIFTL0(SIGNED(64, s2), U32(1))), U32(16));
		return c6x_wr(&insn->ops[2], LOGOR(SHIFTL0(LOGAND(hi, U32(0xffff)), U32(16)), LOGAND(lo, U32(0xffff))));
	}
	if (!strcmp(m, "avg2")) {
		// signed packed 16-bit rounding average: (a + b + 1) >>a 1 per halfword
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(SHIFTL0(LOGAND(SHIFTRA(ADD(ADD(c6x_high16s(VARLP("_a")), c6x_high16s(VARLP("_b"))), U32(1)), U32(1)), U32(0xffff)), U32(16)),
					LOGAND(SHIFTRA(ADD(ADD(c6x_low16s(VARLP("_a")), c6x_low16s(VARLP("_b"))), U32(1)), U32(1)), U32(0xffff)))));
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "avgu4")) {
		// unsigned packed 8-bit rounding average: (a + b + 1) >> 1 per byte
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define AVGU4_BYTE(sh) \
	SHIFTL0(LOGAND(SHIFTR0(ADD(ADD(LOGAND(SHIFTR0(VARLP("_a"), U32(sh)), U32(0xff)), LOGAND(SHIFTR0(VARLP("_b"), U32(sh)), U32(0xff))), U32(1)), U32(1)), U32(0xff)), U32(sh))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(LOGOR(AVGU4_BYTE(24), AVGU4_BYTE(16)), LOGOR(AVGU4_BYTE(8), AVGU4_BYTE(0)))));
#undef AVGU4_BYTE
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "saddu4")) {
		// packed 8-bit unsigned saturating add: min(a + b, 255) per byte
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define SADDU4_SUM(sh)  ADD(LOGAND(SHIFTR0(VARLP("_a"), U32(sh)), U32(0xff)), LOGAND(SHIFTR0(VARLP("_b"), U32(sh)), U32(0xff)))
#define SADDU4_BYTE(sh) SHIFTL0(ITE(UGT(SADDU4_SUM(sh), U32(0xff)), U32(0xff), SADDU4_SUM(sh)), U32(sh))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(LOGOR(SADDU4_BYTE(24), SADDU4_BYTE(16)), LOGOR(SADDU4_BYTE(8), SADDU4_BYTE(0)))));
#undef SADDU4_BYTE
#undef SADDU4_SUM
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "saddus2")) {
		// per halfword: clamp(u16(src1) + s16(src2), 0, 65535); src1 unsigned,
		// src2 signed
		RzILOpPure *a_lo = c6x_src(&insn->ops[0]);
		RzILOpPure *b_lo = c6x_src(&insn->ops[1]);
		RzILOpPure *a_hi = c6x_src(&insn->ops[0]);
		RzILOpPure *b_hi = c6x_src(&insn->ops[1]);
		if (!a_lo || !b_lo || !a_hi || !b_hi) {
			rz_il_op_pure_free(a_lo);
			rz_il_op_pure_free(b_lo);
			rz_il_op_pure_free(a_hi);
			rz_il_op_pure_free(b_hi);
			return NULL;
		}
		RzILOpPure *lo = LET("_lo", ADD(LOGAND(a_lo, U32(0xffff)), c6x_low16s(b_lo)),
			ITE(SLT(VARLP("_lo"), S32(0)), U32(0), ITE(SGT(VARLP("_lo"), S32(0xffff)), U32(0xffff), VARLP("_lo"))));
		RzILOpPure *hi = LET("_hi", ADD(LOGAND(SHIFTR0(a_hi, U32(16)), U32(0xffff)), c6x_high16s(b_hi)),
			ITE(SLT(VARLP("_hi"), S32(0)), U32(0), ITE(SGT(VARLP("_hi"), S32(0xffff)), U32(0xffff), VARLP("_hi"))));
		return c6x_wr(&insn->ops[2], LOGOR(SHIFTL0(hi, U32(16)), lo));
	}
	if (!strcmp(m, "sshvl") || !strcmp(m, "sshvr")) {
		// variable shift of src2 by src1, clamped to [-31, 31]. SSHVL shifts left
		// for a positive count (saturating) and arithmetic-right for a negative
		// one; SSHVR is the mirror. src2 is ops[0], the count src1 is ops[1].
		bool left = m[4] == 'l';
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		RzILOpPure *s = c6x_src(&insn->ops[1]);
		if (!v || !s) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(s);
			return NULL;
		}
		// n >= 0 and n < 0 halves; the shift-left half saturates to 32 bits
		RzILOpPure *pos = left
			? c6x_sats32(SHIFTL0(SIGNED(64, VARLP("_v")), VARLP("_n")))
			: SHIFTRA(VARLP("_v"), VARLP("_n"));
		RzILOpPure *neg = left
			? SHIFTRA(VARLP("_v"), NEG(VARLP("_n")))
			: c6x_sats32(SHIFTL0(SIGNED(64, VARLP("_v")), NEG(VARLP("_n"))));
		return c6x_wr(&insn->ops[2],
			LET("_v", v,
				LET("_sc", s,
					LET("_n", ITE(SGT(VARLP("_sc"), S32(31)), S32(31), ITE(SLT(VARLP("_sc"), S32(-31)), S32(-31), VARLP("_sc"))),
						ITE(SGE(VARLP("_n"), S32(0)), pos, neg)))));
	}
	if (!strcmp(m, "addk")) {
		// dst += sign-extended 16-bit constant (dst is also src)
		const C6xOperand *d = &insn->ops[1];
		return c6x_wr(d, ADD(VARG(c6x_reg_name(d->side, d->num)), S32(insn->ops[0].imm)));
	}
	if (!strcmp(m, "shl")) {
		if (insn->ops[0].kind == C6X_OP_REGPAIR) {
			// 40-bit long shifted left by src1, truncated back to 40 bits
			RzILOpBitVector *v = c6x_long40(&insn->ops[0]);
			RzILOpPure *n = c6x_src(&insn->ops[1]);
			if (!v || !n) {
				rz_il_op_pure_free(v);
				rz_il_op_pure_free(n);
				return NULL;
			}
			return c6x_wr_pair64(&insn->ops[2], LOGAND(SHIFTL0(v, n), SN(64, 0xffffffffffLL)));
		}
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		RzILOpPure *n = c6x_src(&insn->ops[1]);
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], SHIFTL0(v, n));
	}
	if (!strcmp(m, "shr") || !strcmp(m, "shru")) {
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		RzILOpPure *n = c6x_src(&insn->ops[1]);
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		// shr is arithmetic (sign-propagating); shru is logical
		return c6x_wr(&insn->ops[2], m[3] == 'u' ? SHIFTR0(v, n) : SHIFTRA(v, n));
	}
	// Byte/halfword/word/doubleword address arithmetic: the index is scaled by
	// the access width before it is added to (ADDA*) or subtracted from (SUBA*)
	// the base.
	if (!strcmp(m, "addab")) {
		return c6x_addr(insn, false, 0);
	}
	if (!strcmp(m, "addah")) {
		return c6x_addr(insn, false, 1);
	}
	if (!strcmp(m, "addaw")) {
		return c6x_addr(insn, false, 2);
	}
	if (!strcmp(m, "addad")) {
		return c6x_addr(insn, false, 3);
	}
	if (!strcmp(m, "subab")) {
		return c6x_addr(insn, true, 0);
	}
	if (!strcmp(m, "subah")) {
		return c6x_addr(insn, true, 1);
	}
	if (!strcmp(m, "subaw")) {
		return c6x_addr(insn, true, 2);
	}
	if (!strcmp(m, "sadd") || !strcmp(m, "ssub")) {
		// signed add/subtract saturating to the 32-bit range (src1 - src2 for
		// ssub, matching the SUB operand order)
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpBitVector *w1 = SIGNED(64, s1);
		RzILOpBitVector *w2 = SIGNED(64, s2);
		return c6x_wr(&insn->ops[2], c6x_sats32(m[1] == 's' ? SUB(w1, w2) : ADD(w1, w2)));
	}
	if (!strcmp(m, "sshl")) {
		// dst = saturate32(src2 << (src1 & 0x1f)); the shift is done in 64 bits
		// so an overflow past bit 31 saturates instead of being dropped
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		RzILOpPure *n = c6x_src(&insn->ops[1]);
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], c6x_sats32(SHIFTL0(SIGNED(64, v), LOGAND(n, U32(0x1f)))));
	}
	if (!strcmp(m, "rotl")) {
		// rotate src2 left by src1[4:0]: (v << n) | (v >>u (32 - n)); this .M-unit
		// form decodes src1 (the count) into ops[0] and src2 (the value) into ops[1]
		RzILOpPure *v = c6x_src(&insn->ops[1]);
		RzILOpPure *cnt = c6x_src(&insn->ops[0]);
		if (!v || !cnt) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(cnt);
			return NULL;
		}
		return c6x_wr(&insn->ops[2],
			LET("_rv", v, LET("_rn", LOGAND(cnt, U32(0x1f)), LOGOR(SHIFTL0(VARLP("_rv"), VARLP("_rn")), SHIFTR0(VARLP("_rv"), SUB(U32(32), VARLP("_rn")))))));
	}
	if (!strcmp(m, "shlmb") || !strcmp(m, "shrmb")) {
		// shift src2 by one byte and merge the adjacent byte of src1 into the
		// vacated end: left brings src1's msb into the lsb, right the reverse
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpBitVector *v = m[2] == 'l'
			? LOGOR(SHIFTL0(s2, U32(8)), LOGAND(SHIFTR0(s1, U32(24)), U32(0xff)))
			: LOGOR(SHIFTR0(s2, U32(8)), SHIFTL0(LOGAND(s1, U32(0xff)), U32(24)));
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "shr2") || !strcmp(m, "shru2")) {
		// per-halfword shift right by src1[3:0], arithmetic for shr2 and logical
		// (zero-extended) for shru2, lanes independent
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		RzILOpPure *cnt = c6x_src(&insn->ops[1]);
		if (!v || !cnt) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(cnt);
			return NULL;
		}
		bool ar = m[3] != 'u';
		return c6x_wr(&insn->ops[2],
			LET("_sv", v, LET("_sn", UNSIGNED(16, LOGAND(cnt, U32(0xf))), APPEND(ar ? SHIFTRA(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")), ar ? SHIFTRA(UNSIGNED(16, VARLP("_sv")), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, VARLP("_sv")), VARLP("_sn"))))));
	}
	if (!strcmp(m, "swap4")) {
		// exchange the two bytes within each halfword
		RzILOpPure *v = c6x_src(&insn->ops[0]);
		if (!v) {
			return NULL;
		}
		return c6x_wr(&insn->ops[1],
			LET("_w4", v,
				LOGOR(SHIFTL0(LOGAND(VARLP("_w4"), U32(0x00ff00ff)), U32(8)),
					LOGAND(SHIFTR0(VARLP("_w4"), U32(8)), U32(0x00ff00ff)))));
	}
	if (!strcmp(m, "packl4") || !strcmp(m, "packh4")) {
		// gather one byte from each of the four halfwords of src1:src2 -- the low
		// byte of each for packl4, the high byte for packh4 -- src1 to the top
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		ut32 sh = m[4] == 'h' ? 8 : 0; // byte offset within each halfword
		return c6x_wr(&insn->ops[2],
			LET("_q1", s1, LET("_q2", s2, LOGOR(LOGOR(SHIFTL0(LOGAND(SHIFTR0(VARLP("_q1"), U32(16 + sh)), U32(0xff)), U32(24)), SHIFTL0(LOGAND(SHIFTR0(VARLP("_q1"), U32(sh)), U32(0xff)), U32(16))), LOGOR(SHIFTL0(LOGAND(SHIFTR0(VARLP("_q2"), U32(16 + sh)), U32(0xff)), U32(8)), LOGAND(SHIFTR0(VARLP("_q2"), U32(sh)), U32(0xff)))))));
	}
	// 16x16 multiplies, named by (src1 half, src1 sign)(src2 half, src2 sign):
	// H/L pick the high/low halfword, and the S/U suffixes pick signed/unsigned.
	if (!strcmp(m, "mpy")) {
		return c6x_mpy16(insn, false, true, false, true);
	}
	if (!strcmp(m, "mpyh")) {
		return c6x_mpy16(insn, true, true, true, true);
	}
	if (!strcmp(m, "mpyhl")) {
		return c6x_mpy16(insn, true, true, false, true);
	}
	if (!strcmp(m, "mpylh")) {
		return c6x_mpy16(insn, false, true, true, true);
	}
	if (!strcmp(m, "mpyu")) {
		return c6x_mpy16(insn, false, false, false, false);
	}
	if (!strcmp(m, "mpyus")) {
		return c6x_mpy16(insn, false, false, false, true);
	}
	if (!strcmp(m, "mpysu")) {
		return c6x_mpy16(insn, false, true, false, false);
	}
	if (!strcmp(m, "mpyhu")) {
		return c6x_mpy16(insn, true, false, true, false);
	}
	if (!strcmp(m, "mpyhus")) {
		return c6x_mpy16(insn, true, false, true, true);
	}
	if (!strcmp(m, "mpyhsu")) {
		return c6x_mpy16(insn, true, true, true, false);
	}
	if (!strcmp(m, "mpylhu")) {
		return c6x_mpy16(insn, false, false, true, false);
	}
	if (!strcmp(m, "mpyhlu")) {
		return c6x_mpy16(insn, true, false, false, false);
	}
	if (!strcmp(m, "mpyluhs")) {
		return c6x_mpy16(insn, false, false, true, true);
	}
	if (!strcmp(m, "mpyhuls")) {
		return c6x_mpy16(insn, true, false, false, true);
	}
	if (!strcmp(m, "mpylshu")) {
		return c6x_mpy16(insn, false, true, true, false);
	}
	if (!strcmp(m, "mpyhslu")) {
		return c6x_mpy16(insn, true, true, false, false);
	}
	// SMPY family: signed 16x16, doubled and saturated to 32-bit signed.
	if (!strcmp(m, "smpy")) {
		return c6x_smpy(insn, false, false);
	}
	if (!strcmp(m, "smpyh")) {
		return c6x_smpy(insn, true, true);
	}
	if (!strcmp(m, "smpyhl")) {
		return c6x_smpy(insn, true, false);
	}
	if (!strcmp(m, "smpylh")) {
		return c6x_smpy(insn, false, true);
	}
	// 32x32 multiplies: MPYI/MPY32 keep the low 32 (single dst) or full 64 (pair
	// dst); MPYID is the 64-bit signed form; MPY32U/SU/US set the source signs.
	if (!strcmp(m, "mpyi") || !strcmp(m, "mpyid") || !strcmp(m, "mpy32")) {
		return c6x_mpy32(insn, true, true);
	}
	if (!strcmp(m, "mpy32u")) {
		return c6x_mpy32(insn, false, false);
	}
	if (!strcmp(m, "mpy32su")) {
		return c6x_mpy32(insn, true, false);
	}
	if (!strcmp(m, "mpy32us")) {
		return c6x_mpy32(insn, false, true);
	}
	if (!strcmp(m, "add2")) {
		return c6x_packed(insn, 2, false);
	}
	if (!strcmp(m, "sub2")) {
		return c6x_packed(insn, 2, true);
	}
	if (!strcmp(m, "add4")) {
		return c6x_packed(insn, 4, false);
	}
	if (!strcmp(m, "sub4")) {
		return c6x_packed(insn, 4, true);
	}
	if (!strcmp(m, "pack2")) {
		return c6x_pack(insn, false, false); // low(src1):low(src2)
	}
	if (!strcmp(m, "packh2")) {
		return c6x_pack(insn, true, true); // high(src1):high(src2)
	}
	if (!strcmp(m, "packlh2")) {
		return c6x_pack(insn, false, true); // low(src1):high(src2)
	}
	if (!strcmp(m, "packhl2")) {
		return c6x_pack(insn, true, false); // high(src1):low(src2)
	}
	if (!strcmp(m, "unpklu4")) {
		return c6x_unpku4(insn, false);
	}
	if (!strcmp(m, "unpkhu4")) {
		return c6x_unpku4(insn, true);
	}
	if (!strcmp(m, "sadd2")) {
		return c6x_sat_packed(insn, 2, false);
	}
	if (!strcmp(m, "ssub2")) {
		return c6x_sat_packed(insn, 2, true);
	}
	if (!strcmp(m, "spack2")) {
		// saturate two 32-bit signed sources to signed 16 bits and pack
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], APPEND(c6x_sat_s(s1, 16), c6x_sat_s(s2, 16)));
	}
	if (!strcmp(m, "mpy2") || !strcmp(m, "smpy2")) {
		// two signed 16x16 products into a register pair: even reg = lsb*lsb,
		// odd reg = msb*msb. SMPY2 additionally shifts each product left by 1
		// with saturation.
		bool sat = m[0] == 's';
		RzILOpPure *a_lo = c6x_src(&insn->ops[0]);
		RzILOpPure *b_lo = c6x_src(&insn->ops[1]);
		RzILOpPure *a_hi = c6x_src(&insn->ops[0]);
		RzILOpPure *b_hi = c6x_src(&insn->ops[1]);
		if (!a_lo || !b_lo || !a_hi || !b_hi) {
			rz_il_op_pure_free(a_lo);
			rz_il_op_pure_free(b_lo);
			rz_il_op_pure_free(a_hi);
			rz_il_op_pure_free(b_hi);
			return NULL;
		}
		RzILOpBitVector *lo = MUL(c6x_low16s(a_lo), c6x_low16s(b_lo));
		RzILOpBitVector *hi = MUL(c6x_high16s(a_hi), c6x_high16s(b_hi));
		if (sat) {
			lo = c6x_sats32(SHIFTL0(SIGNED(64, lo), U32(1)));
			hi = c6x_sats32(SHIFTL0(SIGNED(64, hi), U32(1)));
		}
		return c6x_wr_pair64(&insn->ops[2], APPEND(hi, lo));
	}
	if (!strcmp(m, "mpyhi") || !strcmp(m, "mpyli")) {
		// signed 16x32 multiply into a register pair (the 48-bit product,
		// sign-extended): MPYHI uses src1's msb16, MPYLI its lsb16
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *h = m[3] == 'h' ? c6x_high16s(s1) : c6x_low16s(s1);
		return c6x_wr_pair64(&insn->ops[2], MUL(SIGNED(64, h), SIGNED(64, s2)));
	}
	if (!strcmp(m, "mpyhir") || !strcmp(m, "mpylir")) {
		// signed 16x32 multiply, rounded: (h16(src1) * src2 + 0x4000) >> 15
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *h = m[3] == 'h' ? c6x_high16s(s1) : c6x_low16s(s1);
		RzILOpBitVector *prod = ADD(MUL(SIGNED(64, h), SIGNED(64, s2)), SN(64, 0x4000));
		return c6x_wr(&insn->ops[2], UNSIGNED(32, SHIFTRA(prod, U32(15))));
	}
	if (!strcmp(m, "spacku4")) {
		// saturate four signed 16-bit values to unsigned bytes and pack them:
		// {satu8(src1_h), satu8(src1_l), satu8(src2_h), satu8(src2_l)}
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define CLAMP8(vn) ITE(SLT(VARLP(vn), S32(0)), U32(0), ITE(SGT(VARLP(vn), S32(0xff)), U32(0xff), VARLP(vn)))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LET("_h3", c6x_high16s(VARLP("_a")),
					LET("_h2", c6x_low16s(VARLP("_a")),
						LET("_h1", c6x_high16s(VARLP("_b")),
							LET("_h0", c6x_low16s(VARLP("_b")),
								LOGOR(LOGOR(SHIFTL0(CLAMP8("_h3"), U32(24)), SHIFTL0(CLAMP8("_h2"), U32(16))),
									LOGOR(SHIFTL0(CLAMP8("_h1"), U32(8)), CLAMP8("_h0")))))))));
#undef CLAMP8
		return c6x_wr(&insn->ops[2], v);
	}
	if (!strcmp(m, "dotp2") || !strcmp(m, "dotpn2")) {
		// DOTP2: lo*lo + hi*hi; DOTPN2: hi*hi - lo*lo (signed 16x16 products)
		bool neg = m[4] == 'n';
		RzILOpPure *s1lo = c6x_src(&insn->ops[0]);
		RzILOpPure *s2lo = c6x_src(&insn->ops[1]);
		RzILOpPure *s1hi = c6x_src(&insn->ops[0]);
		RzILOpPure *s2hi = c6x_src(&insn->ops[1]);
		if (!s1lo || !s2lo || !s1hi || !s2hi) {
			rz_il_op_pure_free(s1lo);
			rz_il_op_pure_free(s2lo);
			rz_il_op_pure_free(s1hi);
			rz_il_op_pure_free(s2hi);
			return NULL;
		}
		RzILOpBitVector *lo = MUL(c6x_low16s(s1lo), c6x_low16s(s2lo));
		RzILOpBitVector *hi = MUL(c6x_high16s(s1hi), c6x_high16s(s2hi));
		return c6x_wr(&insn->ops[2], neg ? SUB(hi, lo) : ADD(lo, hi));
	}
	if (!strcmp(m, "dotpu4")) {
		return c6x_dotp4(insn, false); // unsigned x unsigned bytes
	}
	if (!strcmp(m, "dotpsu4")) {
		return c6x_dotp4(insn, true); // signed src1 x unsigned src2 bytes
	}
	if (!strcmp(m, "addsp")) {
		return c6x_fsp(insn, rz_il_op_new_fadd);
	}
	if (!strcmp(m, "subsp")) {
		return c6x_fsp(insn, rz_il_op_new_fsub);
	}
	if (!strcmp(m, "mpysp")) {
		return c6x_fsp(insn, rz_il_op_new_fmul);
	}
	if (!strcmp(m, "intsp")) {
		// signed 32-bit integer -> single-precision float
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	if (!strcmp(m, "spint")) {
		// single-precision float -> signed 32-bit integer, round to nearest even
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], F2SINT(32, RZ_FLOAT_RMODE_RNE, FLOATV32(s))) : NULL;
	}
	if (!strcmp(m, "sptrunc")) {
		// single-precision float -> signed 32-bit integer, truncating (round to zero)
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], F2SINT(32, RZ_FLOAT_RMODE_RTZ, FLOATV32(s))) : NULL;
	}
	if (!strcmp(m, "cmpeqsp")) {
		// single-precision float equality -> 1/0
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], ITE(FEQ(FLOATV32(a), FLOATV32(b)), U32(1), U32(0)));
	}
	if (!strcmp(m, "cmpgtsp") || !strcmp(m, "cmpltsp")) {
		// single-precision ordered compare -> 1/0. FORDER is an ordered less-than,
		// so GT swaps the operands.
		bool gt = m[3] == 'g';
		RzILOpPure *a = c6x_src(&insn->ops[0]);
		RzILOpPure *b = c6x_src(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBool *cmp = gt ? FORDER(FLOATV32(b), FLOATV32(a)) : FORDER(FLOATV32(a), FLOATV32(b));
		return c6x_wr(&insn->ops[2], ITE(cmp, U32(1), U32(0)));
	}
	if (!strcmp(m, "cmpeqdp")) {
		// double-precision float equality over register pairs -> 1/0
		RzILOpBitVector *a = c6x_pair64(&insn->ops[0]);
		RzILOpBitVector *b = c6x_pair64(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr(&insn->ops[2], ITE(FEQ(FLOATV64(a), FLOATV64(b)), U32(1), U32(0)));
	}
	if (!strcmp(m, "cmpgtdp") || !strcmp(m, "cmpltdp")) {
		// double-precision ordered compare over register pairs -> 1/0
		bool gt = m[3] == 'g';
		RzILOpBitVector *a = c6x_pair64(&insn->ops[0]);
		RzILOpBitVector *b = c6x_pair64(&insn->ops[1]);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBool *cmp = gt ? FORDER(FLOATV64(b), FLOATV64(a)) : FORDER(FLOATV64(a), FLOATV64(b));
		return c6x_wr(&insn->ops[2], ITE(cmp, U32(1), U32(0)));
	}
	if (!strcmp(m, "mpysp2dp")) {
		// two single-precision sources widened to double and multiplied into a pair
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpPure *s2 = c6x_src(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpFloat *a = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s1));
		RzILOpFloat *b = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s2));
		return c6x_wr_pair64(&insn->ops[2], F2BV(rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, a, b)));
	}
	if (!strcmp(m, "mpyspdp")) {
		// single-precision src1 widened to double, multiplied by double src2
		RzILOpPure *s1 = c6x_src(&insn->ops[0]);
		RzILOpBitVector *s2 = c6x_pair64(&insn->ops[1]);
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpFloat *a = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s1));
		return c6x_wr_pair64(&insn->ops[2], F2BV(rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, a, FLOATV64(s2))));
	}
	if (!strcmp(m, "adddp")) {
		return c6x_fdp(insn, rz_il_op_new_fadd);
	}
	if (!strcmp(m, "subdp")) {
		return c6x_fdp(insn, rz_il_op_new_fsub);
	}
	if (!strcmp(m, "mpydp")) {
		return c6x_fdp(insn, rz_il_op_new_fmul);
	}
	if (!strcmp(m, "intdp")) {
		// signed 32-bit integer -> double-precision float (into a pair)
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr_pair64(&insn->ops[1], F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	if (!strcmp(m, "spdp")) {
		// single-precision -> double-precision (into a pair)
		RzILOpPure *s = c6x_src(&insn->ops[0]);
		return s ? c6x_wr_pair64(&insn->ops[1], F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s)))) : NULL;
	}
	if (!strcmp(m, "dpint") || !strcmp(m, "dptrunc")) {
		// double-precision float (pair src2) -> signed 32-bit integer. DPINT
		// rounds to nearest even, DPTRUNC rounds toward zero.
		RzILOpBitVector *s = c6x_pair64(&insn->ops[0]);
		if (!s) {
			return NULL;
		}
		RzFloatRMode rmode = m[2] == 'i' ? RZ_FLOAT_RMODE_RNE : RZ_FLOAT_RMODE_RTZ;
		return c6x_wr(&insn->ops[1], F2SINT(32, rmode, FLOATV64(s)));
	}
	if (!strcmp(m, "dpsp")) {
		// double-precision (pair src2) -> single-precision
		RzILOpBitVector *s = c6x_pair64(&insn->ops[0]);
		return s ? c6x_wr(&insn->ops[1], F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, FLOATV64(s)))) : NULL;
	}
	if (!strcmp(m, "min2")) {
		return c6x_minmax(insn, 2, true, true);
	}
	if (!strcmp(m, "max2")) {
		return c6x_minmax(insn, 2, true, false);
	}
	if (!strcmp(m, "minu4")) {
		return c6x_minmax(insn, 4, false, true);
	}
	if (!strcmp(m, "maxu4")) {
		return c6x_minmax(insn, 4, false, false);
	}
	if (!strcmp(m, "ldw")) {
		return c6x_load(insn, 4, false);
	}
	if (!strcmp(m, "ldb")) {
		return c6x_load(insn, 1, true);
	}
	if (!strcmp(m, "ldbu")) {
		return c6x_load(insn, 1, false);
	}
	if (!strcmp(m, "ldh")) {
		return c6x_load(insn, 2, true);
	}
	if (!strcmp(m, "ldhu")) {
		return c6x_load(insn, 2, false);
	}
	if (!strcmp(m, "stw")) {
		return c6x_store(insn, 4);
	}
	if (!strcmp(m, "stb")) {
		return c6x_store(insn, 1);
	}
	if (!strcmp(m, "sth")) {
		return c6x_store(insn, 2);
	}
	if (!strcmp(m, "lddw") || !strcmp(m, "ldndw")) {
		return c6x_load_pair(insn);
	}
	if (!strcmp(m, "stdw") || !strcmp(m, "stndw")) {
		return c6x_store_pair(insn);
	}
	return NULL;
}

RZ_IPI RzILOpEffect *c6x_lift(const C6xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpEffect *eff = c6x_lift_core(insn, pc);
	if (!eff) {
		return NULL;
	}
	const char *pred = c6x_pred_name(insn->creg);
	if (!pred) {
		return eff; // unconditional
	}
	// predicated: run the effect only when the predicate register satisfies the
	// z sense (z = 1 tests == 0, z = 0 tests != 0).
	RzILOpBool *cond = insn->z ? IS_ZERO(VARG(pred)) : NON_ZERO(VARG(pred));
	return BRANCH(cond, eff, NOP());
}

#include <rz_il/rz_il_opbuilder_end.h>
