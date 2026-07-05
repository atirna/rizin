// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// The C6000 opcode is a fixed 32-bit word. Bit 0 is the parallel bit, bit 1 the
// destination side, bits 31:28 the creg/z predicate; the remaining bits select a
// functional unit and operation through the formats of SPRU733 Appendix C-G.
// Each format is recognised from its fixed low-bit signature, its operand fields
// are sliced out, and the op field is matched in that unit's table below.

#define BITS(w, hi, lo) (((w) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define BIT(w, n)       (((w) >> (n)) & 1u)

// src1 (bits 17:13) is either a register or a short constant, fixed per opcode.
typedef enum {
	SRC1_REG = 0, ///< src1 is a register
	SRC1_SCST5, ///< src1 is a signed 5-bit constant
	SRC1_UCST5, ///< src1 is an unsigned 5-bit constant
	SRC1_NONE, ///< no src1 (unary)
} C6xSrc1Kind;

// A row only decodes on a variant that has the required instruction set.
typedef enum {
	FEAT_BASE = 0, ///< C62x base, present on every generation
	FEAT_FP, ///< floating-point (C67x and up)
	FEAT_SIMD, ///< SIMD/packed (C64x and up)
	FEAT_CPLX, ///< complex/matrix multiply (C674x and C66x: has_fp && has_simd)
	FEAT_C66X, ///< C66x-only additions (4-way dot products, double complex)
} C6xFeat;

// Some floating-point ops mix single registers and 64-bit pairs in ways that
// `pair` alone cannot express, so a row may override the src2/dst shape.
typedef enum {
	OSHAPE_UNIFORM = 0, ///< every register operand follows `pair`
	OSHAPE_CMP_DP, ///< src1/src2 are pairs, dst is a single sint (DP compares)
	OSHAPE_CMP_LONG, ///< src2 is a pair (40-bit long), dst and src1 are singles
	OSHAPE_TO_DP, ///< src2 single widens into a pair dst; src1 (if any) single
	OSHAPE_LONG_DST, ///< src1 single, src2 a pair, dst a pair (long ADD)
} C6xOShape;

typedef struct {
	ut16 op; ///< opfield value within the format
	const char *mnem; ///< mnemonic
	ut8 src1; ///< C6xSrc1Kind
	ut8 feat; ///< C6xFeat gate
	_RzAnalysisOpType type; ///< analysis classification
	bool pair; ///< operands are 64-bit register pairs (double precision)
	ut8 oshape; ///< C6xOShape override for mixed single/pair operands
	bool src1_cross; ///< the cross-path (x) bit selects src1's side, not src2's
	bool no_operand_swap; ///< keep the src1, src2 print order for shift-typed ops
			      ///< that are not reversed-syntax (SHLMB/SHRMB)
} C6xRow;

// .L unit, 7-bit opfield at bits 11:5 (SPRU733 Table 3-12 and per-instruction
// opcodes). Fixed-point base plus the C67x floating-point set.
static const C6xRow c6x_l_rows[] = {
	{ 0x03, "add", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x23, "add", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD, false, OSHAPE_TO_DP },
	{ 0x21, "add", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD, false, OSHAPE_LONG_DST, true },
	{ 0x02, "add", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x20, "add", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x2b, "addu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x29, "addu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x07, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x17, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x27, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_TO_DP },
	{ 0x37, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_TO_DP, true },
	{ 0x06, "sub", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x24, "sub", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x4b, "subc", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x2f, "subu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x0f, "ssub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x0e, "ssub", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x13, "sadd", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x12, "sadd", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x7f, "or", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x7e, "or", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x7b, "and", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7a, "and", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x6f, "xor", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x6e, "xor", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x7c, "andn", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x53, "cmpeq", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x52, "cmpeq", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x51, "cmpeq", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x50, "cmpeq", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x47, "cmpgt", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x46, "cmpgt", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x45, "cmpgt", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x44, "cmpgt", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x4f, "cmpgtu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x4e, "cmpgtu", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x4d, "cmpgtu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x4c, "cmpgtu", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x57, "cmplt", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x56, "cmplt", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x55, "cmplt", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x54, "cmplt", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x5f, "cmpltu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x5e, "cmpltu", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x5d, "cmpltu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x5c, "cmpltu", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_CMP, false, OSHAPE_CMP_LONG },
	{ 0x6b, "lmbd", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x6a, "lmbd", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x63, "norm", SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x60, "norm", SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x61, "shlmb", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SHL, false, OSHAPE_UNIFORM, false, true },
	{ 0x62, "shrmb", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SHR, false, OSHAPE_UNIFORM, false, true },
	{ 0x1a, "abs", SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ABS },
	{ 0x38, "abs", SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ABS, true },
	{ 0x40, "sat", SRC1_NONE, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	// C67x floating-point on .L. Single precision uses scalar registers;
	// double precision uses 64-bit register pairs.
	{ 0x10, "addsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, "subsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x18, "adddp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD, true },
	{ 0x19, "subdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true },
	// src1-cross forms of the non-commutative FP subtracts (x selects src1).
	{ 0x15, "subsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x1d, "subdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true, OSHAPE_UNIFORM, true },
	// int/float conversions and truncation (unary src2 -> dst).
	{ 0x4a, "intsp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x0a, "spint", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x0b, "sptrunc", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x39, "intdp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_TO_DP },
	// double-precision -> integer / single conversions (unary DP pair src2 ->
	// single dst; op fields 0x08/0x09/0x01 per SPRUFE8, encoded but not
	// disassembled by dis6x). CMP_LONG shapes the pair src2 and single dst.
	{ 0x08, "dpint", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x09, "dpsp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	{ 0x01, "dptrunc", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_CMP_LONG },
	// C64x+ SIMD pack/interleave: pack halfwords or bytes from two source
	// registers into one; single registers, src1/src2/dst in the usual order.
	{ 0x00, "pack2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1e, "packh2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1b, "packlh2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x1c, "packhl2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x68, "packl4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x69, "packh4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	// C64x+ packed add/sub (halfword pairs, byte quads) and lane min/max. The
	// saturating ssub2 and the *4 byte forms are single registers throughout.
	{ 0x04, "sub2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x05, "add2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x41, "min2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x42, "max2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x43, "maxu4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x48, "minu4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x64, "ssub2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x65, "add4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x66, "sub4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_SUB },
	// C66x SIMD double add: scst5 src1 with register-pair src2 and dst.
	{ 0x22, "dadd", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD, true },
};

// Floating-point add/sub also issue on the .S unit. They share the .L
// 1-or-2-source format (bits 4:2 == 110, 7-bit opfield) but their opfields
// (0x70..0x77) name the .S unit. SUBSP/SUBDP have a second, cross-path
// (xsint) opfield like their .L counterparts; the DP forms are register pairs.
static const C6xRow c6x_s_fp_rows[] = {
	{ 0x70, "addsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x71, "subsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x75, "subsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, false, OSHAPE_UNIFORM, true },
	{ 0x72, "adddp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD, true },
	{ 0x73, "subdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true },
	{ 0x77, "subdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_SUB, true, OSHAPE_UNIFORM, true },
};

// .D-unit extended logic/arith (C64x+): bits 5:2 == 1100, bits 11:10 == 10,
// 4-bit opfield at bits 9:6. Operand layout matches the standard 3-op form
// (src1, src2, dst; the x bit crosses src2). AND/OR/XOR each have a register
// (uint) and a scst5 form; ADD carries a 5-bit signed constant. OR with a zero
// constant is the MV idiom, but the underlying opcode is what we render.
static const C6xRow c6x_d_ext_rows[] = {
	{ 0x2, "or", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x3, "or", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x6, "and", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7, "and", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0xb, "add", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0xe, "xor", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0xf, "xor", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
};

// .S unit, 6-bit opfield at bits 11:6, signature bits 5:2 == 1000.
static const C6xRow c6x_s_rows[] = {
	{ 0x07, "add", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x06, "add", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x17, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x16, "sub", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x01, "add2", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, "sub2", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	// Shifts (S3/S3i, SPRUFE8 SHL/SHR/SHRU/SSHL opcode maps). op bit 0 selects
	// the register (1) vs ucst5 (0) src1 form. The slong (40-bit, register-pair)
	// variants are omitted; they need src2/dst-only pairing that this shared
	// path cannot yet express.
	{ 0x33, "shl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x32, "shl", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x31, "shl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL, true },
	{ 0x30, "shl", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL, true },
	{ 0x13, "shl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x12, "shl", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x37, "shr", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SAR },
	{ 0x36, "shr", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SAR },
	{ 0x27, "shru", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHR },
	{ 0x26, "shru", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHR },
	{ 0x23, "sshl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x22, "sshl", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SHL },
	{ 0x1f, "and", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x1e, "and", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x0b, "xor", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x0a, "xor", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_XOR },
	{ 0x1b, "or", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x1a, "or", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x36, "andn", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	// single-precision float compares: src1, src2, dst all single
	{ 0x38, "cmpeqsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x39, "cmpgtsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x3a, "cmpltsp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP },
	// double-precision float compares: src1/src2 pairs, dst single sint
	{ 0x28, "cmpeqdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	{ 0x29, "cmpgtdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	{ 0x2a, "cmpltdp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_CMP, true, OSHAPE_CMP_DP },
	// abs (unary, src2 -> dst): single for SP, pair for DP
	{ 0x3c, "abssp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ABS },
	{ 0x2c, "absdp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ABS, true },
	// reciprocal square-root, DP (unary, pair)
	{ 0x2e, "rsqrdp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, true },
	// SP -> DP widening convert (unary, single src2 -> pair dst)
	{ 0x02, "spdp", SRC1_NONE, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MOV, false, OSHAPE_TO_DP },
	// C64x+ packed byte/halfword reshuffles and packed compares (normal .S
	// format). The compares set one result bit per lane in the dst.
	{ 0x08, "packhl2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x10, "packlh2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MOV },
	{ 0x14, "cmpgt2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x15, "cmpgtu4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x1c, "cmpeq4", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
	{ 0x1d, "cmpeq2", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_CMP },
};

// .M unit, 5-bit opfield at bits 11:7, signature bits 6:2 == 00000.
static const C6xRow c6x_m_rows[] = {
	{ 0x19, "mpy", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1f, "mpyu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1d, "mpyus", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1b, "mpysu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1e, "mpysu", SRC1_SCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x01, "mpyh", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x07, "mpyhu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x05, "mpyhus", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x03, "mpyhsu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x11, "mpylh", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x17, "mpylhu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x15, "mpyluhs", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x13, "mpylshu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x09, "mpyhl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0f, "mpyhlu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0d, "mpyhuls", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0b, "mpyhslu", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1a, "smpy", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x02, "smpyh", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0a, "smpyhl", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x12, "smpylh", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x1c, "mpysp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x0e, "mpydp", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL, true },
	{ 0x04, "mpyi", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL },
	// MPYID writes the full 64-bit product of the same 32x32 into a pair.
	{ 0x08, "mpyid", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
	// MPY32 (C64x+): 32x32 multiply. The op-0x10 slot keeps the low 32 bits in
	// a single dst; op-0x14/0x16 write the full 64-bit product to a pair.
	{ 0x10, "mpy32", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0x14, "mpy32", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
	{ 0x16, "mpy32su", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_MUL, false, OSHAPE_TO_DP },
};

// Extended .M (C64x+): bits 5:2 == 1100 with bits 11:10 in {0,1} select the .M
// unit, and the (bits 11:10, bits 9:6) pair names the operation. The wide
// multiplies write a register pair; mpyspdp additionally reads a pair src2.
typedef struct {
	ut8 sub; ///< bits 11:10
	ut8 op; ///< bits 9:6
	const char *mnem;
	ut8 feat;
	bool dst_pair; ///< dst is a 64-bit register pair
	bool src2_pair; ///< src2 is a 64-bit register pair
	_RzAnalysisOpType type;
	bool src1_cross; ///< the cross-path (x) bit selects src1's side (mpyspdp)
	bool swap; ///< reversed syntax src2, src1, dst (sshvl/sshvr/rotl)
} C6xMExtRow;

static const C6xMExtRow c6x_m_ext_rows[] = {
	{ 0, 0, "mpy2", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 1, "smpy2", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 2, "dotpsu4", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 4, "mpyu4", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 5, "mpysu4", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 6, "dotpu4", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 7, "dotpnrsu2", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 9, "dotpn2", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 12, "dotp2", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 13, "dotprsu2", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 0, 14, "mpylir", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 0, "mpyhir", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 1, "gmpy4", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 4, "mpyhi", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 5, "mpyli", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 6, "mpyspdp", FEAT_FP, true, true, RZ_ANALYSIS_OP_TYPE_MUL, true },
	{ 1, 7, "mpysp2dp", FEAT_FP, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 8, "mpy32u", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 9, "mpy32us", FEAT_SIMD, true, false, RZ_ANALYSIS_OP_TYPE_MUL },
	{ 1, 2, "avgu4", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, 3, "avg2", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, 10, "sshvr", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_SHR, false, true },
	{ 1, 12, "sshvl", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_SHL, false, true },
	{ 1, 13, "rotl", FEAT_SIMD, false, false, RZ_ANALYSIS_OP_TYPE_ROL },
};

// The bits 11:10 == 0, bits 9:6 == 3 slot is a family of unary moves and
// bit/byte shuffles (src2 -> dst) selected by the src1 field.
typedef struct {
	ut8 src1;
	const char *mnem;
} C6xMUnaryRow;

static const C6xMUnaryRow c6x_m_unary_rows[] = {
	{ 24, "xpnd4" }, { 25, "xpnd2" }, { 26, "mvd" }, { 28, "shfl" },
	{ 29, "deal" }, { 30, "bitc4" }, { 31, "bitr" }
};

// C66x complex/matrix multiplies and 4-way dot products live in the extended
// .M space too, but are always unconditional and mark it with z = 1, creg = 0
// -- that pattern tells them apart from the C64x+ op in the same slot. The
// complex multiplies and Galois ops reach C674x; the double/4H forms are C66x.
typedef struct {
	ut8 sub; ///< bits 11:10
	ut8 op; ///< bits 9:6
	const char *mnem;
	ut8 feat;
	ut8 k1; ///< src1 operand kind (C6X_OP_REG / _REGPAIR / _REGQUAD)
	ut8 k2; ///< src2 operand kind
	ut8 k3; ///< dst operand kind
} C6xMCplxRow;

static const C6xMCplxRow c6x_m_cplx_rows[] = {
	{ 0, 5, "dotpsu4h", FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REG },
	{ 0, 6, "dotp4h", FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REG },
	{ 0, 10, "cmpy", FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 0, 11, "cmpyr", FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 0, 12, "cmpyr1", FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 0, 13, "dcmpyr1", FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR },
	{ 0, 14, "dccmpyr1", FEAT_C66X, C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR },
	{ 1, 6, "ddotpl2", FEAT_CPLX, C6X_OP_REGPAIR, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 1, 7, "ddotph2", FEAT_CPLX, C6X_OP_REGPAIR, C6X_OP_REG, C6X_OP_REGPAIR },
	{ 1, 10, "qsmpy32r1", FEAT_C66X, C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD },
	{ 1, 11, "xormpy", FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG },
	{ 1, 15, "gmpy", FEAT_CPLX, C6X_OP_REG, C6X_OP_REG, C6X_OP_REG }
};

// C66x quad/matrix multiplies sit in the normal .M format but, like the complex
// ops, mark themselves unconditional with z = 1, creg = 0. They take 128-bit
// register quads; cmatmpy reads its pair src1 and quad src2 from swapped fields.
typedef struct {
	ut8 op; ///< opcode bits 11:7
	const char *mnem;
	ut8 k1; ///< src1 operand kind (C6X_OP_REG / _REGPAIR / _REGQUAD)
	ut8 k2; ///< src2 operand kind
	ut8 k3; ///< dst operand kind
	bool swap; ///< src1 is in the src2 field and vice versa
} C6xMWideRow;

static const C6xMWideRow c6x_m_wide_rows[] = {
	{ 0x04, "cmatmpy", C6X_OP_REGPAIR, C6X_OP_REGQUAD, C6X_OP_REGQUAD, true },
	{ 0x06, "cmatmpyr1", C6X_OP_REGPAIR, C6X_OP_REGQUAD, C6X_OP_REGPAIR, true },
	{ 0x10, "qmpy32", C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD, false },
	{ 0x1c, "dmpysp", C6X_OP_REGPAIR, C6X_OP_REGPAIR, C6X_OP_REGPAIR, false },
	{ 0x1d, "qmpysp", C6X_OP_REGQUAD, C6X_OP_REGQUAD, C6X_OP_REGQUAD, false }
};

// Extended .S (C64x+): bits 5:2 == 1100, bits 11:10 == 11, op at bits 9:6.
// Packed shifts, saturating add/pack and andn; register src1, src2, dst.
typedef struct {
	ut8 op; ///< bits 9:6
	const char *mnem;
	_RzAnalysisOpType type;
	bool swap; ///< render src2 (value) before src1 (count), as shifts do
} C6xSExtRow;

static const C6xSExtRow c6x_s_ext_rows[] = {
	{ 0, "sadd2", RZ_ANALYSIS_OP_TYPE_ADD },
	{ 1, "saddus2", RZ_ANALYSIS_OP_TYPE_ADD },
	{ 3, "saddu4", RZ_ANALYSIS_OP_TYPE_ADD },
	{ 2, "spack2", RZ_ANALYSIS_OP_TYPE_MOV },
	{ 4, "spacku4", RZ_ANALYSIS_OP_TYPE_MOV },
	{ 6, "andn", RZ_ANALYSIS_OP_TYPE_AND },
	{ 7, "shr2", RZ_ANALYSIS_OP_TYPE_SHR, true },
	{ 8, "shru2", RZ_ANALYSIS_OP_TYPE_SHR, true },
	{ 9, "shlmb", RZ_ANALYSIS_OP_TYPE_SHL },
	{ 10, "shrmb", RZ_ANALYSIS_OP_TYPE_SHR },
	{ 11, "rpack2", RZ_ANALYSIS_OP_TYPE_MOV },
	{ 15, "pack2", RZ_ANALYSIS_OP_TYPE_MOV }
};

// The .L opfield 0x1a (nominally ABS) is shared by unary byte/halfword
// reshuffles on C64x+, selected by the src1 field (src2 -> dst).
static const C6xMUnaryRow c6x_l_unary_rows[] = {
	{ 1, "swap4" }, { 2, "unpklu4" }, { 3, "unpkhu4" }, { 4, "abs2" }
};

// .D unit arithmetic and address ops, 6-bit opfield at bits 12:7, signature
// bits 6:2 == 10000 (SPRU733 Figure C-1 body).
static const C6xRow c6x_d_rows[] = {
	{ 0x10, "add", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x12, "add", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x11, "sub", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x13, "sub", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x30, "addab", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x32, "addab", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x34, "addah", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x36, "addah", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x38, "addaw", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3a, "addaw", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3c, "addad", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3c, "addad", SRC1_REG, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3d, "addad", SRC1_UCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x3d, "addad", SRC1_UCST5, FEAT_FP, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0x31, "subab", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x35, "subah", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x39, "subaw", SRC1_REG, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
	{ 0x3b, "subaw", SRC1_UCST5, FEAT_BASE, RZ_ANALYSIS_OP_TYPE_SUB },
};

// .D-unit extended logical/arith (C64x+): SPRUFE8 Dx2/Dx5 family, marked by
// bits 5:2 == 1100 with bits 11:10 == 10 selecting the .D unit. The op is a
// 4-bit field at bits 9:6; OR with a zero source constant becomes MV.
static const C6xRow c6x_dext_rows[] = {
	{ 0x0, "andn", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x2, "or", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x3, "or", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_OR },
	{ 0x6, "and", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0x7, "and", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_AND },
	{ 0xa, "add", SRC1_REG, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_ADD },
	{ 0xf, "xor", SRC1_SCST5, FEAT_SIMD, RZ_ANALYSIS_OP_TYPE_XOR },
};

// .D unit loads/stores, 3-bit opfield at bits 6:4, signature bits 3:2 == 01
// (SPRU733 Tables 3-17/3-19). The op encodes access width and direction.
static const struct {
	ut8 op;
	const char *mnem;
	bool store;
} c6x_mem_rows[] = {
	{ 0x0, "ldhu", false },
	{ 0x1, "ldbu", false },
	{ 0x2, "ldb", false },
	{ 0x3, "stb", true },
	{ 0x4, "ldh", false },
	{ 0x5, "sth", true },
	{ 0x6, "ldw", false },
	{ 0x7, "stw", true },
};

const C6xArchDesc c6x_desc_c62x = { C6X_GEN_C62X, 16, false, false };
const C6xArchDesc c6x_desc_c67x = { C6X_GEN_C67X, 16, true, false };
const C6xArchDesc c6x_desc_c64x = { C6X_GEN_C64X, 32, false, true };
const C6xArchDesc c6x_desc_c674x = { C6X_GEN_C674X, 32, true, true };
const C6xArchDesc c6x_desc_c66x = { C6X_GEN_C66X, 32, true, true };

RZ_IPI const C6xArchDesc *c6x_desc_from_cpu(const char *cpu) {
	if (!cpu) {
		return NULL;
	}
	if (!rz_str_casecmp(cpu, "c62x")) {
		return &c6x_desc_c62x;
	}
	if (!rz_str_casecmp(cpu, "c67x")) {
		return &c6x_desc_c67x;
	}
	if (!rz_str_casecmp(cpu, "c64x")) {
		return &c6x_desc_c64x;
	}
	// C64x+ is a superset of C64x; the extra instructions this engine decodes
	// are gated by the SIMD feature the C64x descriptor already carries.
	if (!rz_str_casecmp(cpu, "c64x+") || !rz_str_casecmp(cpu, "c64xp") ||
		!rz_str_casecmp(cpu, "c64x_plus")) {
		return &c6x_desc_c64x;
	}
	if (!rz_str_casecmp(cpu, "c674x")) {
		return &c6x_desc_c674x;
	}
	if (!rz_str_casecmp(cpu, "c66x")) {
		return &c6x_desc_c66x;
	}
	return NULL;
}

RZ_IPI void c6x_mark_parallel(RZ_INOUT C6xInsn *insn, ut64 addr, RZ_INOUT ut64 *prev_end, RZ_INOUT bool *prev_par) {
	if (insn->is_header) {
		// a fetch-packet header occupies a word but is not part of any execute
		// packet: keep it out of the "||" chain and pass the previous parallel
		// state through unchanged so an execute packet can span the header
		insn->cont = false;
		*prev_end = addr + insn->size;
		return;
	}
	// only a word landing exactly after the previous one continues its packet;
	// a gap (random-access disassembly, region restart) starts fresh
	insn->cont = addr == *prev_end && *prev_par;
	*prev_end = addr + insn->size;
	*prev_par = insn->parallel;
}

static bool feat_ok(const C6xArchDesc *d, ut8 feat) {
	switch (feat) {
	case FEAT_FP:
		return d->has_fp;
	case FEAT_SIMD:
		return d->has_simd;
	case FEAT_CPLX:
		return d->has_fp && d->has_simd; // C674x and C66x
	case FEAT_C66X:
		return d->gen == C6X_GEN_C66X;
	default:
		return true;
	}
}

static const C6xRow *row_find(const C6xRow *rows, size_t n, ut16 op, const C6xArchDesc *d) {
	for (size_t i = 0; i < n; i++) {
		if (rows[i].op == op && feat_ok(d, rows[i].feat)) {
			return &rows[i];
		}
	}
	return NULL;
}

static void op_reg(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REG;
	o->side = side;
	o->num = num;
}

static void op_regpair(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REGPAIR;
	o->side = side;
	o->num = num & ~1u;
}

static void op_regquad(C6xOperand *o, ut8 side, ut8 num) {
	o->kind = C6X_OP_REGQUAD;
	o->side = side;
	o->num = num & ~3u;
}

// Fill a register operand of a caller-chosen width (single / pair / quad).
static void op_by_kind(C6xOperand *o, ut8 kind, ut8 side, ut8 num) {
	if (kind == C6X_OP_REGQUAD) {
		op_regquad(o, side, num);
	} else if (kind == C6X_OP_REGPAIR) {
		op_regpair(o, side, num);
	} else {
		op_reg(o, side, num);
	}
}

static void op_imm(C6xOperand *o, st64 v) {
	o->kind = C6X_OP_IMM;
	o->imm = v;
}

static void op_ctrlreg(C6xOperand *o, const char *name) {
	o->kind = C6X_OP_CTRLREG;
	o->name = name;
}

// Control registers by crlo field (SPRUFE8 Table 3-27). crlo 2 and 29 name a
// different register per direction (read vs write), disambiguated by \p read.
static const char *ctrlreg_name(ut8 crlo, bool read) {
	static const char *const by_crlo[32] = {
		"amr", "csr", NULL, "icr", "ier", "istp", "irp", "nrp",
		NULL, NULL, "tscl", "tsch", NULL, "ilc", "rilc", "rep",
		"pce1", "dnum", "fadcr", "faucr", "fmcr", "ssr", "gplya", "gplyb",
		"gfpgfr", "dier", "tsr", "itsr", "ntsr", NULL, NULL, "ierr"
	};
	if (crlo == 2) {
		return read ? "ifr" : "isr";
	}
	if (crlo == 29) {
		return read ? "efr" : "ecr";
	}
	return by_crlo[crlo];
}

// Sign-extend the low \p bits of \p v. The cast goes through st32 so the sign
// bit propagates: without it the ut32 subtraction wraps and widens to a large
// positive st64 (which broke backward branches and negative constants).
static st64 sext(ut32 v, ut8 bits) {
	ut32 m = 1u << (bits - 1);
	return (st64)(st32)((v ^ m) - m);
}

// Fill src1 (bits 17:13) as register or short constant per the row's kind.
static void fill_src1(C6xOperand *o, ut32 w, ut8 side, C6xSrc1Kind kind) {
	ut8 f = BITS(w, 17, 13);
	switch (kind) {
	case SRC1_REG:
		op_reg(o, side, f);
		break;
	case SRC1_SCST5:
		op_imm(o, sext(f, 5));
		break;
	case SRC1_UCST5:
		op_imm(o, f);
		break;
	default:
		o->kind = C6X_OP_NONE;
		break;
	}
}

// .L/.S/.M 3-operand form: dst, src2 (cross-pathable), src1 (reg or const).
// Double-precision rows read and write 64-bit register pairs instead of scalars.
static void decode_3op(C6xInsn *insn, const C6xRow *row) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 x = BIT(w, 12);
	insn->mnemonic = row->mnem;
	insn->op_type = row->type;
	insn->is_fp = row->feat == FEAT_FP;
	insn->unit_side = s + 1;
	insn->cross = x != 0;
	// The cross-path (x) bit moves one source operand to the opposite register
	// side. It normally selects src2; src1-cross variants (non-commutative ops
	// such as SUBSP/SUBDP) apply it to src1 instead.
	ut8 src1_side = (row->src1_cross && x) ? !s : s;
	ut8 src2_side = (!row->src1_cross && x) ? !s : s;
	ut8 nops = 0;
	if (row->src1 != SRC1_NONE) {
		if (row->pair && row->src1 == SRC1_REG) {
			op_regpair(&insn->ops[nops++], src1_side, BITS(w, 17, 13));
		} else {
			fill_src1(&insn->ops[nops++], w, src1_side, row->src1);
		}
	}
	bool src2_pair = row->pair;
	bool dst_pair = row->pair;
	if (row->oshape == OSHAPE_CMP_DP) {
		dst_pair = false; // DP compare result is a single sint
	} else if (row->oshape == OSHAPE_TO_DP) {
		src2_pair = false; // a single src2 widened into a pair dst
		dst_pair = true;
	} else if (row->oshape == OSHAPE_CMP_LONG) {
		src2_pair = true; // a 40-bit long src2 compared against a single/const
		dst_pair = false;
	} else if (row->oshape == OSHAPE_LONG_DST) {
		src2_pair = true; // long ADD: single src1 + long src2 -> long dst
		dst_pair = true;
	}
	if (src2_pair) {
		op_regpair(&insn->ops[nops++], src2_side, BITS(w, 22, 18)); // src2
	} else {
		op_reg(&insn->ops[nops++], src2_side, BITS(w, 22, 18)); // src2
	}
	// Shifts print value (src2) before count (src1); swap the two sources
	// that were emitted in the fixed src1, src2 order above.
	bool is_shift = row->type == RZ_ANALYSIS_OP_TYPE_SHL ||
		row->type == RZ_ANALYSIS_OP_TYPE_SHR || row->type == RZ_ANALYSIS_OP_TYPE_SAR;
	if (is_shift && nops == 2 && !row->no_operand_swap) {
		C6xOperand tmp = insn->ops[0];
		insn->ops[0] = insn->ops[1];
		insn->ops[1] = tmp;
	}
	if (dst_pair) {
		op_regpair(&insn->ops[nops++], s, BITS(w, 27, 23)); // dst
	} else {
		op_reg(&insn->ops[nops++], s, BITS(w, 27, 23)); // dst
	}
	insn->nops = nops;
	// Render the .S/.L assembler idioms the way the TI tools do so the output
	// matches the reference disassembler:
	//   MV   dst = 0 | src   or   0 + src        (OR/ADD against 0)
	//   NEG  dst = 0 - src                        (SUB from 0)
	//   ZERO dst = src - src                      (SUB of a register from itself)
	//   SUB  src2, k, dst  for  ADD -k, src2, dst (negative-constant ADD)
	bool is_add = !strcmp(row->mnem, "add");
	bool is_sub = !strcmp(row->mnem, "sub");
	bool is_or = !strcmp(row->mnem, "or");
	bool is_xor = !strcmp(row->mnem, "xor");
	if (nops == 3 && insn->ops[0].kind == C6X_OP_IMM && insn->ops[0].imm == 0 &&
		(is_or || is_add || is_sub)) {
		insn->mnemonic = is_sub ? "neg" : "mv";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		insn->ops[0] = insn->ops[1];
		insn->ops[1] = insn->ops[2];
		insn->nops = 2;
	} else if (nops == 3 && is_xor && insn->ops[0].kind == C6X_OP_IMM &&
		insn->ops[0].imm == -1) {
		insn->mnemonic = "not"; // XOR -1, src, dst  ==  NOT src, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOT;
		insn->ops[0] = insn->ops[1];
		insn->ops[1] = insn->ops[2];
		insn->nops = 2;
	} else if (nops == 3 && is_add && insn->ops[0].kind == C6X_OP_IMM &&
		insn->ops[0].imm < 0) {
		insn->mnemonic = "sub"; // ADD -k, src2, dst  ==  SUB src2, k, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		st64 k = -insn->ops[0].imm;
		insn->ops[0] = insn->ops[1];
		op_imm(&insn->ops[1], k);
	} else if (nops == 3 && is_sub && insn->ops[0].kind == C6X_OP_REG &&
		insn->ops[1].kind == C6X_OP_REG && insn->ops[0].num == insn->ops[1].num &&
		insn->ops[0].side == insn->ops[1].side) {
		insn->mnemonic = "zero"; // SUB src, src, dst  ==  ZERO dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		insn->ops[0] = insn->ops[2];
		insn->nops = 1;
	}
}

// .D arithmetic/address form, all on side s with no cross path. The .D
// encoding places the base/src2 register at bits 22:18 and src1 (register or
// short constant) at bits 17:13, and the assembler prints them in that order
// -- src2, src1, dst -- for both plain ADD/SUB and the ADDA*/SUBA* address
// ops, unlike the .L/.S forms that print src1 first.
static void decode_darith(C6xInsn *insn, const C6xRow *row) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	insn->mnemonic = row->mnem;
	insn->op_type = row->type;
	insn->unit_side = s + 1;
	op_reg(&insn->ops[0], s, BITS(w, 22, 18)); // src2 (base)
	fill_src1(&insn->ops[1], w, s, row->src1); // src1 (offset/operand)
	op_reg(&insn->ops[2], s, BITS(w, 27, 23)); // dst
	insn->nops = 3;
	// The .D unit shares the same assembler idioms as .L/.S: MV/NEG (ADD/SUB
	// against 0), NOT (XOR -1), ZERO (SUB of a register from itself), and the
	// negative-constant SUB spelled as ADD. In the .D operand order src2 comes
	// first, so the constant (when present) is src1 at ops[1].
	bool d_add = !strcmp(row->mnem, "add");
	bool d_sub = !strcmp(row->mnem, "sub");
	bool d_xor = !strcmp(row->mnem, "xor");
	if (insn->ops[1].kind == C6X_OP_IMM && insn->ops[1].imm == 0 && (d_add || d_sub)) {
		insn->mnemonic = d_sub ? "neg" : "mv";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		insn->ops[1] = insn->ops[2]; // dst follows src
		insn->nops = 2;
	} else if (insn->ops[1].kind == C6X_OP_IMM && insn->ops[1].imm == -1 && d_xor) {
		insn->mnemonic = "not"; // XOR src, -1, dst  ==  NOT src, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOT;
		insn->ops[1] = insn->ops[2];
		insn->nops = 2;
	} else if (d_add && insn->ops[1].kind == C6X_OP_IMM && insn->ops[1].imm < 0) {
		insn->mnemonic = "sub"; // ADD src2, -k, dst  ==  SUB src2, k, dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_SUB;
		op_imm(&insn->ops[1], -insn->ops[1].imm);
	} else if (d_sub && insn->ops[0].kind == C6X_OP_REG && insn->ops[1].kind == C6X_OP_REG &&
		insn->ops[0].num == insn->ops[1].num && insn->ops[0].side == insn->ops[1].side) {
		insn->mnemonic = "zero"; // SUB src, src, dst  ==  ZERO dst
		insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
		insn->ops[0] = insn->ops[2];
		insn->nops = 1;
	}
}

// .D long-immediate load/store: *+B14/B15[ucst15] (SPRU733 LDW 15-bit offset).
// Base is B14 (y=0) or B15 (y=1); the 15-bit unsigned offset sits at bits 22:8.
static void decode_ldst_long(C6xInsn *insn, const char *mnem, bool store) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	C6xOperand mem = { 0 };
	C6xOperand reg = { 0 };
	insn->mnemonic = mnem;
	insn->op_type = store ? RZ_ANALYSIS_OP_TYPE_STORE : RZ_ANALYSIS_OP_TYPE_LOAD;
	insn->unit = C6X_UNIT_D;
	insn->unit_side = 2; // B14/B15 are on the B side; .D2 only
	mem.kind = C6X_OP_MEM;
	mem.mode = C6X_AM_POS_CST;
	mem.base = y ? 15 : 14;
	mem.base_side = 1;
	mem.off_cst = BITS(w, 22, 8);
	mem.scaled = true;
	op_reg(&reg, s, BITS(w, 27, 23));
	insn->ops[0] = store ? reg : mem;
	insn->ops[1] = store ? mem : reg;
	insn->nops = 2;
}

// .D ADDAW with a 15-bit constant: B14/B15 + ucst15 -> dst. It reuses the STW
// 15-bit-offset slot (bits 6:2 == 0x1f, op 7); the address form is marked by
// the otherwise-reserved creg=0/z=1 pattern (bits 31:28 == 0001), so a real
// (predicated or plain) STW there stays a store. The offset is a word count.
static void decode_addaw_long(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	insn->mnemonic = "addaw";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit = C6X_UNIT_D;
	insn->unit_side = s + 1;
	op_reg(&insn->ops[0], 1, y ? 15 : 14); // base B14/B15
	op_imm(&insn->ops[1], BITS(w, 22, 8)); // ucst15
	insn->ops[1].imm_dec = true;
	op_reg(&insn->ops[2], s, BITS(w, 27, 23)); // dst
	insn->nops = 3;
}

// .D load/store addressing mode (bits 12:9), Table 3-11.
static C6xAddrMode ldst_mode(ut8 field, bool *reg_offset) {
	static const C6xAddrMode modes[16] = {
		C6X_AM_NEG_CST, C6X_AM_POS_CST, C6X_AM_NEG_CST, C6X_AM_POS_CST,
		C6X_AM_NEG_REG, C6X_AM_POS_REG, C6X_AM_NEG_REG, C6X_AM_POS_REG,
		C6X_AM_PREDEC_CST, C6X_AM_PREINC_CST, C6X_AM_POSTDEC_CST, C6X_AM_POSTINC_CST,
		C6X_AM_PREDEC_REG, C6X_AM_PREINC_REG, C6X_AM_POSTDEC_REG, C6X_AM_POSTINC_REG
	};
	*reg_offset = (field & 0x4) != 0;
	return modes[field & 0xf];
}

static void decode_ldst(C6xInsn *insn, const char *mnem, bool store, bool dword) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 y = BIT(w, 7);
	bool reg_off = false;
	C6xOperand mem = { 0 };
	C6xOperand reg = { 0 };
	insn->mnemonic = mnem;
	insn->op_type = store ? RZ_ANALYSIS_OP_TYPE_STORE : RZ_ANALYSIS_OP_TYPE_LOAD;
	insn->unit_side = y + 1;
	mem.kind = C6X_OP_MEM;
	mem.mode = ldst_mode(BITS(w, 12, 9), &reg_off);
	mem.base = BITS(w, 22, 18);
	mem.base_side = y;
	mem.scaled = true; // [] bracket scaling by access size
	if (reg_off) {
		mem.off_reg = BITS(w, 17, 13);
	} else {
		mem.off_cst = BITS(w, 17, 13);
	}
	if (dword) {
		reg.kind = C6X_OP_REGPAIR;
		reg.side = s;
		reg.num = BITS(w, 27, 23) & ~1u;
	} else {
		op_reg(&reg, s, BITS(w, 27, 23));
	}
	// TI syntax: loads read "*mem, dst"; stores read "src, *mem".
	insn->ops[0] = store ? reg : mem;
	insn->ops[1] = store ? mem : reg;
	insn->nops = 2;
}

// .S branch to a register: B/BNOP (.S2) src2 (SPRU733 "Branch Using a
// Register"). src2 holds the target; a return is BNOP .S2 B3, 5. The 3-bit
// field at 15:13 is the NOP count -- when non-zero the assembler spells it
// BNOP; the C64x+ compiler uses BNOP B3, 5 as the return idiom.
static void decode_branch_reg(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 x = BIT(w, 12);
	ut8 n = BITS(w, 15, 13);
	insn->mnemonic = n ? "bnop" : "b";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
	insn->unit_side = 2; // .S2 only
	insn->cross = x != 0;
	// src2 is read from the B side, or the A side when the cross path is used
	op_reg(&insn->ops[0], x ? 0 : 1, BITS(w, 22, 18));
	insn->nops = 1;
	if (n) {
		op_imm(&insn->ops[insn->nops++], n);
	}
}

// .S branch, 21-bit signed PC-relative displacement (scaled by 4), Figure F-5.
static void decode_branch(C6xInsn *insn) {
	ut32 w = insn->word;
	st64 disp = sext(BITS(w, 27, 7), 21) * 4;
	insn->unit_side = BIT(w, 1) + 1;
	insn->ops[0].kind = C6X_OP_PCREL;
	insn->ops[0].imm = disp; // absolute target resolved by the analysis filler
	insn->nops = 1;
	// CALLP is encoded as an otherwise-meaningless unconditional branch with the
	// z bit set; the return address is placed in A3 (.S1) or B3 (.S2).
	if (insn->creg == 0 && insn->z) {
		insn->mnemonic = "callp";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_CALL;
		op_reg(&insn->ops[1], insn->unit_side - 1, 3);
		insn->nops = 2;
		return;
	}
	insn->mnemonic = "b";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
}

// .S BNOP with a displacement (SPRUFE8 Figure F-10): a 12-bit signed
// displacement plus a NOP count. Unlike the plain B (scaled by 4), this
// displacement is half-word-scaled (x2) so it can target compact instructions;
// it stays packet-relative, so the analysis filler resolves it against PCE1.
static void decode_branch_nop(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 n = BITS(w, 15, 13);
	insn->mnemonic = "bnop";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
	insn->unit_side = BIT(w, 1) + 1;
	insn->ops[0].kind = C6X_OP_PCREL;
	insn->ops[0].imm = sext(BITS(w, 27, 16), 12) * 2;
	op_imm(&insn->ops[1], n);
	insn->nops = 2;
}
static void decode_mvk(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	ut8 h = BIT(w, 6);
	insn->mnemonic = h ? "mvkh" : "mvk";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
	insn->unit_side = s + 1;
	op_imm(&insn->ops[0], h ? (st64)BITS(w, 22, 7) : sext(BITS(w, 22, 7), 16));
	op_reg(&insn->ops[1], s, BITS(w, 27, 23));
	insn->nops = 2;
}

// .S ADDK, 16-bit signed constant, Figure (ADDK opcode row bits 6:2 == 10100).
static void decode_addk(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	insn->mnemonic = "addk";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit_side = s + 1;
	op_imm(&insn->ops[0], sext(BITS(w, 22, 7), 16));
	op_reg(&insn->ops[1], s, BITS(w, 27, 23));
	insn->nops = 2;
}

// .S2 ADDKPC (C64x+): forms a PC-relative address, dst = PCE1 + scst7 * 4,
// and skips a following count (bits 15:13) of parallel NOP cycles. The target
// is rendered like a branch so it reads as an absolute address.
static void decode_addkpc(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	insn->mnemonic = "addkpc";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
	insn->unit_side = s + 1;
	insn->ops[0].kind = C6X_OP_PCREL;
	insn->ops[0].imm = sext(BITS(w, 22, 16), 7) * 4;
	op_reg(&insn->ops[1], s, BITS(w, 27, 23)); // dst
	op_imm(&insn->ops[2], BITS(w, 15, 13)); // parallel NOP count
	insn->ops[2].imm_dec = true;
	insn->nops = 3;
}

// .S BDEC/BPOS (C64x+ loop control): branch to PCE1 + scst10 * 4 while the
// named register is non-negative; BDEC also predecrements it. Bit 12 selects
// the decrementing form (1) over the plain positive test (0).
static void decode_bdec(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	insn->mnemonic = BIT(w, 12) ? "bdec" : "bpos";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_CJMP;
	insn->unit_side = s + 1;
	insn->ops[0].kind = C6X_OP_PCREL;
	insn->ops[0].imm = sext(BITS(w, 22, 13), 10) * 4;
	op_reg(&insn->ops[1], s, BITS(w, 27, 23)); // counter register
	insn->nops = 2;
}

// No-unit NOP (SPRU733 Appendix G): the word is all zero except the parallel bit
// and a 1..8 cycle count in bits 16:13 (count = field + 1). IDLE is a dedicated
// control opcode handled by the emulation format.
static bool decode_nounit(C6xInsn *insn) {
	ut32 w = insn->word;
	// only the count field (16:13) and the parallel bit (0) may be set
	if ((w & ~((0xfu << 13) | 1u)) == 0) {
		ut8 cnt = BITS(w, 16, 13) + 1;
		// a 16-cycle delay is not a real NOP; that slot is the IDLE opcode
		if (cnt == 16) {
			insn->mnemonic = "idle";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
			insn->unit = C6X_UNIT_NONE;
			return true;
		}
		insn->mnemonic = "nop";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		insn->unit = C6X_UNIT_NONE;
		if (cnt > 1) {
			op_imm(&insn->ops[0], cnt);
			insn->nops = 1;
		}
		return true;
	}
	// SPLOOP/SPLOOPD/SPMASK (C64x+ software-pipelined loop buffer): bit 17 marks
	// this class, bits 17:13 pick the op, and SPLOOP(D) carry the loop iteration
	// interval (ii = field + 1) in bits 27:23.
	if (BIT(w, 17) && (w & ~((0x1fu << 23) | (0x1fu << 13) | 1u)) == 0) {
		ut8 sel = BITS(w, 17, 13);
		const char *mn = sel == 24 ? "spmask" : sel == 28 ? "sploop"
			: sel == 29                               ? "sploopd"
								  : NULL;
		if (mn) {
			insn->mnemonic = mn;
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
			insn->unit = C6X_UNIT_NONE;
			if (sel != 24) {
				op_imm(&insn->ops[0], BITS(w, 27, 23) + 1);
				insn->nops = 1;
			}
			return true;
		}
	}
	// DINT/RINT: no-unit interrupt-enable control (SPRUFE8 Figure H-1). The
	// 0001 prefix at bits 31:28 is opcode, not a predicate, so it must not be
	// read as creg/z. op (bits 16:13) selects the mnemonic; only the op field
	// and the parallel bit may otherwise be set.
	if ((w & ~((0xfu << 13) | 1u)) == 0x10000000) {
		ut8 op = BITS(w, 16, 13);
		const char *mn = op == 2 ? "dint" : op == 3 ? "rint"
							    : NULL;
		if (mn) {
			insn->mnemonic = mn;
			insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
			insn->unit = C6X_UNIT_NONE;
			insn->creg = 0;
			insn->z = 0;
			return true;
		}
	}
	return false;
}

// MVC: move between a control register and a general register (.S2 only).
// bit 6 selects direction; the control register is named by its crlo field
// (crhi is 0 for register access, so it is not rendered).
static bool decode_mvc(C6xInsn *insn) {
	ut32 w = insn->word;
	ut8 s = BIT(w, 1);
	bool read = BIT(w, 6); // 1: control -> register; 0: register -> control
	ut8 crlo = read ? BITS(w, 22, 18) : BITS(w, 27, 23);
	ut8 reg = read ? BITS(w, 27, 23) : BITS(w, 22, 18);
	const char *cr = ctrlreg_name(crlo, read);
	insn->mnemonic = "mvc";
	insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
	insn->unit = C6X_UNIT_S;
	insn->unit_side = s + 1;
	if (read) {
		op_ctrlreg(&insn->ops[0], cr);
		op_reg(&insn->ops[1], s, reg);
	} else {
		op_reg(&insn->ops[0], s, reg);
		op_ctrlreg(&insn->ops[1], cr);
	}
	insn->nops = 2;
	return cr != NULL;
}

// EXTU/EXT/SET/CLR, constant form (SPRUFE8 field-op format): csta and cstb
// give the bit-field bounds as 5-bit constants; the op is bits 7:6.
static bool decode_field(C6xInsn *insn) {
	ut32 w = insn->word;
	static const char *const names[4] = { "extu", "ext", "set", "clr" };
	static const _RzAnalysisOpType types[4] = {
		RZ_ANALYSIS_OP_TYPE_SHR, RZ_ANALYSIS_OP_TYPE_SHR,
		RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_AND
	};
	ut8 op = BITS(w, 7, 6);
	ut8 s = BIT(w, 1);
	insn->mnemonic = names[op];
	insn->op_type = types[op];
	insn->unit = C6X_UNIT_S;
	insn->unit_side = s + 1;
	op_reg(&insn->ops[0], s, BITS(w, 22, 18)); // src2
	op_imm(&insn->ops[1], BITS(w, 17, 13)); // csta
	op_imm(&insn->ops[2], BITS(w, 12, 8)); // cstb
	insn->ops[1].imm_dec = true;
	insn->ops[2].imm_dec = true;
	op_reg(&insn->ops[3], s, BITS(w, 27, 23)); // dst
	insn->nops = 4;
	return true;
}

// Decode a functional-unit instruction from its low-bit signature.
static bool decode_unit(const C6xArchDesc *d, C6xInsn *insn) {
	ut32 w = insn->word;
	// .D loads/stores: bits 3:2 == 01
	if (BITS(w, 3, 2) == 0x1) {
		// Doubleword variants (register pair) are marked by bit 8; the op
		// field then selects among them. Available on C64x+ (SIMD) and C67x
		// (FP), not plain C62x.
		if (BIT(w, 8)) {
			const char *mn = NULL;
			bool store = false, dword = true;
			switch (BITS(w, 6, 4)) {
			case 0x2: mn = "ldndw"; break;
			case 0x3:
				mn = "ldnw", dword = false;
				break; // non-aligned word load (C64x+)
			case 0x4: mn = "stdw", store = true; break;
			case 0x5:
				mn = "stnw", store = true, dword = false;
				break; // non-aligned word store (C64x+)
			case 0x6: mn = "lddw"; break;
			case 0x7: mn = "stndw", store = true; break;
			}
			if (mn) {
				decode_ldst(insn, mn, store, dword);
				insn->unit = C6X_UNIT_D;
				return feat_ok(d, FEAT_FP) || feat_ok(d, FEAT_SIMD);
			}
		}
		ut8 op = BITS(w, 6, 4);
		decode_ldst(insn, c6x_mem_rows[op].mnem, c6x_mem_rows[op].store, false);
		insn->unit = C6X_UNIT_D;
		return true;
	}
	// .D long-immediate loads/stores (*+B14/B15[ucst15]): bits 3:2 == 11
	if (BITS(w, 3, 2) == 0x3) {
		ut8 op = BITS(w, 6, 4);
		// ADDAW shares the op-7 (STW) slot; bits 31:28 == 0001 selects it.
		if (op == 0x7 && BITS(w, 31, 28) == 0x1) {
			decode_addaw_long(insn);
			return true;
		}
		decode_ldst_long(insn, c6x_mem_rows[op].mnem, c6x_mem_rows[op].store);
		return true;
	}
	// .L 1-or-2-source: bits 4:2 == 110
	if (BITS(w, 4, 2) == 0x6) {
		// FP add/sub on .S issue in this same format; their opfields select
		// the .S unit, so match them before the .L table.
		const C6xRow *sf = row_find(c6x_s_fp_rows, RZ_ARRAY_SIZE(c6x_s_fp_rows), BITS(w, 11, 5), d);
		if (sf) {
			decode_3op(insn, sf);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		// MVK.L (LSDx1 overlay, C64x+): the ABS opfield 0x1a is reused for
		// a 5-bit signed constant move; ABS's unary form fixes src1 = 0,
		// so a src1 field of 0x05 means MVK instead.
		if (BITS(w, 11, 5) == 0x1a && BITS(w, 17, 13) == 0x05) {
			ut8 s = BIT(w, 1);
			insn->mnemonic = "mvk";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_L;
			insn->unit_side = s + 1;
			op_imm(&insn->ops[0], sext(BITS(w, 22, 18), 5));
			insn->ops[0].imm_dec = true;
			op_reg(&insn->ops[1], s, BITS(w, 27, 23));
			insn->nops = 2;
			return true;
		}
		// The ABS opfield also carries the C64x+ unary byte reshuffles, chosen
		// by src1; src1 == 0 is the ABS itself and falls through to the table.
		if (feat_ok(d, FEAT_SIMD) && BITS(w, 11, 5) == 0x1a) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_l_unary_rows); i++) {
				if (c6x_l_unary_rows[i].src1 != BITS(w, 17, 13)) {
					continue;
				}
				ut8 s = BIT(w, 1);
				ut8 x = BIT(w, 12);
				insn->mnemonic = c6x_l_unary_rows[i].mnem;
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_L;
				insn->unit_side = s + 1;
				insn->cross = x;
				op_reg(&insn->ops[0], x ? !s : s, BITS(w, 22, 18)); // src2
				op_reg(&insn->ops[1], s, BITS(w, 27, 23)); // dst
				insn->nops = 2;
				return true;
			}
		}
		const C6xRow *r = row_find(c6x_l_rows, RZ_ARRAY_SIZE(c6x_l_rows), BITS(w, 11, 5), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_L;
			return true;
		}
		return false;
	}
	// EXTU/EXT/SET/CLR, constant field form: bits 5:2 == 0010
	if (BITS(w, 5, 2) == 0x2) {
		return decode_field(insn);
	}
	// .D-unit extended logic/arith (C64x+): bits 5:2 == 1100, bits 11:10 == 10.
	if (BITS(w, 5, 2) == 0xc && BITS(w, 11, 10) == 0x2) {
		const C6xRow *r = row_find(c6x_d_ext_rows, RZ_ARRAY_SIZE(c6x_d_ext_rows), BITS(w, 9, 6), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
	}
	// Extended .M (C64x+): bits 5:2 == 1100 with bits 11:10 in {0,1}. The
	// unary moves/shuffles share the bits 9:6 == 3 slot and are told apart by
	// the src1 field; every other slot is a two-source (packed) multiply.
	if (feat_ok(d, FEAT_SIMD) && BITS(w, 5, 2) == 0xc && BITS(w, 11, 10) <= 1) {
		ut8 s = BIT(w, 1);
		ut8 x = BIT(w, 12);
		// C66x complex/matrix ops occupy this space with z = 1, creg = 0 (they
		// are always unconditional); that signature reserves the slot from the
		// C64x+ op below, which is either unconditional (z = 0) or predicated
		// (creg != 0).
		if (BITS(w, 31, 29) == 0 && BIT(w, 28) == 1) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_cplx_rows); i++) {
				const C6xMCplxRow *r = &c6x_m_cplx_rows[i];
				if (r->sub != BITS(w, 11, 10) || r->op != BITS(w, 9, 6) || !feat_ok(d, r->feat)) {
					continue;
				}
				insn->mnemonic = r->mnem;
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MUL;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s + 1;
				insn->cross = x;
				op_by_kind(&insn->ops[0], r->k1, s, BITS(w, 17, 13)); // src1
				op_by_kind(&insn->ops[1], r->k2, x ? !s : s, BITS(w, 22, 18)); // src2 (cross)
				op_by_kind(&insn->ops[2], r->k3, s, BITS(w, 27, 23)); // dst
				insn->nops = 3;
				return true;
			}
			return false;
		}
		if (BITS(w, 11, 10) == 0 && BITS(w, 9, 6) == 3) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_unary_rows); i++) {
				if (c6x_m_unary_rows[i].src1 != BITS(w, 17, 13)) {
					continue;
				}
				insn->mnemonic = c6x_m_unary_rows[i].mnem;
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s + 1;
				insn->cross = x;
				op_reg(&insn->ops[0], x ? !s : s, BITS(w, 22, 18)); // src2
				op_reg(&insn->ops[1], s, BITS(w, 27, 23)); // dst
				insn->nops = 2;
				return true;
			}
			return false;
		}
		for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_ext_rows); i++) {
			const C6xMExtRow *r = &c6x_m_ext_rows[i];
			if (r->sub != BITS(w, 11, 10) || r->op != BITS(w, 9, 6) || !feat_ok(d, r->feat)) {
				continue;
			}
			insn->mnemonic = r->mnem;
			insn->op_type = r->type;
			insn->is_fp = r->feat == FEAT_FP;
			insn->unit = C6X_UNIT_M;
			insn->unit_side = s + 1;
			insn->cross = x;
			// the x bit normally crosses src2; mpyspdp crosses src1 (the SP
			// value) instead, its DP-pair src2 staying on the unit side
			ut8 src1_side = r->src1_cross && x ? !s : s;
			ut8 src2_side = !r->src1_cross && x ? !s : s;
			if (r->swap) {
				// reversed syntax (src2, src1, dst): the shift-count and
				// rotate ops print the value (src2) before the amount (src1)
				op_reg(&insn->ops[0], src2_side, BITS(w, 22, 18)); // src2
				op_reg(&insn->ops[1], src1_side, BITS(w, 17, 13)); // src1
			} else {
				op_reg(&insn->ops[0], src1_side, BITS(w, 17, 13)); // src1
				if (r->src2_pair) {
					op_regpair(&insn->ops[1], src2_side, BITS(w, 22, 18));
				} else {
					op_reg(&insn->ops[1], src2_side, BITS(w, 22, 18));
				}
			}
			if (r->dst_pair) {
				op_regpair(&insn->ops[2], s, BITS(w, 27, 23));
			} else {
				op_reg(&insn->ops[2], s, BITS(w, 27, 23));
			}
			insn->nops = 3;
			return true;
		}
		return false;
	}
	// Extended .S (C64x+): bits 5:2 == 1100, bits 11:10 == 11. Packed shifts,
	// saturating add/pack and andn share this space, keyed by bits 9:6.
	if (feat_ok(d, FEAT_SIMD) && BITS(w, 5, 2) == 0xc && BITS(w, 11, 10) == 0x3) {
		for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_s_ext_rows); i++) {
			if (c6x_s_ext_rows[i].op != BITS(w, 9, 6)) {
				continue;
			}
			ut8 s = BIT(w, 1);
			ut8 x = BIT(w, 12);
			ut8 src2_side = x ? !s : s;
			insn->mnemonic = c6x_s_ext_rows[i].mnem;
			insn->op_type = c6x_s_ext_rows[i].type;
			insn->unit = C6X_UNIT_S;
			insn->unit_side = s + 1;
			insn->cross = x;
			if (c6x_s_ext_rows[i].swap) {
				// packed shifts print value (src2) then count (src1)
				op_reg(&insn->ops[0], src2_side, BITS(w, 22, 18));
				op_reg(&insn->ops[1], s, BITS(w, 17, 13));
			} else {
				op_reg(&insn->ops[0], s, BITS(w, 17, 13)); // src1
				op_reg(&insn->ops[1], src2_side, BITS(w, 22, 18)); // src2
			}
			op_reg(&insn->ops[2], s, BITS(w, 27, 23)); // dst
			insn->nops = 3;
			return true;
		}
		return false;
	}
	// .D extended logical/arith (C64x+): bits 5:2 == 1100, bits 11:10 == 10
	if (BITS(w, 5, 2) == 0xc && BITS(w, 11, 10) == 0x2) {
		const C6xRow *r = row_find(c6x_dext_rows, RZ_ARRAY_SIZE(c6x_dext_rows), BITS(w, 9, 6), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
		return false;
	}
	// remaining formats have bits 4:2 == 000, 100 or 010; refine by higher bits
	ut8 sig = BITS(w, 6, 2);
	if (sig == 0x00) { // .M unit
		// C66x quad/matrix multiplies share this format but are unconditional
		// with z = 1, creg = 0 -- that reserves the slot from the z = 0 scalar
		// multiply at the same opcode.
		if (BITS(w, 31, 29) == 0 && BIT(w, 28) == 1 && feat_ok(d, FEAT_C66X)) {
			for (size_t i = 0; i < RZ_ARRAY_SIZE(c6x_m_wide_rows); i++) {
				const C6xMWideRow *r = &c6x_m_wide_rows[i];
				if (r->op != BITS(w, 11, 7)) {
					continue;
				}
				ut8 s = BIT(w, 1);
				insn->mnemonic = r->mnem;
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MUL;
				insn->unit = C6X_UNIT_M;
				insn->unit_side = s + 1;
				// cmatmpy swaps the src1/src2 register fields
				ut8 f1 = r->swap ? BITS(w, 22, 18) : BITS(w, 17, 13);
				ut8 f2 = r->swap ? BITS(w, 17, 13) : BITS(w, 22, 18);
				op_by_kind(&insn->ops[0], r->k1, s, f1);
				op_by_kind(&insn->ops[1], r->k2, s, f2);
				op_by_kind(&insn->ops[2], r->k3, s, BITS(w, 27, 23));
				insn->nops = 3;
				return true;
			}
			return false;
		}
		const C6xRow *r = row_find(c6x_m_rows, RZ_ARRAY_SIZE(c6x_m_rows), BITS(w, 11, 7), d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_M;
			return true;
		}
		return false;
	}
	if (sig == 0x10) { // .D arithmetic/address
		// MVK on the .D unit (C64x+) reuses the op-0 slot: a 5-bit signed
		// constant move, dst on side s. cst5 sits at bits 17:13.
		if (BITS(w, 12, 7) == 0x0) {
			ut8 s = BIT(w, 1);
			insn->mnemonic = "mvk";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_D;
			insn->unit_side = s + 1;
			op_imm(&insn->ops[0], sext(BITS(w, 17, 13), 5));
			insn->ops[0].imm_dec = true;
			op_reg(&insn->ops[1], s, BITS(w, 27, 23));
			insn->nops = 2;
			return true;
		}
		const C6xRow *r = row_find(c6x_d_rows, RZ_ARRAY_SIZE(c6x_d_rows), BITS(w, 12, 7), d);
		if (r) {
			decode_darith(insn, r);
			insn->unit = C6X_UNIT_D;
			return true;
		}
		return false;
	}
	if (BITS(w, 5, 2) == 0x8) { // .S 1-or-2-source (6-bit op)
		ut16 sop = BITS(w, 11, 6);
		if (sop == 0x0d) { // B src2: register branch (.S2 only)
			decode_branch_reg(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == 0x04) { // BNOP with a displacement (Figure F-10)
			decode_branch_nop(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == 0x0e || sop == 0x0f) { // MVC (control-register move)
			return decode_mvc(insn);
		}
		if (sop == 0x05) { // ADDKPC (.S2, C64x+): PC-relative address form
			decode_addkpc(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == 0x00) { // BDEC/BPOS (C64x+): register-conditional loop branch
			decode_bdec(insn);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		if (sop == 0x03) { // B IRP/NRP (.S2): return from a (non)maskable interrupt
			ut8 n = BITS(w, 15, 13);
			insn->mnemonic = n ? "bnop" : "b";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
			insn->unit_side = 2;
			op_ctrlreg(&insn->ops[0], ctrlreg_name(BITS(w, 22, 18), true));
			insn->nops = 1;
			if (n) {
				op_imm(&insn->ops[insn->nops++], n);
			}
			insn->unit = C6X_UNIT_S;
			return true;
		}
		const C6xRow *r = row_find(c6x_s_rows, RZ_ARRAY_SIZE(c6x_s_rows), sop, d);
		if (r) {
			decode_3op(insn, r);
			insn->unit = C6X_UNIT_S;
			return true;
		}
		return false;
	}
	if (sig == 0x04) { // .S branch immediate
		decode_branch(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	if (sig == 0x14) { // .S ADDK
		decode_addk(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	if (BITS(w, 5, 2) == 0xa) { // .S MVK/MVKH (bit6 = h)
		decode_mvk(insn);
		insn->unit = C6X_UNIT_S;
		return true;
	}
	return false;
}

// Map a 3-bit compact register field to a register operand. The header RS bit
// selects the low (A0-A7 / B0-B7) or high (A16-A23 / B16-B23) register set.
static void compact_reg(C6xOperand *o, ut8 field, ut8 side, bool rs) {
	op_reg(o, side, (rs ? 16 : 0) + (field & 0x7));
}

// The .L L3i short constant (SPRUFE8 Figure D-5): sn:cst3 encode a 5-bit signed
// value where cst3 == 0 means +-8 rather than 0.
static st64 l3i_const(ut8 sn, ut8 cst3) {
	ut8 raw = (sn << 3) | cst3;
	return raw == 0 ? 8 : (raw < 8 ? (st64)raw : (st64)raw - 16);
}

// Decode a 16-bit compact instruction (SPRUFE8 3.10, Appendices D and G). \p rs
// and \p sat come from the fetch-packet header expansion field. Only the common
// subset is handled (NOP; MV; predicated MVK; and the .L ALU/compare/MVK forms);
// unhandled encodings leave the mnemonic NULL but keep the 2-byte size so the
// packet stays aligned. bit 0 is the side selector (s); the parallel bit comes
// from the header p-bits and is set by the caller.
static void decode_compact(C6xInsn *insn, ut16 w, bool rs, bool sat, ut8 dsz, bool br) {
	insn->size = 2;
	ut8 s = w & 1; // 0 = A side (.x1), 1 = B side (.x2)
	insn->unit_side = s + 1;

	// no-unit NOP: 13 fixed low bits, (count - 1) in bits 15:13.
	if ((w & 0x1fff) == 0x0c6e) {
		insn->mnemonic = "nop";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		insn->unit_side = 0;
		op_imm(&insn->ops[0], ((w >> 13) & 0x7) + 1);
		insn->nops = 1;
		return;
	}

	if ((w & 0x6) == 0x6) {
		// Shared .L/.S/.D forms (Appendix G): bits 2:1 == 11, unit at bits 4:3.
		ut8 unit_f = (w >> 3) & 0x3;
		C6xUnit unit = unit_f == 0 ? C6X_UNIT_L : unit_f == 1 ? C6X_UNIT_S
			: unit_f == 2                                 ? C6X_UNIT_D
								      : C6X_UNIT_NONE;
		ut8 b5 = (w >> 5) & 1, b6 = (w >> 6) & 1;
		ut8 b10 = (w >> 10) & 1, b11 = (w >> 11) & 1, b12 = (w >> 12) & 1;
		ut8 x = b12;
		if (unit == C6X_UNIT_D && b5 == 1 && b6 == 1 && b11 == 0) {
			// Dpp (Figure C-21): B15 stack load/store, word or doubleword.
			// The pointer is always B15; stores post-decrement and loads
			// pre-increment by ucst2. src/dst is a full 4-bit register on the
			// side named by t (bit 12); the RS header bit does not apply here.
			bool dw = (w >> 15) & 1;
			bool ld = (w >> 14) & 1;
			ut8 t = (w >> 12) & 1;
			ut8 rnum = (w >> 7) & 0xf;
			insn->mnemonic = dw ? (ld ? "lddw" : "stdw") : (ld ? "ldw" : "stw");
			insn->op_type = ld ? RZ_ANALYSIS_OP_TYPE_LOAD : RZ_ANALYSIS_OP_TYPE_STORE;
			insn->unit = C6X_UNIT_D;
			C6xOperand mem = { 0 };
			mem.kind = C6X_OP_MEM;
			mem.base = 15;
			mem.base_side = 1; // B15
			mem.scaled = true;
			mem.mode = ld ? C6X_AM_PREINC_CST : C6X_AM_POSTDEC_CST;
			mem.off_cst = ((w >> 13) & 1) + 1; // ucst2 = ucst0 + 1
			C6xOperand reg = { 0 };
			if (dw) {
				op_regpair(&reg, t, rnum);
			} else {
				op_reg(&reg, t, rnum);
			}
			insn->ops[0] = ld ? mem : reg;
			insn->ops[1] = ld ? reg : mem;
			insn->nops = 2;
			return;
		}
		if (b5 == 0) { // G-1 / G-2: MV (mvto has bit6 = 0, mvfr has bit6 = 1)
			insn->mnemonic = "mv";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = unit;
			insn->cross = x;
			compact_reg(&insn->ops[0], (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&insn->ops[1], (w >> 13) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (b6 == 1 && b12 == 0 && b11 == 1 && b10 == 0) { // G-3: predicated MVK ucst1
			ut8 cc = (w >> 14) & 0x3;
			insn->mnemonic = "mvk";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = unit;
			insn->creg = (cc & 2) ? 0x1 : 0x6; // 10x -> B0, 0x -> A0
			insn->z = cc & 1; // odd CC is the negated ([!A0]/[!B0]) sense
			op_imm(&insn->ops[0], (w >> 13) & 0x1); // ucst1
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (unit == C6X_UNIT_L && b6 == 0 && b5 == 1 && b10 == 1) { // Lx5: MVK scst5 (.L)
			insn->mnemonic = "mvk";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_L;
			ut8 scst5 = (((w >> 11) & 0x3) << 3) | ((w >> 13) & 0x7);
			op_imm(&insn->ops[0], sext(scst5, 5));
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (unit == C6X_UNIT_L && b6 == 0 && b5 == 1 && b10 == 0) {
			// Lx3c/Lx1c: .L compare against a small constant. bit 12 == 0 is
			// CMPEQ with a ucst3 (Lx3c); bit 12 == 1 selects CMPLT/CMPGT/
			// CMPLTU/CMPGTU with a ucst1 (Lx1c). dst is A0/A1 or B0/B1.
			ut8 dstlo = (w >> 11) & 1;
			insn->unit = C6X_UNIT_L;
			if (b12 == 0) {
				insn->mnemonic = "cmpeq";
				op_imm(&insn->ops[0], (w >> 13) & 0x7); // ucst3
			} else {
				static const char *const mn[4] = { "cmplt", "cmpgt", "cmpltu", "cmpgtu" };
				insn->mnemonic = mn[(w >> 14) & 0x3];
				op_imm(&insn->ops[0], (w >> 13) & 0x1); // ucst1
			}
			insn->op_type = RZ_ANALYSIS_OP_TYPE_CMP;
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, s, rs); // src2
			op_reg(&insn->ops[2], s, dstlo); // dst A0/A1 or B0/B1
			insn->nops = 3;
			return;
		}
		if (b6 == 1 && b5 == 1 && b12 == 1 && b11 == 1 && b10 == 0) {
			// G-4 LSDx1: op field selects MVK 0/1 or ADD/XOR src,1 (src == dst).
			ut8 op = (w >> 13) & 0x7;
			if (op < 2) { // MVK 0 or MVK 1
				insn->mnemonic = "mvk";
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = unit;
				op_imm(&insn->ops[0], op);
				compact_reg(&insn->ops[1], (w >> 7) & 0x7, s, rs);
				insn->nops = 2;
				return;
			}
			if (op == 5 || op == 7) { // ADD src,1,dst or XOR src,1,dst
				insn->mnemonic = op == 5 ? "add" : "xor";
				insn->op_type = op == 5 ? RZ_ANALYSIS_OP_TYPE_ADD : RZ_ANALYSIS_OP_TYPE_XOR;
				insn->unit = unit;
				compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src (== dst)
				op_imm(&insn->ops[1], 1);
				compact_reg(&insn->ops[2], (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (unit == C6X_UNIT_S && op == 6) {
				// Sx1: MVC src, ILC -- move a general register into the
				// inner-loop-count control register (encoded with s = 1).
				insn->mnemonic = "mvc";
				insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
				insn->unit = C6X_UNIT_S;
				compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src
				op_ctrlreg(&insn->ops[1], "ilc");
				insn->nops = 2;
				return;
			}
			return; // remaining op 2/3/4 per-unit Dx1/Lx1/Sx1 forms not decoded
		}
		if (unit == C6X_UNIT_S && b6 == 1 && b5 == 1 && b12 == 0 && b11 == 0) {
			// Sx1b: BNOP src2, N3 -- a branch to a B-side register (B0-B15).
			// This is the C64x+ compact form of the ABI return B .S2 B3; the
			// encoding is always BNOP, even when the NOP count is zero.
			ut8 n3 = (w >> 13) & 0x7;
			insn->mnemonic = "bnop";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_RJMP;
			insn->unit = C6X_UNIT_S;
			op_reg(&insn->ops[0], 1, (w >> 7) & 0xf); // src2 on the B side
			op_imm(&insn->ops[1], n3);
			insn->nops = 2;
			return;
		}
		return; // other shared forms not decoded yet
	}

	if ((w & 0x6) == 0x0) {
		// .L-only forms (Appendix D): bits 2:1 == 00, distinguished by bits 3,10.
		ut8 b3 = (w >> 3) & 1, b10 = (w >> 10) & 1, x = (w >> 12) & 1;
		insn->unit = C6X_UNIT_L;
		insn->cross = x;
		if (b3 == 0 && b10 == 0) { // L3: ADD/SUB (+ SADD/SSUB under header SAT)
			ut8 op = (w >> 11) & 1;
			insn->mnemonic = op ? (sat ? "ssub" : "sub") : (sat ? "sadd" : "add");
			insn->op_type = op ? RZ_ANALYSIS_OP_TYPE_SUB : RZ_ANALYSIS_OP_TYPE_ADD;
			compact_reg(&insn->ops[0], (w >> 13) & 0x7, s, rs); // src1
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&insn->ops[2], (w >> 4) & 0x7, s, rs); // dst
			insn->nops = 3;
			return;
		}
		if (b3 == 0 && b10 == 1) { // L3i: ADD scst5, src2, dst
			insn->mnemonic = "add";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_ADD;
			op_imm(&insn->ops[0], l3i_const((w >> 11) & 1, (w >> 13) & 0x7));
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, x ? !s : s, rs); // src2
			compact_reg(&insn->ops[2], (w >> 4) & 0x7, s, rs); // dst
			insn->nops = 3;
			return;
		}
		if (b3 == 1 && b10 == 1) { // L2c: AND/OR/XOR/CMPEQ/CMPLT/CMPGT(U)
			static const char *ops[8] = { "and", "or", "xor", "cmpeq",
				"cmplt", "cmpgt", "cmpltu", "cmpgtu" };
			static const _RzAnalysisOpType types[8] = { RZ_ANALYSIS_OP_TYPE_AND,
				RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_XOR,
				RZ_ANALYSIS_OP_TYPE_CMP, RZ_ANALYSIS_OP_TYPE_CMP,
				RZ_ANALYSIS_OP_TYPE_CMP, RZ_ANALYSIS_OP_TYPE_CMP,
				RZ_ANALYSIS_OP_TYPE_CMP };
			ut8 op = ((w >> 11) & 1) << 2 | ((w >> 5) & 0x3); // op2 : op1-0
			insn->mnemonic = ops[op];
			insn->op_type = types[op];
			compact_reg(&insn->ops[0], (w >> 13) & 0x7, s, rs); // src1
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, x ? !s : s, rs); // src2
			op_reg(&insn->ops[2], s, (w >> 4) & 0x1); // dst: A0/A1 or B0/B1
			insn->nops = 3;
			return;
		}
		return; // Ltbd and other .L forms not decoded yet
	}
	if ((w & 0x6) == 0x4) {
		// .D-unit loads/stores (Appendix C): bits 2:1 == 10. Data size comes
		// from the header DSZ combined with the opcode sz bit; the addressing
		// form (offset const, offset reg, post-inc, pre-dec) from bits 11:10.
		ut8 t = (w >> 12) & 1; // T datapath (data register) side
		ut8 sz = (w >> 9) & 1;
		bool ld = (w >> 3) & 1;
		ut8 prim = (dsz >> 2) & 1, sec = dsz & 0x3;
		const char *mn;
		bool dwpair = false;
		if (sz == 0 && prim == 1) {
			// Doubleword-primary access (Doff4DW/DindDW/DincDW/DdecDW): the
			// register is an even pair encoded at bits 6:5, and na (bit 4)
			// selects aligned (DW) versus nonaligned (NDW).
			ut8 na = (w >> 4) & 1;
			mn = na ? (ld ? "ldndw" : "stndw") : (ld ? "lddw" : "stdw");
			dwpair = true;
		} else if (sz == 0) {
			mn = ld ? "ldw" : "stw"; // word-primary access
		} else if (prim == 0) { // word-primary packet: secondary byte/half sizes
			static const char *l[4] = { "ldbu", "ldb", "ldhu", "ldh" };
			static const char *st[4] = { "stb", "stb", "sth", "sth" };
			mn = ld ? l[sec] : st[sec];
		} else { // doubleword-primary packet: secondary word/byte/half sizes
			static const char *l[4] = { "ldw", "ldb", "ldnw", "ldh" };
			static const char *st[4] = { "stw", "stb", "stnw", "sth" };
			mn = ld ? l[sec] : st[sec];
		}
		insn->mnemonic = mn;
		insn->op_type = ld ? RZ_ANALYSIS_OP_TYPE_LOAD : RZ_ANALYSIS_OP_TYPE_STORE;
		insn->unit = C6X_UNIT_D;
		C6xOperand mem = { 0 };
		mem.kind = C6X_OP_MEM;
		mem.base = (rs ? 16 : 0) + 4 + ((w >> 7) & 0x3); // pointer is R4-R7
		mem.base_side = s;
		mem.scaled = true;
		ut8 b11 = (w >> 11) & 1, b10 = (w >> 10) & 1;
		if (b10 == 0) { // Doff4: *+ptr[ucst4]
			mem.mode = C6X_AM_POS_CST;
			mem.off_cst = (b11 << 3) | ((w >> 13) & 0x7);
		} else if (b11 == 0) { // Dind: *+ptr[src1]
			mem.mode = C6X_AM_POS_REG;
			mem.off_reg = (rs ? 16 : 0) + ((w >> 13) & 0x7);
		} else if (((w >> 14) & 0x3) == 0) { // Dinc: *ptr++[ucst2]
			mem.mode = C6X_AM_POSTINC_CST;
			mem.off_cst = ((w >> 13) & 1) + 1;
		} else { // Ddec: *--ptr[ucst2]
			mem.mode = C6X_AM_PREDEC_CST;
			mem.off_cst = ((w >> 13) & 1) + 1;
		}
		C6xOperand reg = { 0 };
		if (dwpair) {
			// even register pair, address formed as op6:op5:0
			op_regpair(&reg, t, (rs ? 16 : 0) + (((w >> 5) & 0x3) << 1));
		} else {
			op_reg(&reg, t, (rs ? 16 : 0) + ((w >> 4) & 0x7));
		}
		insn->ops[0] = ld ? mem : reg; // loads: *mem, dst; stores: src, *mem
		insn->ops[1] = ld ? reg : mem;
		insn->nops = 2;
		return;
	}
	if ((w & 0x6) == 0x2) {
		// .S-unit compact formats (Appendix F): bits 2:1 == 01. Under a header
		// BR bit the bit-3 forms are branches; otherwise they are ALU/shift ops
		// (still to do). The MVK form (Smvk8) is BR-independent.
		if (((w >> 4) & 1) && !((w >> 3) & 1)) {
			// Smvk8 MVK: ucst8 is scattered across the word.
			ut16 imm = ((w >> 13) & 0x7) | (((w >> 11) & 0x3) << 3) |
				(((w >> 5) & 0x3) << 5) | (((w >> 10) & 0x1) << 7);
			insn->mnemonic = "mvk";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_MOV;
			insn->unit = C6X_UNIT_S;
			op_imm(&insn->ops[0], imm);
			compact_reg(&insn->ops[1], (w >> 7) & 0x7, s, rs); // dst
			insn->nops = 2;
			return;
		}
		if (!((w >> 3) & 1) && !((w >> 4) & 1)) {
			// .S ALU: shifts (Ssh5/S2sh, bit 10 == 1) and field operations
			// (Sc5/S2ext, bit 10 == 0). The op at bits 6:5 selects the form;
			// op == 3 escapes to the register-count (S2sh) or fixed-width
			// (S2ext) variant, which carries its own op at bits 12:11.
			insn->unit = C6X_UNIT_S;
			ut8 b10 = (w >> 10) & 1;
			ut8 op = (w >> 5) & 0x3;
			ut8 ucst5 = (((w >> 11) & 0x3) << 3) | ((w >> 13) & 0x7);
			if (b10 && op != 3) { // Ssh5: SHL/SHR/SHRU (SSHL when header SAT)
				static const char *const mn[3] = { "shl", "shr", "shru" };
				insn->mnemonic = (op == 2 && sat) ? "sshl" : mn[op];
				insn->op_type = op ? RZ_ANALYSIS_OP_TYPE_SHR : RZ_ANALYSIS_OP_TYPE_SHL;
				compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src2 (= dst)
				op_imm(&insn->ops[1], ucst5);
				compact_reg(&insn->ops[2], (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (b10) { // S2sh: register-count shift, src1 (count) at bits 15:13
				static const char *const mn[4] = { "shl", "shr", "shru", "sshl" };
				ut8 op2 = (w >> 11) & 0x3;
				insn->mnemonic = mn[op2];
				insn->op_type = op2 == 1 ? RZ_ANALYSIS_OP_TYPE_SHR : RZ_ANALYSIS_OP_TYPE_SHL;
				compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src2 (= dst)
				compact_reg(&insn->ops[1], (w >> 13) & 0x7, s, rs); // src1 (count)
				compact_reg(&insn->ops[2], (w >> 7) & 0x7, s, rs); // dst
				insn->nops = 3;
				return;
			}
			if (op != 3) { // Sc5: EXTU/SET/CLR with a ucst5 field (dst is A0/B0)
				static const char *const mn[3] = { "extu", "set", "clr" };
				static const _RzAnalysisOpType ty[3] = { RZ_ANALYSIS_OP_TYPE_SHR,
					RZ_ANALYSIS_OP_TYPE_OR, RZ_ANALYSIS_OP_TYPE_AND };
				insn->mnemonic = mn[op];
				insn->op_type = ty[op];
				compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src2
				op_imm(&insn->ops[1], ucst5);
				op_imm(&insn->ops[2], op == 0 ? 31 : ucst5); // EXTU pairs with 31
				op_reg(&insn->ops[3], s, 0); // dst A0/B0
				insn->nops = 4;
				return;
			}
			// S2ext: EXT/EXTU with a fixed 16- or 24-bit field width.
			static const char *const mn[4] = { "ext", "ext", "extu", "extu" };
			ut8 op2 = (w >> 11) & 0x3;
			ut8 width = (op2 & 1) ? 24 : 16;
			insn->mnemonic = mn[op2];
			insn->op_type = RZ_ANALYSIS_OP_TYPE_SHR;
			compact_reg(&insn->ops[0], (w >> 7) & 0x7, s, rs); // src2
			op_imm(&insn->ops[1], width);
			op_imm(&insn->ops[2], width);
			compact_reg(&insn->ops[3], (w >> 13) & 0x7, s, rs); // dst
			insn->nops = 4;
			return;
		}
		if (br && ((w >> 3) & 1)) {
			// Branch forms (Sbs7/Sbu8/Scs10 and their conditional variants). The
			// displacement is packet-relative and scaled to the 16-bit slot, so
			// the analysis filler resolves it against the fetch-packet base.
			insn->unit = C6X_UNIT_S;
			ut8 b4 = (w >> 4) & 1, b5 = (w >> 5) & 1;
			if (b5 == 0 && b4 == 1) { // Scs10: CALLP scst10, 5
				insn->mnemonic = "callp";
				insn->op_type = RZ_ANALYSIS_OP_TYPE_CALL;
				insn->ops[0].kind = C6X_OP_PCREL;
				insn->ops[0].imm = sext((w >> 6) & 0x3ff, 10) * 2;
				insn->nops = 1;
				return;
			}
			bool wide = ((w >> 14) & 0x3) == 0x3; // Sbu8/Sbu8c use an 8-bit ucst
			st64 disp = wide ? (st64)(((w >> 6) & 0xff) * 2) // ucst8 (unsigned)
					 : sext((w >> 6) & 0x7f, 7) * 2; // scst7 (signed)
			ut8 n3 = wide ? 5 : ((w >> 13) & 0x7); // NOP count (Sbu8 implies 5)
			if (b5) { // conditional variants carry a predicate in s and bit 4
				insn->creg = (w & 1) ? 0x1 : 0x6; // s selects B0 / A0
				insn->z = b4; // bit 4 is the z (negate) sense
			}
			insn->mnemonic = "bnop";
			insn->op_type = RZ_ANALYSIS_OP_TYPE_JMP;
			insn->ops[0].kind = C6X_OP_PCREL;
			insn->ops[0].imm = disp;
			op_imm(&insn->ops[1], n3);
			insn->nops = 2;
			return;
		}
		return;
	}
}

RZ_IPI bool c6x_decode(const C6xArchDesc *desc, const ut8 *buf, int len, ut64 pc, bool big_endian, RZ_OUT C6xInsn *insn) {
	rz_return_val_if_fail(desc && buf && insn, false);
	if (len < 2) {
		return false;
	}
	memset(insn, 0, sizeof(*insn));
	// C64x+ compact fetch packets (SPRUFE8 3.10): the eighth word of a 32-byte
	// fetch packet is a header (top nibble 1110) whose layout field marks which
	// of the other seven words hold two 16-bit compact instructions. Look for
	// that header ahead of the current word; if this slot is compact, decode a
	// 16-bit instruction and take the parallel bit from the header p-bit field.
	// Only families with the compact set are probed, so C62x/C67x are untouched;
	// when the header is not reachable (an isolated single-word decode) the
	// 32-bit path runs and still recognises a header word on its own.
	if (desc->has_simd) {
		ut32 fp_off = (ut32)(pc & 0x1f);
		int hdr_off = 0x1c - (int)fp_off; // header lives at packet offset 0x1c
		if (fp_off < 0x1c && hdr_off + 4 <= len) {
			ut32 hdr = big_endian ? rz_read_be32(buf + hdr_off) : rz_read_le32(buf + hdr_off);
			ut8 slot = fp_off >> 2;
			if ((hdr >> 28) == 0xe && ((hdr >> (21 + slot)) & 1)) {
				ut16 w16 = big_endian ? rz_read_be16(buf) : rz_read_le16(buf);
				ut8 half = (fp_off >> 1) & 1;
				insn->word = w16;
				insn->parallel = (hdr >> (slot * 2 + half)) & 1;
				decode_compact(insn, w16, (hdr >> 19) & 1, (hdr >> 14) & 1,
					(hdr >> 16) & 0x7, (hdr >> 15) & 1);
				return true;
			}
		}
	}
	if (len < 4) {
		return false;
	}
	insn->word = big_endian ? rz_read_be32(buf) : rz_read_le32(buf);
	insn->size = 4;
	ut32 w = insn->word;
	// A C64x+ compact fetch packet replaces its eighth word with a header
	// (SPRUFE8 3.10.2): top nibble 1110, i.e. creg=111/z=0, which is the
	// reserved predicate no real instruction uses. The header repacks the
	// other slots as 16-bit compact instructions; decoding those is future
	// work, but the header itself is recognised so it is not mis-read as a
	// 32-bit opcode and to flag the packet as compact.
	if ((w >> 28) == 0xe) {
		insn->is_header = true;
		insn->mnemonic = ".fphead";
		insn->op_type = RZ_ANALYSIS_OP_TYPE_NULL;
		return true;
	}
	insn->parallel = BIT(w, 0) != 0;
	insn->creg = BITS(w, 31, 29);
	insn->z = BIT(w, 28);
	insn->op_type = RZ_ANALYSIS_OP_TYPE_ILL;
	if (decode_nounit(insn)) {
		return true;
	}
	if (!decode_unit(desc, insn)) {
		insn->mnemonic = NULL; // unrecognised, still 4 bytes
		insn->op_type = RZ_ANALYSIS_OP_TYPE_ILL;
	}
	return true;
}

static int c6x_mnem_cmp(const void *a, const void *b, RZ_UNUSED void *user) {
	return strcmp((const char *)a, (const char *)b);
}

RZ_IPI RZ_OWN RzPVector /*<const char *>*/ *c6x_mnemonics(void) {
	RzPVector *v = rz_pvector_new(NULL);
	if (!v) {
		return NULL;
	}
	// Each functional-unit table stores its printed mnemonic in a `mnem`
	// field; gather them all, then add the few the decoder emits directly
	// (loads, stores, moves, branches, the address-arithmetic forms and the
	// nop/idle family). Sorting and dropping duplicates leaves `rz-asm -e`
	// with one clean, stable entry per opcode. The strings are borrowed from
	// static storage, so the pvector owns no elements.
#define C6X_MNEMS(tbl) \
	do { \
		for (size_t i = 0; i < RZ_ARRAY_SIZE(tbl); i++) { \
			if ((tbl)[i].mnem) { \
				rz_pvector_push(v, (void *)(tbl)[i].mnem); \
			} \
		} \
	} while (0)
	C6X_MNEMS(c6x_l_rows);
	C6X_MNEMS(c6x_s_fp_rows);
	C6X_MNEMS(c6x_d_ext_rows);
	C6X_MNEMS(c6x_s_rows);
	C6X_MNEMS(c6x_m_rows);
	C6X_MNEMS(c6x_m_ext_rows);
	C6X_MNEMS(c6x_m_unary_rows);
	C6X_MNEMS(c6x_m_cplx_rows);
	C6X_MNEMS(c6x_m_wide_rows);
	C6X_MNEMS(c6x_s_ext_rows);
	C6X_MNEMS(c6x_l_unary_rows);
	C6X_MNEMS(c6x_d_rows);
	C6X_MNEMS(c6x_dext_rows);
	C6X_MNEMS(c6x_mem_rows);
#undef C6X_MNEMS
	static const char *synthesized[] = {
		"add", "addaw", "addk", "addkpc", "b", "bdec", "bnop", "bpos",
		"callp", "cmpeq", "idle", "lddw", "ldndw", "ldnw", "ldw", "mv",
		"mvc", "mvk", "mvkh", "neg", "nop", "not", "sadd", "sshl",
		"ssub", "stdw", "stndw", "stnw", "stw", "sub", "xor", "zero"
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(synthesized); i++) {
		rz_pvector_push(v, (void *)synthesized[i]);
	}
	rz_pvector_sort(v, c6x_mnem_cmp, NULL);
	for (size_t i = 1; i < rz_pvector_len(v);) {
		if (!strcmp((const char *)rz_pvector_at(v, i - 1), (const char *)rz_pvector_at(v, i))) {
			rz_pvector_remove_at(v, i);
		} else {
			i++;
		}
	}
	return v;
}
