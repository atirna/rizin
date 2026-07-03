// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_C6X_H
#define RZ_TMS320_C6X_H

#include <rz_types.h>
#include <rz_analysis.h> // RzAnalysisOp, _RzAnalysisOpType

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * Shared decode/format core for the TMS320C6000 VLIW DSP family (C62x / C64x /
 * C64x+ / C67x / C67x+ / C674x / C66x).
 *
 * Every C6000 generation shares one instruction container: a 32-bit opcode with
 * a fixed low-bit frame (bit 0 = parallel, bit 1 = dst side, bits 31:28 = the
 * creg/z predicate) and a functional-unit-selected body. The families differ
 * only in *which* opcodes decode -- C67x adds the floating-point set on top of
 * the C62x fixed-point base, C64x adds the SIMD/packed set, C66x adds more --
 * so a single decode engine driven by one instruction table plus a per-variant
 * \ref C6xArchDesc feature gate covers them all, mirroring how the C55 engine
 * serves C54x/C55x/C55x+.
 *
 * The decoder (c6x_decode()) runs once and fills a \ref C6xInsn; two pure
 * consumers read it and never re-parse: c6x_format() (asm string) and
 * c6x_fill_analysis() (RzAnalysisOp). RzIL uplifting is a planned third
 * consumer and attaches the same way.
 */

/** Family member; gates variant-specific opcodes and register width. */
typedef enum {
	C6X_GEN_C62X = 0, ///< TMS320C62x (fixed-point base, 16+16 registers)
	C6X_GEN_C67X, ///< TMS320C67x/C67x+ (adds floating-point)
	C6X_GEN_C64X, ///< TMS320C64x/C64x+ (adds SIMD, 32+32 registers)
	C6X_GEN_C674X, ///< TMS320C674x (unified C64x+ and C67x+)
	C6X_GEN_C66X, ///< TMS320C66x (adds 4x SIMD / complex arithmetic)
} C6xGen;

/** Functional unit an instruction issues on. */
typedef enum {
	C6X_UNIT_NONE = 0, ///< no unit (NOP, IDLE, loop buffer, emulation)
	C6X_UNIT_L, ///< .L1 / .L2 (arithmetic, logical, compares)
	C6X_UNIT_S, ///< .S1 / .S2 (shifts, branches, moves, field ops)
	C6X_UNIT_M, ///< .M1 / .M2 (multiplies)
	C6X_UNIT_D, ///< .D1 / .D2 (loads, stores, address arithmetic)
} C6xUnit;

/** Data-memory addressing modes for .D loads/stores (Table 3-11). */
typedef enum {
	C6X_AM_NONE = 0,
	C6X_AM_NEG_CST, ///< *-R[ucst5]
	C6X_AM_POS_CST, ///< *+R[ucst5]
	C6X_AM_NEG_REG, ///< *-R[offsetR]
	C6X_AM_POS_REG, ///< *+R[offsetR]
	C6X_AM_PREDEC_CST, ///< *--R[ucst5]
	C6X_AM_PREINC_CST, ///< *++R[ucst5]
	C6X_AM_POSTDEC_CST, ///< *R--[ucst5]
	C6X_AM_POSTINC_CST, ///< *R++[ucst5]
	C6X_AM_PREDEC_REG, ///< *--R[offsetR]
	C6X_AM_PREINC_REG, ///< *++R[offsetR]
	C6X_AM_POSTDEC_REG, ///< *R--[offsetR]
	C6X_AM_POSTINC_REG, ///< *R++[offsetR]
	C6X_AM_BASE_LONG, ///< *+B14/B15[ucst15] long-immediate offset
} C6xAddrMode;

/** Operand kind within a decoded instruction. */
typedef enum {
	C6X_OP_NONE = 0,
	C6X_OP_REG, ///< general-purpose register (side + num)
	C6X_OP_REGPAIR, ///< register pair reg+1:reg (odd:even), 64-bit
	C6X_OP_REGQUAD, ///< register quad reg+3:reg+2:reg+1:reg (C66x 128-bit ops)
	C6X_OP_IMM, ///< immediate constant (signed value in \ref C6xOperand::imm)
	C6X_OP_CTRLREG, ///< control register named by \ref C6xOperand::name (MVC)
	C6X_OP_MEM, ///< *baseR addressing (see \ref C6xAddrMode)
	C6X_OP_PCREL, ///< PC-relative branch target (absolute address in imm)
} C6xOpKind;

/** One decoded operand. */
typedef struct {
	C6xOpKind kind;
	ut8 side; ///< register file: 0 = A, 1 = B
	ut8 num; ///< register number (low member of a pair)
	st64 imm; ///< immediate / displacement / absolute branch target
	bool imm_dec; ///< render imm in decimal (bit counts: csta/cstb)
	const char *name; ///< control-register name for C6X_OP_CTRLREG
	// memory operands (kind == C6X_OP_MEM)
	C6xAddrMode mode; ///< addressing mode
	ut8 base; ///< base register number
	ut8 base_side; ///< base register file (0 = A, 1 = B)
	ut8 off_reg; ///< register offset number (register-offset modes)
	ut32 off_cst; ///< constant offset (ucst5 / ucst15), unscaled
	bool scaled; ///< offset is scaled by the access size (bracket syntax)
} C6xOperand;

#define C6X_MAX_OPS 4

/** A fully decoded C6000 instruction. */
typedef struct {
	ut32 word; ///< raw 32-bit opcode (little-endian host value)
	ut32 size; ///< instruction size in bytes (always 4)
	const char *mnemonic; ///< base mnemonic ("add", "ldw", "mpysp", ...)
	C6xUnit unit; ///< functional unit
	ut8 unit_side; ///< 1 = .x1 unit (A datapath), 2 = .x2 unit (B datapath)
	bool cross; ///< src2 uses the register-file cross path (x bit)
	bool parallel; ///< p-bit: the *following* instruction runs in parallel
	bool cont; ///< this instruction continues the previous execute packet (renders "||")
	bool is_fp; ///< the operation is floating-point (selects the FPU family)
	ut8 creg; ///< predicate register code (bits 31:29); 0 = unconditional
	ut8 z; ///< predicate sense (bit 28): 0 = nonzero, 1 = zero
	_RzAnalysisOpType op_type; ///< analysis classification
	C6xOperand ops[C6X_MAX_OPS];
	ut8 nops; ///< number of valid operands
	bool is_header; ///< compact fetch-packet header word (renders as .fphead)
} C6xInsn;

/** Per-variant feature gate and register-set descriptor. */
typedef struct {
	C6xGen gen; ///< which family member
	ut8 num_regs; ///< registers per side (16 for C62x/C67x, 32 otherwise)
	bool has_fp; ///< floating-point set present (C67x/C674x/C66x)
	bool has_simd; ///< SIMD/packed set present (C64x/C674x/C66x)
} C6xArchDesc;

/** Ready-made descriptors, one per supported asm.cpu value. */
extern const C6xArchDesc c6x_desc_c62x;
extern const C6xArchDesc c6x_desc_c64x;
extern const C6xArchDesc c6x_desc_c67x;
extern const C6xArchDesc c6x_desc_c674x;
extern const C6xArchDesc c6x_desc_c66x;

/** Resolve an asm.cpu string to a descriptor, or NULL if not a C6000 cpu. */
RZ_IPI const C6xArchDesc *c6x_desc_from_cpu(const char *cpu);

/**
 * Decode one 32-bit C6000 opcode.
 * \param desc variant descriptor (feature gate)
 * \param buf input bytes (>= 4)
 * \param len available bytes
 * \param big_endian byte order of \p buf
 * \param insn output, filled on success
 * \return true if a 4-byte opcode was consumed (even when unrecognised, in
 *         which case \ref C6xInsn::mnemonic is NULL)
 */
RZ_IPI bool c6x_decode(const C6xArchDesc *desc, const ut8 *buf, int len, ut64 pc, bool big_endian, RZ_OUT C6xInsn *insn);

/**
 * \brief Flag whether \p insn continues the previous execute packet.
 *
 * TI marks an instruction with "||" when it runs in parallel with the one
 * before it, i.e. when the *previous* word set its parallel bit. Decoding is
 * stateless, so \p prev_end (address just past the last instruction) and
 * \p prev_par (its parallel bit) carry that one-word look-back across calls;
 * both are updated for the next call.
 */
RZ_IPI void c6x_mark_parallel(RZ_INOUT C6xInsn *insn, ut64 addr, RZ_INOUT ut64 *prev_end, RZ_INOUT bool *prev_par);

/** Render a decoded instruction to a newly allocated asm string. \p pc is the
 *  instruction address, used to resolve PC-relative branch targets. */
RZ_IPI RZ_OWN char *c6x_format(const C6xArchDesc *desc, const C6xInsn *insn, ut64 pc);

/** Fill an RzAnalysisOp from a decoded instruction (type, jump/fail, ...). */
RZ_IPI void c6x_fill_analysis(const C6xArchDesc *desc, const C6xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op);

/** RzIL configuration (register bindings, PC/memory widths) for the C6000 VM. */
RZ_IPI RzAnalysisILConfig *tms320_c6x_il_config(RZ_NONNULL RzAnalysis *analysis);

/** Lift a decoded instruction to RzIL, or NULL when the form is not yet lifted.
 *  \p pc is the instruction address (for PC-relative results). */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift(const C6xInsn *insn, ut64 pc);

#ifdef __cplusplus
}
#endif

#endif
