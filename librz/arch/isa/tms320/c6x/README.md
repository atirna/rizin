# TMS320C6000 (c6x) native engine

Native disassembler and analysis for the Texas Instruments TMS320C6000
VLIW DSP line, shared across the `c62x`, `c64x`, `c67x`, `c674x`, and
`c66x` cpus of the `tms320` arch plugin. It replaces the incomplete
Capstone-based C64x path with one code base for the whole family,
mirroring how the `c55`/`c54x` engines are laid out.

## Design

The engine is split into a single pure decoder and a set of stateless
consumers, so new output backends (RzIL, pseudo) can be added without
touching instruction decoding:

- `c6x_decode.c` -- turns a 32-bit word into a `C6xInsn` (unit, operands,
  predicate, parallel bit, analysis op-type). No allocation, no Rizin
  asm/analysis structures.
- `c6x_format.c` -- renders a `C6xInsn` to TI-style assembly text.
- `c6x_analysis.c` -- fills the control-flow fields of an `RzAnalysisOp`
  from a `C6xInsn`.
- `c6x.h` -- the shared `C6xInsn`/operand types and the per-cpu
  `C6xArchDesc` feature descriptors.

Each cpu is a `C6xArchDesc` carrying the register-file width and the
`has_fp` / `has_simd` feature gates. A single opcode table drives every
variant; rows tagged floating-point or SIMD only decode when the
selected cpu provides them, so `mpysp` disassembles on `c67x`/`c674x`
but is `invalid` on `c62x`.

### Instruction format

Every C6000 instruction is a fixed 32-bit little-endian word (the plugin
also honours `cfg.bigendian` for big-endian images). The low bits carry
the framing common to all formats:

- bit 0 `p` -- parallel bit. A run of instructions with `p = 1`
  terminated by `p = 0` forms one execute packet; the members run in
  parallel. Following TI/objdump, the `||` prefix marks every instruction
  after the first in a packet -- i.e. `this` instruction renders `||` when
  the **previous** word set its `p` bit. Decoding is stateless, so the
  disassembler and analysis plugins carry a one-word look-back (previous
  end address and its `p` bit) to reconstruct that; a fetch-packet header
  is transparent to the chain so an execute packet may span it.
- bit 1 `s` -- destination side / unit side (0 = A, 1 = B).
- bits 31:29 `creg`, bit 28 `z` -- predication (SPRU733 Table 3-9).
  `creg` names the guarding register (`B0..B2`, `A0..A2`); `z` selects
  test-nonzero (`[reg]`) vs test-zero (`[!reg]`).

The functional unit and operation are then recognised from each format's
fixed low-bit signature (`.L` `bits[4:2]==110`, `.S` 6-bit-op
`bits[5:2]==1000`, `.M` `bits[6:2]==00000`, `.D` arithmetic
`bits[6:2]==10000`, `.D` load/store `bits[3:2]==01`, `.D` long-immediate
load/store `bits[3:2]==11`, `.S` branch/ADDK/MVK, no-unit NOP), after
which the operand fields are sliced out and the op field matched in that
unit's table.


## Coverage

CPUs: `c62x`, `c64x`, `c64x+` (`c64xp`), `c67x`, `c674x`, `c66x`. The
register-file view (16 or 32 registers per side) and the control-register
set follow the selected cpu, and floating-point / C64x+ / C66x rows are
gated so an opcode is `invalid` on a cpu that lacks it.

Decoded (operands verified byte-exact against TI `dis6x` and hand-encoded
SPRU733/SPRUFE8 vectors), across the full instruction set:

- the `.L`/`.S`/`.D`/`.M` fixed-point ALU, packed-halfword/byte add and
  subtract, shifts, saturating add/sub, min/max, compares, `lmbd`, `norm`,
  and `abs` -- in register, constant, cross-path, and 40-bit-long forms;
- the `.M` multiply family: the 16x16 `mpy*`/`smpy*` set, 32x32
  `mpyi`/`mpyid`/`mpy32(u/su/us)`, the C64x+ packed and interpolated
  multiplies (`mpy2`/`smpy2`, `mpyhi`/`mpyli`, `mpyhir`/`mpylir`, the dot
  products), and the Galois `gmpy4`;
- `.D` address arithmetic and the load/store set (`ldb`..`ldw`, `lddw`,
  and the non-aligned/doubleword forms) in every addressing mode,
  including the `*+B14/B15[ucst15]` long-immediate and B15 stack forms;
- control transfer: PC-relative `b`, `bnop`, `callp`, `addkpc`,
  `bdec`/`bpos`, the register and interrupt-return branches, and the
  `B .S2 B3` ABI return -- with resolved, packet-relative targets;
- `mvc` control-register moves (named from the `crlo`/`crhi` field), the
  `ext`/`extu`/`set`/`clr` field ops, `mvk`/`mvkl`/`mvkh`/`mvd`, and the
  `mv`/`neg`/`not`/`zero` assembler idioms on every unit;
- single- and double-precision float: arithmetic (`addsp`..`mpydp`),
  conversions (`intsp`/`spint`/`sptrunc`/`intdp`/`spdp`/`dpint`/`dpsp`/`dptrunc`),
  compares, `abssp`/`absdp`, `mpyspdp`/`mpysp2dp`, and the `rsqrdp` estimate;
- the C64x+/C66x packed-SIMD and complex/matrix set (packs, unpacks,
  shuffles, `bitr`/`bitc4`/`deal`/`shfl`, the complex and quad multiplies),
  the software-pipelined loop-buffer ops (`sploop*`/`spmask`/`idle`), and
  the compact 16-bit fetch-packet header (`.fphead`) and every compact
  slot form.

Packet parallelism (`||`) is reconstructed from the `p` bit across the
stateless decode calls and matches TI/objdump address-by-address,
including across a fetch-packet header and in mixed compact/32-bit packets.

### RzIL

`c6x_il.c` lifts a decoded `C6xInsn` to RzIL, wired through `op->il_op`
with a per-cpu IL config (32-bit `pce1` PC, byte memory, the general
register file and the control registers `mvc` reaches). Every decoded
instruction that has data semantics is lifted: the integer ALU, shifts,
the full multiply set, packed-SIMD lanes, saturating and packed compares,
field ops, the loads/stores and doubleword pairs, and the control
transfers (predication wraps the effect in a branch on the guard
register). Floating point is lifted through the RzIL float ops --
single/double arithmetic, conversions, the ordered and equality compares,
and the mixed-precision `mpyspdp`/`mpysp2dp`. The 40-bit long `abs`, `sat`,
`norm`, compares and shift use a shared sign-extending pair reader and a
64-bit `clz`. Lifts are validated by `rz-asm -I` on each `d` line in the
c6x asm test databases and by stepping the RzIL VM.

Not lifted: `dint`/`rint` carry no data effect, and the hardware
reciprocal/reciprocal-root estimates (`rcpsp`/`rsqrsp`/`rcpdp`) and the
Galois `gmpy4`/`xormpy` reduction have no exact functional model. The five
branch delay slots are not modelled (as in Rizin's other delay-slot
lifters): the transfer is emitted directly, while `cont`/`parallel` and
`op->delay` carry what a delay-slot-aware pass would need.

### Calling convention and mnemonics

The C6000 EABI (SPRAB89) calling convention is registered for the C6000
cpus -- arguments in `A4`/`B4`/`A6`/`B6`/`A8`/`B8`/`A10`/`B10`/`A12`/`B12`
and the return value in `A4` -- and made the analysis default whenever a
c6x cpu is selected (a C5000 cpu restores the `c55x` convention), so
`arcc` and the argument analysis resolve against the real register file.
`aoma` lists the instruction mnemonics the decoder knows and `aom`
converts between a mnemonic and its id.

## References

- TI **SPRU733** -- *TMS320C67x/C67x+ DSP CPU and Instruction Set*
  (primary encoding reference used here).
- TI **SPRU732** (C64x), **SPRUFE8** (C674x unified), **SPRUGH7** (C66x),
  **SPRU731** (C62x) -- per-family instruction sets.
- TI **SPRAB89** -- C6000 Embedded Application Binary Interface (ELF).
