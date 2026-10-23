# Phase 3 Task Cards — Floating-Point & SPE (`RC3`)

Run after `RC2` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 2 output
plus `src/ppc32rt.h` (`fpr[32]`, `acc`, `fpscr`, `spefscr`, `gpr_hi[32]`),
this file. Reference: `../i686rt` x87/SSE phases (read-only).

Common lane rules: as Phase 2. FP lanes additionally: NaN propagation and
rounding-mode rules per E03/SPEC §2.2; `Rc=1` CR1 update for FP compares;
`AT_HWCAP`-gated NEON use in the emitter (L3b).

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L3a | `lane/p3-l3a` `../ppc32rt-l3a` | `src/interp/fp.c`, `src/interp/fp.h` | host unit test, NaN/rounding cases |
| L3b | `lane/p3-l3b` `../ppc32rt-l3b` | `src/dbt/emit_fp.c`, `src/dbt/emit_fp.h` | host unit test of FP emission |
| L3c | `lane/p3-l3c` `../ppc32rt-l3c` | `tests/test_p3_fp_spe.c` | host-native self-check prints `PASS` |

## Card L3a — FPU & SPE reference interpreter

Scope: `src/interp/fp.c` implementing SPEC §2.2 classic FPU (`lfs`/`lfd`/
`stfs`/`stfd` + update/indexed, `fadd[s]`/`fsub[s]`/`fmul[s]`/`fdiv[s]`/
`fsqrt[s]`, fused `fmadd[s]`/`fmsub[s]`/`fnmadd[s]`/`fnmsub[s]`, `fcmpu`/
`fcmpo`, `fctiw[z]`, `frsp`, `fabs`/`fnabs`/`fneg`/`fmr`/`fsel`, `mffs`/
`mtfsf` with `fpscr`) and e500v2 SPE (major opcode 4): 64-bit GPRs as
`(gpr_hi[r]<<32)|gpr[r]` + `acc` + `spefscr`; vector integer/logical/merge/
ldst (`evaddw`, `evsubfw`, `evand`, `evor`, `evxor`, `evmr`, `evmerge*`,
`evldd[x]`/`evldw[x]`/`evstdd[x]`/`evstdw[x]`, `evsel`, `evmra`, MAC);
scalar `efs*`/`efd*`; vector `evfs*`. Classic 32-bit insns never touch
`gpr_hi`.
Check: host unit test (NaN payload, `0.0` vs `-0.0`, `fctiw` overflow,
`evaddw` upper-word) prints `L3A OK`.

## Card L3b — AArch64 FP & NEON emitter

Scope: `src/dbt/emit_fp.c` lowering every L3a instruction to AArch64 FP/
NEON (`fmadd`/`fmsub`/`fnmadd`/`fnmsub` → `fmadd`/`fmsub`/`fnmadd`/
`fnmsub`; `fsqrt` → `fsqrt`; SPE vector integer → NEON `add`/`sub`/`and`/
`orr`/`eor` on `d`/`v` regs; `efs*` scalar-single → `s`-reg ops; `efd*`
→ `d`-reg ops), FPSCR→NZCV/FPCR rounding mapping, phase-gated `AT_HWCAP`
activation comment. No `x18`.
Check: host unit test asserting selected lowerings prints `L3B OK`.

## Card L3c — FP/SPE test suite

Scope: `tests/test_p3_fp_spe.c` — PPC32 fixture covering scalar FP
arithmetic, `fcmpo`/`fcmpu` NaN cases, rounding modes, `fctiw[z]`
conversions, SPE vector integer + `efs*`/`efd*` spot checks; prints `PASS`,
exits 0.
Check: host-native self-check of expected-output logic prints `PASS`
(oracle comparison at `RC3` by the coordinator).

## `RC3` (coordinator, after all three merge)

`test_p3_fp_spe` matches `qemu-ppc` (both CPUs) bit-for-bit on both engines
with `0` `--difftest` divergences in a bounded Docker container.
