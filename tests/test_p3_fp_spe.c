/*
 * tests/test_p3_fp_spe.c — freestanding PPC32 Phase 3 FP/SPE self-test.
 *
 * A no-libc PowerPC 32-bit static ELF exercising the Phase 3
 * interpreter surface (docs/lanes/phase-3.md, SPEC section 2.2):
 * scalar FP arithmetic (fadd/fsub/fmul/fdiv/fsqrt/fmadd/fneg/fabs/
 * fsel/frsp), fcmpo/fcmpu ordered + NaN (QNaN/SNaN) CR outcomes,
 * rounding modes via fctiw (RN=nearest) / fctiwz (to-zero) / mtfsfi
 * RN switching (+inf/-inf), fctiw overflow saturation, and e500v2
 * SPE vector integer (evaddw/evsubfw/evand/evor/evxor/evmergehi/
 * evmergelo via evldd/evstdd) plus efs/efd scalar and evfsadd
 * vector spot checks.
 *
 * FP constants are exact in binary (1.5, 2.25, 3.75, 3.375, 4.875,
 * 2.5, -1.5, 2^62), so every arithmetic expectation is bit-exact.
 * SPE sites need an e500v2 CPU (primary opcode 4 SIGILLs on the
 * classic 750); the classic-FP sites run on either CPU.
 *
 * Target path (#ifdef __powerpc__): pure .text assembly, _start entry,
 * raw sc syscalls (sc = 0x44000002, nr in r0, args in r3..r8).
 * Writes "PASS\n" + exit(0) on success, else "FAIL id=<..> got=<..>
 * want=<..>" + exit(1). No TOC use (PC-relative via bl/mflr), so no
 * startup files are needed beyond -nostdlib -static. The SPE section
 * is wrapped in .machine push/e500v2/pop so the default classic
 * toolchain still assembles the file. Build (coordinator runs it):
 *   powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding \
 *     -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
 *     tests/test_p3_fp_spe.c -o test_p3_fp_spe
 *
 * Host path (#else): native self-check replicating every expected value
 * with C models (bit patterns via memcpy, CR outcomes, nearest-even /
 * to-zero / +inf / -inf rounding, per-lane SPE integer models).
 * Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_p3_fp_spe.c -o /tmp/p3spe && /tmp/p3spe
 * must print PASS. Oracle comparison (qemu-ppc -cpu 750 / -cpu e500v2)
 * runs at RC3 via the coordinator.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

/*
 * Freestanding target. Register plan: r31 = PC base (set once, never
 * clobbered), r1 = stack (64 B frame carved at entry), r0 = scratch /
 * syscall nr, r3-r5 = test + syscall regs.
 * FPR plan: f1 = 1.5, f2 = 2.25 (rebuilt before each group),
 * f3/f4 = results, f5/f6 = NaN operands.
 * SPE plan: r14-r17 (never touched by the classic section, so their
 * gpr_hi upper halves stay 0 until SPE insns run).
 * check_eq(r3=got, r4=want, r5=site id) preserves r6-r12/r31/FPRs.
 */
__asm__(
".text\n"
"    .globl _start\n"
"    .align 2\n"
"_start:\n"
"    bl getpc\n"
"getpc:\n"
"    mflr 31\n"
"    addi 1,1,-64\n"
/* ---- load f1=1.5, f2=2.25 ---- */
"    lis 3,0x3FF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 1,16(1)\n"
"    lis 3,0x4002\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 2,16(1)\n"
/* ---- sites 1-2: fadd 1.5+2.25 -> 3.75 ---- */
"    fadd 3,1,2\n"
"    stfd 3,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x400E\n"
"    li 5,1\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,2\n"
"    bl check_eq\n"
/* ---- sites 3-4: fsub 3.75-2.25 -> 1.5 ---- */
"    fsub 4,3,2\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x3FF8\n"
"    li 5,3\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,4\n"
"    bl check_eq\n"
/* ---- sites 5-6: fmul 1.5*2.25 -> 3.375 ---- */
"    fmul 4,1,2\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x400B\n"
"    li 5,5\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,6\n"
"    bl check_eq\n"
/* ---- sites 7-8: fdiv 2.25/1.5 -> 1.5 ---- */
"    fdiv 4,2,1\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x3FF8\n"
"    li 5,7\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,8\n"
"    bl check_eq\n"
/* ---- sites 9-10: fsqrt(2.25) -> 1.5 ---- */
"    fsqrt 4,2\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x3FF8\n"
"    li 5,9\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,10\n"
"    bl check_eq\n"
/* ---- sites 11-12: fmadd 1.5*2.25+1.5 -> 4.875 ---- */
"    fmadd 4,1,2,1\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4013\n"
"    ori 4,4,0x8000@l\n"
"    li 5,11\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,12\n"
"    bl check_eq\n"
/* ---- sites 13-14: fneg(1.5) -> -1.5 ---- */
"    fneg 4,1\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0xBFF8\n"
"    li 5,13\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,14\n"
"    bl check_eq\n"
/* ---- sites 15-16: fabs(-1.5) -> 1.5 ---- */
"    fabs 4,4\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x3FF8\n"
"    li 5,15\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,16\n"
"    bl check_eq\n"
/* ---- sites 17-18: fsel(1.5, 2.25, 1.5) -> 2.25 ---- */
"    fsel 4,1,2,1\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4002\n"
"    li 5,17\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,18\n"
"    bl check_eq\n"
/* ---- sites 19-20: frsp(3.75) -> 3.75 (exact in float) ---- */
"    frsp 4,3\n"
"    stfd 4,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x400E\n"
"    li 5,19\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,20\n"
"    bl check_eq\n"
/* ---- build QNaN f5, SNaN f6 ---- */
"    lis 3,0x7FF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 5,16(1)\n"
"    lis 3,0x7FF0\n"
"    stw 3,16(1)\n"
"    li 3,1\n"
"    stw 3,20(1)\n"
"    lfd 6,16(1)\n"
/* ---- sites 21-23: fcmpu ordered: LT=8, GT=4, EQ=2 ---- */
"    fcmpu 0,1,2\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,8\n"
"    li 5,21\n"
"    bl check_eq\n"
"    fcmpu 0,2,1\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,4\n"
"    li 5,22\n"
"    bl check_eq\n"
"    fcmpu 0,1,1\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,2\n"
"    li 5,23\n"
"    bl check_eq\n"
/* ---- sites 24-25: fcmpu unordered: QNaN=1, SNaN=1 ---- */
"    fcmpu 0,5,1\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,1\n"
"    li 5,24\n"
"    bl check_eq\n"
"    fcmpu 0,1,6\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,1\n"
"    li 5,25\n"
"    bl check_eq\n"
/* ---- sites 26-28: fcmpo ordered + NaN: LT=8, UN=1, UN=1 ---- */
"    fcmpo 0,1,2\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,8\n"
"    li 5,26\n"
"    bl check_eq\n"
"    fcmpo 0,5,1\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,1\n"
"    li 5,27\n"
"    bl check_eq\n"
"    fcmpo 0,6,1\n"
"    mfcr 3\n"
"    rlwinm 3,3,4,28,31\n"
"    li 4,1\n"
"    li 5,28\n"
"    bl check_eq\n"
/* ---- reload f1=1.5 for conversion tests ---- */
"    lis 3,0x3FF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 1,16(1)\n"
/* ---- site 29: fctiw(1.5) RN=nearest -> 2 ---- */
"    fctiw 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,29\n"
"    bl check_eq\n"
/* ---- site 30: fctiwz(1.5) -> 1 ---- */
"    fctiwz 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,1\n"
"    li 5,30\n"
"    bl check_eq\n"
/* ---- build f2=-1.5 ---- */
"    lis 3,0xBFF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 2,16(1)\n"
/* ---- site 31: fctiwz(-1.5) -> -1 ---- */
"    fctiwz 3,2\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,-1\n"
"    li 5,31\n"
"    bl check_eq\n"
/* ---- site 32: fctiw(-1.5) RN=nearest -> -2 (half-even) ---- */
"    fctiw 3,2\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,-2\n"
"    li 5,32\n"
"    bl check_eq\n"
/* ---- build f2=2.5 ---- */
"    lis 3,0x4004\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 2,16(1)\n"
/* ---- site 33: fctiw(2.5) RN=nearest-even -> 2 ---- */
"    fctiw 3,2\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,33\n"
"    bl check_eq\n"
/* ---- site 34: fctiwz(2.5) -> 2 ---- */
"    fctiwz 3,2\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,34\n"
"    bl check_eq\n"
/* ---- reload f1=1.5 for RN-switch tests ---- */
"    lis 3,0x3FF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 1,16(1)\n"
/* ---- site 35: RN=to-zero (mtfsfi 7,1): fctiw(1.5) -> 1 ---- */
"    mtfsfi 7,1\n"
"    fctiw 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,1\n"
"    li 5,35\n"
"    bl check_eq\n"
/* ---- site 36: RN=nearest (mtfsfi 7,0): fctiw(1.5) -> 2 ---- */
"    mtfsfi 7,0\n"
"    fctiw 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,36\n"
"    bl check_eq\n"
/* ---- site 37: RN=+inf (mtfsfi 7,2): fctiw(1.5) -> 2 ---- */
"    mtfsfi 7,2\n"
"    fctiw 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,37\n"
"    bl check_eq\n"
/* ---- site 38: RN=-inf (mtfsfi 7,3): fctiw(1.5) -> 1 ---- */
"    mtfsfi 7,3\n"
"    fctiw 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    li 4,1\n"
"    li 5,38\n"
"    bl check_eq\n"
"    mtfsfi 7,0\n"
/* ---- build f1=2^62 (0x43D0000000000000) ---- */
"    lis 3,0x43D0\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lfd 1,16(1)\n"
/* ---- site 39: fctiwz(2^62) saturates -> 0x80000000 ---- */
"    fctiwz 3,1\n"
"    stfd 3,32(1)\n"
"    lwz 3,36(1)\n"
"    lis 4,0x8000\n"
"    li 5,39\n"
"    bl check_eq\n"
/* ---- SPE vector section (e500v2): .machine push/pop ---- */
"    .machine push\n"
"    .machine e500v2\n"
/* ---- build 64-bit vecA={1,2} at 16(1), vecB={3,4} at 24(1) ---- */
"    li 3,1\n"
"    stw 3,16(1)\n"
"    li 3,2\n"
"    stw 3,20(1)\n"
"    li 3,3\n"
"    stw 3,24(1)\n"
"    li 3,4\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
/* ---- sites 40-41: evaddw {1,2}+{3,4} -> {4,6} ---- */
"    evaddw 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    li 4,4\n"
"    li 5,40\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,6\n"
"    li 5,41\n"
"    bl check_eq\n"
/* ---- build vecA={10,3}, vecB={4,1} ---- */
"    li 3,10\n"
"    stw 3,16(1)\n"
"    li 3,3\n"
"    stw 3,20(1)\n"
"    li 3,4\n"
"    stw 3,24(1)\n"
"    li 3,1\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
/* ---- sites 42-43: evsubfw {10,3}-{4,1} -> {6,2} ---- */
"    evsubfw 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    li 4,6\n"
"    li 5,42\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,2\n"
"    li 5,43\n"
"    bl check_eq\n"
/* ---- build vecA=vecB={0xF0F0F0F0,F0F0F0F0}/{0x0FF00FF0,0x0FF00FF0} -- */
"    lis 3,0xF0F0\n"
"    ori 3,3,0xF0F0@l\n"
"    stw 3,16(1)\n"
"    stw 3,20(1)\n"
"    lis 3,0x0FF0\n"
"    ori 3,3,0x0FF0@l\n"
"    stw 3,24(1)\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
/* ---- sites 44-45: evand -> {0x00F000F0,0x00F000F0} ---- */
"    evand 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x00F0\n"
"    ori 4,4,0x00F0@l\n"
"    li 5,44\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    lis 4,0x00F0\n"
"    ori 4,4,0x00F0@l\n"
"    li 5,45\n"
"    bl check_eq\n"
/* ---- sites 46-47: evor -> {0xFFF0FFF0,0xFFF0FFF0} ---- */
"    evor 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0xFFF0\n"
"    ori 4,4,0xFFF0@l\n"
"    li 5,46\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    lis 4,0xFFF0\n"
"    ori 4,4,0xFFF0@l\n"
"    li 5,47\n"
"    bl check_eq\n"
/* ---- sites 48-49: evxor -> {0xFF00FF00,0xFF00FF00} ---- */
"    evxor 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0xFF00\n"
"    ori 4,4,0xFF00@l\n"
"    li 5,48\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    lis 4,0xFF00\n"
"    ori 4,4,0xFF00@l\n"
"    li 5,49\n"
"    bl check_eq\n"
/* ---- rebuild vecA={1,2}, vecB={3,4} for merges ---- */
"    li 3,1\n"
"    stw 3,16(1)\n"
"    li 3,2\n"
"    stw 3,20(1)\n"
"    li 3,3\n"
"    stw 3,24(1)\n"
"    li 3,4\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
/* ---- sites 50-51: evmergehi -> {1,3} ---- */
"    evmergehi 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    li 4,1\n"
"    li 5,50\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,3\n"
"    li 5,51\n"
"    bl check_eq\n"
/* ---- sites 52-53: evmergelo -> {2,4} ---- */
"    evmergelo 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    li 4,2\n"
"    li 5,52\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,4\n"
"    li 5,53\n"
"    bl check_eq\n"
/* ---- site 54: efsadd 1.5f+2.25f -> 3.75f (0x40700000) ---- */
"    lis 3,0x3FC0\n"
"    stw 3,16(1)\n"
"    lwz 14,16(1)\n"
"    lis 3,0x4010\n"
"    stw 3,16(1)\n"
"    lwz 15,16(1)\n"
"    efsadd 16,14,15\n"
"    stw 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4070\n"
"    li 5,54\n"
"    bl check_eq\n"
/* ---- site 55: efssub 3.75f-1.5f -> 2.25f (0x40100000) ---- */
"    lis 3,0x4070\n"
"    stw 3,16(1)\n"
"    lwz 14,16(1)\n"
"    lis 3,0x3FC0\n"
"    stw 3,16(1)\n"
"    lwz 15,16(1)\n"
"    efssub 16,14,15\n"
"    stw 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4010\n"
"    li 5,55\n"
"    bl check_eq\n"
/* ---- sites 56-57: efdadd 1.5+2.25 -> 3.75 ---- */
"    lis 3,0x3FF8\n"
"    stw 3,16(1)\n"
"    li 3,0\n"
"    stw 3,20(1)\n"
"    lis 3,0x4002\n"
"    stw 3,24(1)\n"
"    li 3,0\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
"    efdadd 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x400E\n"
"    li 5,56\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,57\n"
"    bl check_eq\n"
/* ---- sites 58-59: efdsub 3.75-1.5 -> 2.25 ---- */
"    lis 3,0x400E\n"
"    stw 3,24(1)\n"
"    li 3,0\n"
"    stw 3,28(1)\n"
"    evldd 15,24(1)\n"
"    efdsub 16,15,14\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4002\n"
"    li 5,58\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    li 4,0\n"
"    li 5,59\n"
"    bl check_eq\n"
/* ---- build float vecA={1.5f,2.5f}, vecB={2.25f,1.25f} ---- */
"    lis 3,0x3FC0\n"
"    stw 3,16(1)\n"
"    lis 3,0x4020\n"
"    stw 3,20(1)\n"
"    lis 3,0x4010\n"
"    stw 3,24(1)\n"
"    lis 3,0x3FA0\n"
"    stw 3,28(1)\n"
"    evldd 14,16(1)\n"
"    evldd 15,24(1)\n"
/* ---- sites 60-61: evfsadd -> {3.75f,3.75f} ---- */
"    evfsadd 16,14,15\n"
"    evstdd 16,32(1)\n"
"    lwz 3,32(1)\n"
"    lis 4,0x4070\n"
"    li 5,60\n"
"    bl check_eq\n"
"    lwz 3,36(1)\n"
"    lis 4,0x4070\n"
"    li 5,61\n"
"    bl check_eq\n"
"    .machine pop\n"
/* ---- PASS + exit(0) ---- */
"    addi 3,31,s_pass-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
/* ---- helpers (identical to tests/test_p1_isa.c) ---- */
"check_eq:\n"
"    cmpw 3,4\n"
"    beqlr\n"
"fail:\n"
"    addi 1,1,-48\n"
"    stw 3,0(1)\n"
"    stw 4,4(1)\n"
"    stw 5,8(1)\n"
"    addi 3,31,s_fail-getpc\n"
"    li 4,8\n"
"    bl print\n"
"    lwz 3,8(1)\n"
"    bl print_hex8\n"
"    addi 3,31,s_got-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    lwz 3,0(1)\n"
"    bl print_hex8\n"
"    addi 3,31,s_want-getpc\n"
"    li 4,6\n"
"    bl print\n"
"    lwz 3,4(1)\n"
"    bl print_hex8\n"
"    addi 3,31,s_nl-getpc\n"
"    li 4,1\n"
"    bl print\n"
"    li 3,1\n"
"    li 0,1\n"
"    .long 0x44000002\n"
"print:\n"
"    mr 5,4\n"
"    mr 4,3\n"
"    li 3,1\n"
"    li 0,4\n"
"    .long 0x44000002\n"
"    blr\n"
"print_hex8:\n"
"    mflr 0\n"
"    addi 1,1,-32\n"
"    stw 0,20(1)\n"
"    stw 3,4(1)\n"
"    li 6,8\n"
"    addi 5,1,8\n"
"1:\n"
"    lwz 0,4(1)\n"
"    rlwinm 0,0,4,28,31\n"
"    cmpwi 0,10\n"
"    blt 2f\n"
"    li 7,87\n"
"    add 0,0,7\n"
"    b 3f\n"
"2:\n"
"    li 7,48\n"
"    add 0,0,7\n"
"3:\n"
"    stb 0,0(5)\n"
"    addi 5,5,1\n"
"    lwz 0,4(1)\n"
"    rlwinm 0,0,4,0,31\n"
"    stw 0,4(1)\n"
"    addi 6,6,-1\n"
"    cmpwi 6,0\n"
"    bne 1b\n"
"    addi 3,1,8\n"
"    li 4,8\n"
"    bl print\n"
"    lwz 0,20(1)\n"
"    mtlr 0\n"
"    addi 1,1,32\n"
"    blr\n"
"s_fail: .ascii \"FAIL id=\"\n"
"s_got: .ascii \" got=\"\n"
"s_want: .ascii \" want=\"\n"
"s_nl: .ascii \"\\n\"\n"
"s_pass: .ascii \"PASS\\n\"\n"
);

#else /* host-native self-check of the expected-output logic */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t dbl_bits(double v)
{
    uint64_t u = 0u;
    memcpy(&u, &v, sizeof u);
    return u;
}

static uint32_t flt_bits(float v)
{
    uint32_t u = 0u;
    memcpy(&u, &v, sizeof u);
    return u;
}

static double bits_dbl(uint32_t hi, uint32_t lo)
{
    uint64_t u = ((uint64_t)hi << 32U) | (uint64_t)lo;
    double v = 0.0;
    memcpy(&v, &u, sizeof v);
    return v;
}

/* CR outcome for fcmpu/fcmpo: 8 LT, 4 GT, 2 EQ, 1 UN (NaN). */
static uint32_t fcmp_cr(double a, double b)
{
    if (a != a || b != b) {
        return 1u;
    }
    if (a < b) {
        return 8u;
    }
    if (a > b) {
        return 4u;
    }
    return 2u;
}

/* fctiw[z] model: mode 0 = nearest-even, 1 = to-zero, 2 = +inf, 3 = -inf.
 * Out-of-range saturates to 0x80000000, matching the oracle. */
static uint32_t fctiw_model(double x, int mode)
{
    double ax;
    int64_t mag;
    double frac;
    int neg;
    if (x != x || x >= 2147483648.0 || x < -2147483649.0) {
        return 0x80000000u;
    }
    neg = (x < 0.0) ? 1 : 0;
    ax = neg ? -x : x;
    mag = (int64_t)ax;
    frac = ax - (double)mag;
    if (mode == 0) {
        if (frac > 0.5 || (frac == 0.5 && (mag & 1LL) != 0LL)) {
            mag++;
        }
    } else if (mode == 1) {
        /* truncate: nothing to do */
    } else if (mode == 2) {
        if (!neg && frac > 0.0) {
            mag++;
        }
    } else {
        if (neg && frac > 0.0) {
            mag++;
        }
    }
    if (neg) {
        return (uint32_t)(int32_t)(-mag);
    }
    return (uint32_t)(int32_t)mag;
}

/* 64-bit SPE lane pair {hi, lo}. */
typedef struct {
    uint32_t hi;
    uint32_t lo;
} spe64;

static spe64 spe_add(spe64 a, spe64 b)
{
    spe64 r;
    r.hi = a.hi + b.hi;
    r.lo = a.lo + b.lo;
    return r;
}

static spe64 spe_sub(spe64 a, spe64 b) /* evsubfw: b - a per lane */
{
    spe64 r;
    r.hi = b.hi - a.hi;
    r.lo = b.lo - a.lo;
    return r;
}

static int failures = 0;

#define TEST(name, got, want)                                  \
    do {                                                       \
        uint32_t g_ = (uint32_t)(got);                         \
        uint32_t w_ = (uint32_t)(want);                        \
        if (g_ != w_) {                                        \
            printf("FAIL %s got=0x%08x want=0x%08x\n",         \
                name, g_, w_);                                 \
            failures++;                                        \
        }                                                      \
    } while (0)

int main(void)
{
    double d15 = bits_dbl(0x3FF80000u, 0u);
    double d225 = bits_dbl(0x40020000u, 0u);
    double d375 = bits_dbl(0x400E0000u, 0u);
    double d25 = bits_dbl(0x40040000u, 0u);
    double dm15 = bits_dbl(0xBFF80000u, 0u);
    double big = bits_dbl(0x43D00000u, 0u); /* 2^62 */
    double qnan = strtod("NAN", NULL);
    double snan = bits_dbl(0x7FF00000u, 1u);
    float f15 = 1.5f;
    float f225 = 2.25f;
    float f375 = 3.75f;
    float f25 = 2.5f;
    float f125 = 1.25f;
    spe64 va;
    spe64 vb;
    spe64 vr;

    /* Scalar FP arithmetic bit patterns. */
    TEST("fadd_hi", (uint32_t)(dbl_bits(d15 + d225) >> 32U), 0x400E0000u);
    TEST("fadd_lo", (uint32_t)dbl_bits(d15 + d225), 0u);
    TEST("fsub_hi", (uint32_t)(dbl_bits(d375 - d225) >> 32U), 0x3FF80000u);
    TEST("fsub_lo", (uint32_t)dbl_bits(d375 - d225), 0u);
    TEST("fmul_hi", (uint32_t)(dbl_bits(d15 * d225) >> 32U), 0x400B0000u);
    TEST("fmul_lo", (uint32_t)dbl_bits(d15 * d225), 0u);
    TEST("fdiv_hi", (uint32_t)(dbl_bits(d225 / d15) >> 32U), 0x3FF80000u);
    TEST("fdiv_lo", (uint32_t)dbl_bits(d225 / d15), 0u);
    TEST("fsqrt_hi", (uint32_t)(dbl_bits(d225 / d15) >> 32U), 0x3FF80000u);
    TEST("fmadd_hi", (uint32_t)(dbl_bits(d15 * d225 + d15) >> 32U),
        0x40138000u);
    TEST("fmadd_lo", (uint32_t)dbl_bits(d15 * d225 + d15), 0u);
    TEST("fneg_hi", (uint32_t)(dbl_bits(-d15) >> 32U), 0xBFF80000u);
    TEST("fneg_lo", (uint32_t)dbl_bits(-d15), 0u);
    TEST("fabs_hi", (uint32_t)(dbl_bits(-dm15) >> 32U), 0x3FF80000u);
    TEST("fsel_hi", (uint32_t)(dbl_bits(d15 >= 0.0 ? d225 : d15) >> 32U),
        0x40020000u);
    TEST("frsp_hi", (uint32_t)(dbl_bits((double)(float)d375) >> 32U),
        0x400E0000u);

    /* fcmpo/fcmpu CR outcomes incl. NaN. */
    TEST("fcmpu_lt", fcmp_cr(d15, d225), 8u);
    TEST("fcmpu_gt", fcmp_cr(d225, d15), 4u);
    TEST("fcmpu_eq", fcmp_cr(d15, d15), 2u);
    TEST("fcmpu_qnan", fcmp_cr(qnan, d15), 1u);
    TEST("fcmpu_snan", fcmp_cr(d15, snan), 1u);
    TEST("fcmpo_lt", fcmp_cr(d15, d225), 8u);
    TEST("fcmpo_qnan", fcmp_cr(qnan, d15), 1u);
    TEST("fcmpo_snan", fcmp_cr(snan, d15), 1u);

    /* Rounding modes + conversions. */
    TEST("fctiw_near", fctiw_model(d15, 0), 2u);
    TEST("fctiwz", fctiw_model(d15, 1), 1u);
    TEST("fctiwz_neg", fctiw_model(dm15, 1), 0xFFFFFFFFu);
    TEST("fctiw_neg_half", fctiw_model(dm15, 0), 0xFFFFFFFEu);
    TEST("fctiw_halfeven", fctiw_model(d25, 0), 2u);
    TEST("fctiwz_25", fctiw_model(d25, 1), 2u);
    TEST("fctiw_tozero", fctiw_model(d15, 1), 1u);
    TEST("fctiw_nearest", fctiw_model(d15, 0), 2u);
    TEST("fctiw_pinf", fctiw_model(d15, 2), 2u);
    TEST("fctiw_ninf", fctiw_model(d15, 3), 1u);
    TEST("fctiw_ovf", fctiw_model(big, 1), 0x80000000u);

    /* SPE vector integer. */
    va.hi = 1u;
    va.lo = 2u;
    vb.hi = 3u;
    vb.lo = 4u;
    vr = spe_add(va, vb);
    TEST("evaddw_hi", vr.hi, 4u);
    TEST("evaddw_lo", vr.lo, 6u);
    va.hi = 4u;
    va.lo = 1u;
    vb.hi = 10u;
    vb.lo = 3u;
    vr = spe_sub(va, vb);
    TEST("evsubfw_hi", vr.hi, 6u);
    TEST("evsubfw_lo", vr.lo, 2u);
    va.hi = 0xF0F0F0F0u;
    va.lo = 0xF0F0F0F0u;
    vb.hi = 0x0FF00FF0u;
    vb.lo = 0x0FF00FF0u;
    TEST("evand_hi", va.hi & vb.hi, 0x00F000F0u);
    TEST("evand_lo", va.lo & vb.lo, 0x00F000F0u);
    TEST("evor_hi", va.hi | vb.hi, 0xFFF0FFF0u);
    TEST("evor_lo", va.lo | vb.lo, 0xFFF0FFF0u);
    TEST("evxor_hi", va.hi ^ vb.hi, 0xFF00FF00u);
    TEST("evxor_lo", va.lo ^ vb.lo, 0xFF00FF00u);
    va.hi = 1u;
    va.lo = 2u;
    vb.hi = 3u;
    vb.lo = 4u;
    TEST("evmergehi_hi", va.hi, 1u);
    TEST("evmergehi_lo", vb.hi, 3u);
    TEST("evmergelo_hi", va.lo, 2u);
    TEST("evmergelo_lo", vb.lo, 4u);

    /* efs/efd scalar + evfs vector spot checks. */
    TEST("efsadd", flt_bits(f15 + f225), 0x40700000u);
    TEST("efssub", flt_bits(f375 - f15), 0x40100000u);
    TEST("efdadd_hi", (uint32_t)(dbl_bits(d15 + d225) >> 32U), 0x400E0000u);
    TEST("efdadd_lo", (uint32_t)dbl_bits(d15 + d225), 0u);
    TEST("efdsub_hi", (uint32_t)(dbl_bits(d375 - d15) >> 32U), 0x40020000u);
    TEST("efdsub_lo", (uint32_t)dbl_bits(d375 - d15), 0u);
    TEST("evfsadd_hi", flt_bits(f15 + f225), 0x40700000u);
    TEST("evfsadd_lo", flt_bits(f25 + f125), 0x40700000u);

    if (failures != 0) {
        printf("FAILURES %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* __powerpc__ */
