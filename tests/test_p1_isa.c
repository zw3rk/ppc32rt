/*
 * tests/test_p1_isa.c — freestanding PPC32 Phase 1 integer-ISA self-test
 *
 * A no-libc PowerPC 32-bit static ELF that exercises the Phase 1
 * interpreter surface (docs/lanes/phase-1.md, SPEC section 2.2):
 * ALU (add/sub/addc/subfc/and/or/xor/cmp with XER.CA + CR0 checks),
 * shifts (slw/srw/sraw/srawi with the E02 dropped-bit CA rule),
 * rlwinm/rlwimi/rlwnm (incl. the MB > ME wrap case, E02), b/bc/bl/blr/
 * bctr/bdnz loop, a bctr stub in the last word before a PROT_NONE page
 * (page_end - 4), lwarx/stwcx. atomic increment, and unaligned lwz/stw
 * (plus BE byte order via lbz).
 *
 * Target path (#ifdef __powerpc__): pure .text assembly, _start entry,
 * raw sc syscalls (sc = 0x44000002, nr in r0, args in r3..r8, E01).
 * Writes "PASS\n" + exit(0) on success, else "FAIL id=<..> got=<..>
 * want=<..>" + exit(1). No TOC use (PC-relative via bl/mflr), so no
 * startup files are needed beyond -nostdlib -static.
 *
 * Host path (#else): native self-check replicating every expected value
 * with C models (mask/rotate/shift-carry per E02). Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_p1_isa.c -o /tmp/p1_selfcheck && /tmp/p1_selfcheck
 * must print PASS. Oracle comparison (qemu-ppc -cpu 750 / -cpu e500v2)
 * runs at RC1 via tools/build_fixture.sh + coordinator container.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

/*
 * Freestanding target. Register plan: r31 = PC base (set once, never
 * clobbered), r1 = stack (64 B frame carved at entry), r0 = scratch /
 * immediates, r3-r8 = test + syscall regs, r9-r12 = test regs.
 * check_eq(r3=got, r4=want, r5=site id) preserves r6-r12/r31.
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
/* ---- site 1: add ---- */
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    lis 4,0x1111@h\n"
"    ori 4,4,0x1111@l\n"
"    add 5,3,4\n"
"    mr 3,5\n"
"    lis 4,0x2345@h\n"
"    ori 4,4,0x6789@l\n"
"    li 5,1\n"
"    bl check_eq\n"
/* ---- site 2: subf (A-B) ---- */
"    lis 3,0x2345@h\n"
"    ori 3,3,0x6789@l\n"
"    lis 4,0x1111@h\n"
"    ori 4,4,0x1111@l\n"
"    subf 5,4,3\n"
"    mr 3,5\n"
"    lis 4,0x1234@h\n"
"    ori 4,4,0x5678@l\n"
"    li 5,2\n"
"    bl check_eq\n"
/* ---- sites 3-4: addc 0xFFFFFFFF+1 -> 0, CA=1 ---- */
"    li 3,-1\n"
"    li 4,1\n"
"    addc 5,3,4\n"
"    mr 3,5\n"
"    li 4,0\n"
"    li 5,3\n"
"    bl check_eq\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,1\n"
"    li 5,4\n"
"    bl check_eq\n"
/* ---- sites 5-6: subfc 5-3 -> 2, CA=1 ---- */
"    li 3,5\n"
"    li 4,3\n"
"    subfc 5,4,3\n"
"    mr 3,5\n"
"    li 4,2\n"
"    li 5,5\n"
"    bl check_eq\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,1\n"
"    li 5,6\n"
"    bl check_eq\n"
/* ---- sites 7-8: subfc 3-5 -> 0xFFFFFFFE, CA=0 ---- */
"    li 3,3\n"
"    li 4,5\n"
"    subfc 5,4,3\n"
"    mr 3,5\n"
"    li 4,-2\n"
"    li 5,7\n"
"    bl check_eq\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,0\n"
"    li 5,8\n"
"    bl check_eq\n"
/* ---- sites 9-11: and/or/xor ---- */
"    lis 3,0xF0F0@h\n"
"    ori 3,3,0xF0F0@l\n"
"    lis 4,0x0FF0@h\n"
"    ori 4,4,0x0FF0@l\n"
"    and 5,3,4\n"
"    mr 3,5\n"
"    lis 4,0x00F0@h\n"
"    ori 4,4,0x00F0@l\n"
"    li 5,9\n"
"    bl check_eq\n"
"    lis 3,0xF0F0@h\n"
"    ori 3,3,0xF0F0@l\n"
"    lis 4,0x0FF0@h\n"
"    ori 4,4,0x0FF0@l\n"
"    or 5,3,4\n"
"    mr 3,5\n"
"    lis 4,0xFFF0@h\n"
"    ori 4,4,0xFFF0@l\n"
"    li 5,10\n"
"    bl check_eq\n"
"    lis 3,0xF0F0@h\n"
"    ori 3,3,0xF0F0@l\n"
"    lis 4,0x0FF0@h\n"
"    ori 4,4,0x0FF0@l\n"
"    xor 5,3,4\n"
"    mr 3,5\n"
"    lis 4,0xFF00@h\n"
"    ori 4,4,0xFF00@l\n"
"    li 5,11\n"
"    bl check_eq\n"
/* ---- sites 12-16: cmpw/cmpwi/cmplw CR0 field ---- */
"    li 3,5\n"
"    cmpwi 3,5\n"
"    mfcr 6\n"
"    rlwinm 6,6,0,28,31\n"
"    mr 3,6\n"
"    li 4,2\n"
"    li 5,12\n"
"    bl check_eq\n"
"    li 3,3\n"
"    cmpwi 3,5\n"
"    mfcr 6\n"
"    rlwinm 6,6,0,28,31\n"
"    mr 3,6\n"
"    li 4,8\n"
"    li 5,13\n"
"    bl check_eq\n"
"    li 3,7\n"
"    cmpwi 3,5\n"
"    mfcr 6\n"
"    rlwinm 6,6,0,28,31\n"
"    mr 3,6\n"
"    li 4,4\n"
"    li 5,14\n"
"    bl check_eq\n"
"    li 3,-1\n"
"    li 4,1\n"
"    cmpw 3,4\n"
"    mfcr 6\n"
"    rlwinm 6,6,0,28,31\n"
"    mr 3,6\n"
"    li 4,8\n"
"    li 5,15\n"
"    bl check_eq\n"
"    li 3,-1\n"
"    li 4,1\n"
"    cmplw 3,4\n"
"    mfcr 6\n"
"    rlwinm 6,6,0,28,31\n"
"    mr 3,6\n"
"    li 4,4\n"
"    li 5,16\n"
"    bl check_eq\n"
/* ---- sites 17-18: slw / srw ---- */
"    li 3,1\n"
"    li 4,31\n"
"    slw 5,3,4\n"
"    mr 3,5\n"
"    lis 4,0x8000@h\n"
"    li 5,17\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    li 4,31\n"
"    srw 5,3,4\n"
"    mr 3,5\n"
"    li 4,1\n"
"    li 5,18\n"
"    bl check_eq\n"
/* ---- sites 19-26: srawi / sraw + CA (E02 dropped-bit rule) ---- */
"    lis 3,0x4000@h\n"
"    srawi 5,3,1\n"
"    mr 3,5\n"
"    lis 4,0x2000@h\n"
"    li 5,19\n"
"    bl check_eq\n"
"    lis 3,0x4000@h\n"
"    srawi 5,3,0\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,0\n"
"    li 5,20\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    ori 3,3,1@l\n"
"    srawi 5,3,1\n"
"    mr 3,5\n"
"    lis 4,0xC000@h\n"
"    li 5,21\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    ori 3,3,1@l\n"
"    srawi 5,3,1\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,1\n"
"    li 5,22\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    srawi 5,3,1\n"
"    mr 3,5\n"
"    lis 4,0xC000@h\n"
"    li 5,23\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    srawi 5,3,1\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,0\n"
"    li 5,24\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    li 4,32\n"
"    sraw 5,3,4\n"
"    mr 3,5\n"
"    li 4,-1\n"
"    li 5,25\n"
"    bl check_eq\n"
"    lis 3,0x8000@h\n"
"    li 4,32\n"
"    sraw 5,3,4\n"
"    mfxer 6\n"
"    rlwinm 6,6,2,31,31\n"
"    mr 3,6\n"
"    li 4,1\n"
"    li 5,26\n"
"    bl check_eq\n"
/* ---- sites 27-32: rlwinm / rlwimi / rlwnm ---- */
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    rlwinm 5,3,0,0,31\n"
"    mr 3,5\n"
"    lis 4,0x1234@h\n"
"    ori 4,4,0x5678@l\n"
"    li 5,27\n"
"    bl check_eq\n"
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    rlwinm 5,3,24,24,31\n"
"    mr 3,5\n"
"    li 4,0x56\n"
"    li 5,28\n"
"    bl check_eq\n"
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    rlwinm 5,3,8,24,7\n"
"    mr 3,5\n"
"    lis 4,0x3400@h\n"
"    ori 4,4,0x0012@l\n"
"    li 5,29\n"
"    bl check_eq\n"
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    rlwinm 5,3,8,16,15\n"
"    mr 3,5\n"
"    lis 4,0x3456@h\n"
"    ori 4,4,0x7812@l\n"
"    li 5,30\n"
"    bl check_eq\n"
"    lis 5,0xFFFF@h\n"
"    ori 5,5,0xFF00@l\n"
"    li 3,0xAB\n"
"    rlwimi 5,3,0,24,31\n"
"    mr 3,5\n"
"    lis 4,0xFFFF@h\n"
"    ori 4,4,0xFFAB@l\n"
"    li 5,31\n"
"    bl check_eq\n"
"    lis 3,0x1234@h\n"
"    ori 3,3,0x5678@l\n"
"    li 4,8\n"
"    rlwnm 5,3,4,0,31\n"
"    mr 3,5\n"
"    lis 4,0x3456@h\n"
"    ori 4,4,0x7812@l\n"
"    li 5,32\n"
"    bl check_eq\n"
/* ---- sites 33-35: b / bc taken / bc not-taken ---- */
"    li 5,0\n"
"    b 1f\n"
"    li 5,1\n"
"1:\n"
"    mr 3,5\n"
"    li 4,0\n"
"    li 5,33\n"
"    bl check_eq\n"
"    li 5,0\n"
"    cmpwi 5,0\n"
"    beq 1f\n"
"    li 5,1\n"
"1:\n"
"    mr 3,5\n"
"    li 4,0\n"
"    li 5,34\n"
"    bl check_eq\n"
"    li 5,0\n"
"    cmpwi 5,1\n"
"    beq 1f\n"
"    li 5,7\n"
"1:\n"
"    mr 3,5\n"
"    li 4,7\n"
"    li 5,35\n"
"    bl check_eq\n"
/* ---- site 36: bl / blr subroutine ---- */
"    li 3,10\n"
"    bl sub_add5\n"
"    b 1f\n"
"sub_add5:\n"
"    addi 3,3,5\n"
"    blr\n"
"1:\n"
"    mr 3,3\n"
"    li 4,15\n"
"    li 5,36\n"
"    bl check_eq\n"
/* ---- sites 37-38: bdnz loop ---- */
"    li 5,0\n"
"    li 6,5\n"
"    mtctr 6\n"
"1:\n"
"    addi 5,5,1\n"
"    bdnz 1b\n"
"    mr 3,5\n"
"    li 4,5\n"
"    li 5,37\n"
"    bl check_eq\n"
"    mfctr 6\n"
"    mr 3,6\n"
"    li 4,0\n"
"    li 5,38\n"
"    bl check_eq\n"
/* ---- site 39: bctr ---- */
"    addi 10,31,bctr_dst-getpc\n"
"    mtctr 10\n"
"    bctr\n"
"bctr_dst:\n"
"    li 5,0x42\n"
"    mr 3,5\n"
"    li 4,0x42\n"
"    li 5,39\n"
"    bl check_eq\n"
/* ---- sites 40-42: mmap2 pair, PROT_NONE guard, branch at page_end-4 ---- */
"    li 0,192\n"
"    li 3,0\n"
"    li 4,8192\n"
"    li 5,3\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mfcr 7\n"
"    rlwinm 7,7,28,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,40\n"
"    bl check_eq\n"
"    addi 3,9,4096\n"
"    li 4,4096\n"
"    li 5,0\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,28,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,41\n"
"    bl check_eq\n"
"    addi 10,9,4092\n"
"    lis 0,0x4E80@h\n"
"    ori 0,0,0x0420@l\n"
"    stw 0,0(10)\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    addi 0,31,resumed-getpc\n"
"    mtctr 0\n"
"    mtlr 10\n"
"    li 11,0\n"
"    blr\n"
"    li 3,1\n"
"    li 4,0\n"
"    li 5,43\n"
"    bl fail\n"
"resumed:\n"
"    mr 3,11\n"
"    li 4,0\n"
"    li 5,42\n"
"    bl check_eq\n"
/* ---- site 44: lwarx/stwcx. atomic increment 0 -> 5 ---- */
"    addi 9,1,16\n"
"    li 0,0\n"
"    stw 0,0(9)\n"
"    li 6,5\n"
"    mtctr 6\n"
"1:\n"
"    lwarx 4,0,9\n"
"    addi 4,4,1\n"
"    stwcx. 4,0,9\n"
"    bne 1b\n"
"    bdnz 1b\n"
"    lwz 4,0(9)\n"
"    mr 3,4\n"
"    li 4,5\n"
"    li 5,44\n"
"    bl check_eq\n"
/* ---- sites 45-47: unaligned lwz/stw + BE byte order ---- */
"    addi 9,1,24\n"
"    addi 9,9,1\n"
"    lis 4,0x1234@h\n"
"    ori 4,4,0x5678@l\n"
"    stw 4,0(9)\n"
"    lwz 5,0(9)\n"
"    mr 3,5\n"
"    lis 4,0x1234@h\n"
"    ori 4,4,0x5678@l\n"
"    li 5,45\n"
"    bl check_eq\n"
"    lbz 5,0(9)\n"
"    mr 3,5\n"
"    li 4,0x12\n"
"    li 5,46\n"
"    bl check_eq\n"
"    lbz 5,3(9)\n"
"    mr 3,5\n"
"    li 4,0x78\n"
"    li 5,47\n"
"    bl check_eq\n"
/* ---- PASS + exit(0) ---- */
"    addi 3,31,s_pass-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
/* ---- helpers ---- */
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
"    addi 1,1,-16\n"
"    stw 3,4(1)\n"
"    li 6,8\n"
"    addi 5,1,8\n"
"1:\n"
"    lwz 0,4(1)\n"
"    rlwinm 0,0,28,28,31\n"
"    cmpwi 0,10\n"
"    blt 2f\n"
"    addi 0,0,87\n"
"    b 3f\n"
"2:\n"
"    addi 0,0,48\n"
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
"    addi 1,1,16\n"
"    blr\n"
"s_fail: .ascii \"FAIL id=\"\n"
"s_got: .ascii \" got=\"\n"
"s_want: .ascii \" want=\"\n"
"s_nl: .ascii \"\\n\"\n"
"s_pass: .ascii \"PASS\\n\"\n"
);

#else /* host-native self-check of the expected-output logic */

#include <stdio.h>

static uint32_t rotl32(uint32_t v, unsigned n)
{
    n &= 31u;
    if (n == 0u) {
        return v;
    }
    return (uint32_t)((v << n) | (v >> (32u - n)));
}

/* E02 section 2: MB<=ME selects [MB,ME], MB>ME the complement. */
static uint32_t ppc_mask32(unsigned mb, unsigned me)
{
    uint32_t ml = (mb == 0u) ? 0xFFFFFFFFu : (0xFFFFFFFFu >> mb);
    uint32_t mh = (me == 31u) ? 0u : (0xFFFFFFFFu >> (me + 1u));
    uint32_t x = ml ^ mh;
    return (mb <= me) ? x : (uint32_t)~x;
}

static uint32_t rlwinm(uint32_t rs, unsigned sh, unsigned mb, unsigned me)
{
    return (uint32_t)(rotl32(rs, sh) & ppc_mask32(mb, me));
}

static uint32_t rlwimi(uint32_t ra, uint32_t rs, unsigned sh, unsigned mb,
    unsigned me)
{
    uint32_t m = ppc_mask32(mb, me);
    return (uint32_t)((rotl32(rs, sh) & m) | (ra & ~m));
}

static uint32_t rlwnm(uint32_t rs, uint32_t rb, unsigned mb, unsigned me)
{
    return (uint32_t)(rotl32(rs, rb & 31u) & ppc_mask32(mb, me));
}

/* Returns result; stores carry in *ca (E02 section 3 rules). */
static uint32_t srawi_model(uint32_t rs, unsigned sh, uint32_t *ca)
{
    uint32_t res;
    uint64_t lowmask;
    if (sh == 0u) {
        *ca = 0u;
        return rs;
    }
    res = (uint32_t)(((int32_t)rs) >> sh);
    lowmask = ((uint64_t)1 << sh) - 1u;
    *ca = ((rs & 0x80000000u) != 0u && ((uint64_t)rs & lowmask) != 0u) ? 1u : 0u;
    return res;
}

static uint32_t sraw_model(uint32_t rs, uint32_t rb, uint32_t *ca)
{
    unsigned n = rb & 63u;
    if (n == 0u) {
        *ca = 0u;
        return rs;
    }
    if (n >= 32u) {
        uint32_t res = (rs & 0x80000000u) != 0u ? 0xFFFFFFFFu : 0u;
        *ca = (res != 0u) ? 1u : 0u;
        return res;
    }
    return srawi_model(rs, n, ca);
}

static uint32_t addc_model(uint32_t a, uint32_t b, uint32_t *ca)
{
    uint64_t s = (uint64_t)a + (uint64_t)b;
    *ca = (uint32_t)(s >> 32);
    return (uint32_t)s;
}

static uint32_t subfc_model(uint32_t a, uint32_t b, uint32_t *ca)
/* rd = b - a, CA = (b >= a) */
{
    *ca = (b >= a) ? 1u : 0u;
    return (uint32_t)(b - a);
}

/* CR0 field for a signed compare: 8 LT, 4 GT, 2 EQ. */
static uint32_t cr0_signed(int32_t a, int32_t b)
{
    if (a < b) {
        return 8u;
    }
    if (a > b) {
        return 4u;
    }
    return 2u;
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
    uint32_t ca = 0u;
    uint32_t cell = 0u;
    uint32_t i;
    unsigned char ubuf[8];
    uint32_t uw;

    TEST("add", 0x12345678u + 0x11111111u, 0x23456789u);
    TEST("subf", 0x23456789u - 0x11111111u, 0x12345678u);
    TEST("addc", addc_model(0xFFFFFFFFu, 1u, &ca), 0u);
    TEST("addc_ca", ca, 1u);
    TEST("subfc", subfc_model(3u, 5u, &ca), 2u);
    TEST("subfc_ca", ca, 1u);
    TEST("subfc2", subfc_model(5u, 3u, &ca), 0xFFFFFFFEu);
    TEST("subfc2_ca", ca, 0u);
    TEST("and", 0xF0F0F0F0u & 0x0FF00FF0u, 0x00F000F0u);
    TEST("or", 0xF0F0F0F0u | 0x0FF00FF0u, 0xFFF0FFF0u);
    TEST("xor", 0xF0F0F0F0u ^ 0x0FF00FF0u, 0xFF00FF00u);
    TEST("cmp_eq", cr0_signed(5, 5), 2u);
    TEST("cmp_lt", cr0_signed(3, 5), 8u);
    TEST("cmp_gt", cr0_signed(7, 5), 4u);
    TEST("cmpw_neg", cr0_signed(-1, 1), 8u);
    TEST("cmplw", (0xFFFFFFFFu > 1u) ? 4u : 8u, 4u);
    TEST("slw", 1u << 31, 0x80000000u);
    TEST("srw", 0x80000000u >> 31, 1u);
    TEST("srawi_pos", srawi_model(0x40000000u, 1u, &ca), 0x20000000u);
    TEST("srawi_pos_ca", ca, 0u);
    TEST("srawi_neg1", srawi_model(0x80000001u, 1u, &ca), 0xC0000000u);
    TEST("srawi_neg1_ca", ca, 1u);
    TEST("srawi_neg0", srawi_model(0x80000000u, 1u, &ca), 0xC0000000u);
    TEST("srawi_neg0_ca", ca, 0u);
    TEST("sraw_sat", sraw_model(0x80000000u, 32u, &ca), 0xFFFFFFFFu);
    TEST("sraw_sat_ca", ca, 1u);
    TEST("mask_wrap", ppc_mask32(24u, 7u), 0xFF0000FFu);
    TEST("mask_wrapfull", ppc_mask32(16u, 15u), 0xFFFFFFFFu);
    TEST("rlwinm_id", rlwinm(0x12345678u, 0u, 0u, 31u), 0x12345678u);
    TEST("rlwinm_ext", rlwinm(0x12345678u, 24u, 24u, 31u), 0x56u);
    TEST("rlwinm_wrap", rlwinm(0x12345678u, 8u, 24u, 7u), 0x34000012u);
    TEST("rlwinm_wrapfull", rlwinm(0x12345678u, 8u, 16u, 15u), 0x34567812u);
    TEST("rlwimi", rlwimi(0xFFFFFF00u, 0xABu, 0u, 24u, 31u), 0xFFFFFFABu);
    TEST("rlwnm", rlwnm(0x12345678u, 8u, 0u, 31u), 0x34567812u);

    /* Branch/loop shapes mirrored from the target path. */
    {
        uint32_t r5 = 0u;
        goto skip;
        r5 = 1u;
skip:
        TEST("b_fwd", r5, 0u);
    }
    {
        uint32_t ctr = 5u;
        uint32_t r5 = 0u;
        while (ctr != 0u) {
            ctr--;
            r5++;
        }
        TEST("bdnz", r5, 5u);
        TEST("bdnz_ctr", ctr, 0u);
    }
    /* lwarx/stwcx. increment loop model: single-threaded, always succeeds. */
    cell = 0u;
    for (i = 0u; i < 5u; i++) {
        uint32_t loaded = cell;
        cell = loaded + 1u;
    }
    TEST("atomic", cell, 5u);
    /* Unaligned + big-endian byte order model. */
    uw = 0x12345678u;
    ubuf[1] = (unsigned char)(uw >> 24);
    ubuf[2] = (unsigned char)(uw >> 16);
    ubuf[3] = (unsigned char)(uw >> 8);
    ubuf[4] = (unsigned char)uw;
    TEST("unaligned",
        ((uint32_t)ubuf[1] << 24) | ((uint32_t)ubuf[2] << 16) |
        ((uint32_t)ubuf[3] << 8) | (uint32_t)ubuf[4],
        0x12345678u);
    TEST("be_first", ubuf[1], 0x12u);
    TEST("be_last", ubuf[4], 0x78u);

    if (failures != 0) {
        printf("FAILURES %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* __powerpc__ */
