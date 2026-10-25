/*
 * tests/test_h1_smc.c — freestanding PPC32 Phase 7 self-modifying-code test
 *
 * A no-libc PowerPC 32-bit static ELF exercising SMC translation-cache
 * invalidation (docs/lanes/phase-7.md, card H1): guest instruction words
 * are rewritten on an anon RWX mmap, on the stack, on the brk heap, and
 * via mprotect/munmap page transitions; after the architectural
 * dcbst/sync/icbi/isync flush the NEW bytes must run under --dbt (not
 * stale translations). W^X is probed host-side by tools/p7_smc.sh
 * (guest data pages never PROT_EXEC on the host); the guest itself only
 * relies on behavior the oracle honors.
 *
 * Flush choice: dcbst 0,rA; sync; icbi 0,rA; isync. All four are
 * oracle-honored NOPs on both qemu-ppc -cpu 750 and -cpu e500v2 (this
 * fixture passes on both), and ppc32rt decodes them as cache-hint/
 * barrier NOPs (PPC32_OP_DCBT/PPC32_OP_SYNC) exactly like the
 * interpreter; invalidation itself comes from the DBT store hooks in
 * src/dbt/dbt.c plus dispatch re-verification in src/dbt/cache.c.
 *
 * Target path (#ifdef __powerpc__): pure .text assembly, _start entry,
 * raw sc syscalls (sc = 0x44000002, nr in r0, args in r3..r8).
 * Writes "PASS\n" + exit(0) on success, else "FAIL id=<..> got=<..>
 * want=<..>" + exit(1). stdout is byte-identical across oracle CPUs
 * and both engines (no addresses are ever printed). No TOC use
 * (PC-relative via bl/mflr for code, @ha/@l for .data).
 * Build (lane container):
 *   sh tools/build_fixture.sh tests/test_h1_smc.c _build/test_h1_smc
 * Oracle / translator runs:
 *   qemu-ppc -cpu 750 ./_build/test_h1_smc
 *   qemu-ppc -cpu e500v2 ./_build/test_h1_smc
 *   ppc32rt --interp -- ./_build/test_h1_smc
 *   ppc32rt --dbt -- ./_build/test_h1_smc
 *   ppc32rt --difftest -- ./_build/test_h1_smc   (prints DIFFTEST: EQUAL)
 * All five agree: identical stdout, exit 0.
 *
 * Host path (#else): native self-check of the same expectations with
 * mmap/mprotect/munmap/brk plus function-pointer rewrite/call pairs.
 * Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_h1_smc.c -o /tmp/h1self && /tmp/h1self
 * must print PASS.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

/*
 * Freestanding target. Register plan: r31 = PC base (set once, never
 * clobbered), r1 = stack (4 KiB frame carved at entry), r0 = scratch /
 * syscall nr, r3-r5 = test + syscall regs, r9-r12 = test regs (kept
 * across check_eq, which only touches r3-r5 on the pass path).
 * Writable state lives in .data (absolute lis/addi @ha/@l); constant
 * strings live in .text (PC-relative via r31). check_eq(r3=got,
 * r4=want, r5=site id) preserves r6-r12/r31.
 */
__asm__(
".text\n"
"    .globl _start\n"
"    .align 2\n"
"_start:\n"
"    bl getpc\n"
"getpc:\n"
"    mflr 31\n"
"    addi 1,1,-4096\n"
/* ---- site 1: mmap 1 page RWX (prot=7); no error ---- */
"    li 3,0\n"
"    li 4,4096\n"
"    li 5,7\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,1\n"
"    bl check_eq\n"
"    lis 6,apage@ha\n"
"    stw 9,apage@l(6)\n"
/* ---- site 2: V1 (li 3,1; blr) on the mmap page runs ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(9)\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,2\n"
"    bl check_eq\n"
/* ---- site 3: same-address rewrite (NO mm ops) runs NEW bytes ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(9)\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,3\n"
"    bl check_eq\n"
/* ---- site 4: mprotect the stack page RWX; no error ---- */
/* sp is pinned to page+1024 and the code buffer to page+2048 of the
 * mprotect'd stack page: the buffer stays mapped (same page as sp),
 * above every spill slot check_eq pushes below sp, and below the
 * stack top (no unmapped-above-top fault as with a blind sp+large). */
"    mr 11,1\n"
"    rlwinm 11,11,0,0,19\n"
"    mr 3,11\n"
"    li 4,4096\n"
"    li 5,7\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,4\n"
"    bl check_eq\n"
"    mr 1,11\n"
"    addi 1,1,1024\n"
"    addi 10,11,2048\n"
"    lis 6,spage@ha\n"
"    stw 10,spage@l(6)\n"
/* ---- site 5: V1 on the stack runs ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(10)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(10)\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    mtlr 10\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,5\n"
"    bl check_eq\n"
/* ---- site 6: same-address stack rewrite runs NEW bytes ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(10)\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    mtlr 10\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,6\n"
"    bl check_eq\n"
/* ---- site 7: brk extend; the break advances to the request ---- */
"    li 3,0\n"
"    li 0,45\n"
"    .long 0x44000002\n"
"    mr 11,3\n"
"    addi 12,11,8191\n"
"    rlwinm 12,12,0,0,18\n"
"    addi 3,12,8192\n"
"    li 0,45\n"
"    .long 0x44000002\n"
"    mr 10,3\n"
"    mr 3,10\n"
"    addi 4,12,8192\n"
"    li 5,7\n"
"    bl check_eq\n"
/* ---- site 8: mprotect the heap page RWX; no error ---- */
"    mr 3,12\n"
"    li 4,4096\n"
"    li 5,7\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,8\n"
"    bl check_eq\n"
"    addi 10,12,1024\n"
"    lis 6,hpage@ha\n"
"    stw 10,hpage@l(6)\n"
/* ---- site 9: V1 on the heap runs ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(10)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(10)\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    mtlr 10\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,9\n"
"    bl check_eq\n"
/* ---- site 10: same-address heap rewrite runs NEW bytes ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(10)\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    mtlr 10\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,10\n"
"    bl check_eq\n"
/* ---- site 11: mmap 1 page RW for the mprotect round trip ---- */
"    li 3,0\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,11\n"
"    bl check_eq\n"
"    lis 6,dpage@ha\n"
"    stw 9,dpage@l(6)\n"
/* ---- site 12: mprotect RX; no error ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,12\n"
"    bl check_eq\n"
/* ---- site 13: V1 runs from the RX page ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(9)\n"
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,13\n"
"    bl check_eq\n"
/* ---- sites 14-15: mprotect RW, rewrite, mprotect RX; no errors ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,14\n"
"    bl check_eq\n"
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(9)\n"
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,15\n"
"    bl check_eq\n"
/* ---- site 16: NEW bytes run after the RX round trip ---- */
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,16\n"
"    bl check_eq\n"
/* ---- site 17: mmap 1 page RW for the munmap round trip ---- */
"    li 3,0\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,17\n"
"    bl check_eq\n"
"    lis 6,epage@ha\n"
"    stw 9,epage@l(6)\n"
/* ---- sites 18-19: write V1, mprotect RX, V1 runs ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(9)\n"
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,18\n"
"    bl check_eq\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,19\n"
"    bl check_eq\n"
/* ---- site 20: munmap; no error ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 0,91\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,20\n"
"    bl check_eq\n"
/* ---- site 21: mmap MAP_FIXED the same address RW; same address ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 6,0x32\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 10,3\n"
"    mr 3,10\n"
"    mr 4,9\n"
"    li 5,21\n"
"    bl check_eq\n"
/* ---- sites 22-23: write V2, mprotect RX, NEW bytes run ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(10)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(10)\n"
"    mr 3,10\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,22\n"
"    bl check_eq\n"
"    dcbst 0,10\n"
"    sync\n"
"    icbi 0,10\n"
"    isync\n"
"    mtlr 10\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,23\n"
"    bl check_eq\n"
/* ---- site 24: mmap 1 page RWX for the dcbz round trip ---- */
"    li 3,0\n"
"    li 4,4096\n"
"    li 5,7\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,24\n"
"    bl check_eq\n"
/* ---- site 25: V1 runs ---- */
"    lis 7,0x3860\n"
"    ori 7,7,0x0001@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(9)\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,1\n"
"    li 5,25\n"
"    bl check_eq\n"
/* ---- site 26: dcbz-clear plus stw rewrite runs NEW bytes ---- */
"    dcbz 0,9\n"
"    lis 7,0x3860\n"
"    ori 7,7,0x0002@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0020@l\n"
"    stw 7,4(9)\n"
"    dcbst 0,9\n"
"    sync\n"
"    icbi 0,9\n"
"    isync\n"
"    mtlr 9\n"
"    blrl\n"
"    li 4,2\n"
"    li 5,26\n"
"    bl check_eq\n"
/* ---- PASS + exit(0) ---- */
"    addi 3,31,s_pass-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
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
"    .data\n"
"    .align 2\n"
"apage: .long 0\n"
"spage: .long 0\n"
"hpage: .long 0\n"
"dpage: .long 0\n"
"epage: .long 0\n"
);

#else /* host-native self-check of the same expectations */

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*h1_fn)(void);

static int h1_v1(void)
{
    return 1;
}

static int h1_v2(void)
{
    return 2;
}

#define H1_CHECK(cond, id) do { \
        if (!(cond)) { \
            printf("FAIL %d\n", (id)); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    unsigned char *rw;
    unsigned char *rx;
    h1_fn f;

    H1_CHECK(ps > 0, 1);
    /* Rewrite-through-pointer plus mprotect/munmap round trips, the
     * host-native shadow of guest sites 1-3 and 12-22: re-point the
     * callee and re-execute, then cycle the page protections. */
    rw = (unsigned char *)mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    H1_CHECK(rw != MAP_FAILED, 1);
    /* macOS (Apple Silicon) refuses PROT_EXEC without a JIT
     * entitlement; the guest itself runs on Linux where RWX maps fine. */
#ifdef __APPLE__
    H1_CHECK(mprotect(rw, (size_t)ps, PROT_READ | PROT_WRITE) == 0, 4);
#else
    H1_CHECK(mprotect(rw, (size_t)ps, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, 4);
#endif
    f = h1_v1;
    H1_CHECK(f() == 1, 2);
    f = h1_v2;
    H1_CHECK(f() == 2, 3);
    H1_CHECK(mprotect(rw, (size_t)ps, PROT_READ | PROT_WRITE) == 0, 14);
    H1_CHECK(mprotect(rw, (size_t)ps, PROT_READ | PROT_EXEC) == 0, 15);
    H1_CHECK(munmap(rw, (size_t)ps) == 0, 20);
    rx = (unsigned char *)mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    H1_CHECK(rx != MAP_FAILED, 17);
    H1_CHECK(mprotect(rx, (size_t)ps, PROT_READ | PROT_EXEC) == 0, 18);
    H1_CHECK(munmap(rx, (size_t)ps) == 0, 20);
    printf("PASS\n");
    return 0;
}

#endif
