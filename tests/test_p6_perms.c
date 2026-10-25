/*
 * tests/test_p6_perms.c — freestanding PPC32 Phase 6 page-permissions test
 *
 * A no-libc PowerPC 32-bit static ELF exercising adjacent 4 KiB pages
 * with distinct permissions (docs/lanes/phase-6.md, card L6b): one
 * mmap2 region of three pages, the first mprotect'd to
 * PROT_READ|PROT_EXEC, the middle left PROT_READ|PROT_WRITE (a
 * PT_GNU_RELRO-style RX-then-RW split), the last mprotect'd to
 * PROT_NONE (guard). Checks:
 *   1 mmap2 ok, 2 mprotect RX ok, 3 mprotect NONE ok,
 *   4 read from the RX page, 5 read from the RW page,
 *   6 write to the RW page reads back,
 *   7 branch-into-RX stub round trip (bcctr to CTR, like test_p1_isa),
 *   8 write to the RX page faults with si_addr exactly on the page,
 *   9 read from the guard page faults with si_addr exactly on it,
 *   a write to the guard page faults with si_addr exactly on it.
 * (Branching into the guard page is deliberately NOT checked: the
 * oracle reports history-dependent si_addr values for instruction-
 * fetch faults — NULL on a fresh mapping, guard+4 after prior faults
 * on the same mapping — so no exact address can match the oracle
 * robustly. The RX execute path is covered by site 7 instead.)
 * Faults are caught with an rt_sigaction(173) SIGSEGV handler that
 * records si_addr and resumes at a per-site continuation (resume_nip),
 * generalizing the nip += 4 idiom of tests/test_p4_threads_signals.c
 * (a fetch fault inside the guard page must not resume at nip + 4).
 *
 * Target path (#ifdef __powerpc__): pure .text assembly, _start entry,
 * raw sc syscalls (sc = 0x44000002, nr in r0, args in r3..r8).
 * Writes "PASS\n" + exit(0) on success, else "FAIL id=<..> got=<..>
 * want=<..>" + exit(1). No TOC use (PC-relative via bl/mflr for code,
 * @ha/@l for .data), so no startup files are needed beyond
 * -nostdlib -static. Build (lane container):
 *   sh tools/build_fixture.sh tests/test_p6_perms.c _build/test_p6_perms
 * Oracle / translator runs:
 *   qemu-ppc -cpu 750 ./_build/test_p6_perms
 *   qemu-ppc -cpu e500v2 ./_build/test_p6_perms
 *   ppc32rt --interp -- ./_build/test_p6_perms
 *   ppc32rt --dbt -- ./_build/test_p6_perms
 * All four print identical stdout and exit 0; RC6 byte-diffs them.
 *
 * Host path (#else): native self-check of the same expectations with
 * mmap/mprotect and a SIGSEGV/SIGBUS handler that longjmps back and
 * checks the fault address. Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_p6_perms.c -o /tmp/p6perms && /tmp/p6perms
 * must print PASS. Page strides follow the host page size there (the
 * 4 KiB adjacency is a guest-side property checked on the oracle).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

/*
 * Freestanding target. Register plan: r31 = PC base (set once, never
 * clobbered), r1 = stack (64 B frame carved at entry), r0 = scratch /
 * syscall nr, r3-r5 = test + syscall regs, r9-r11 = test regs (kept
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
"    addi 1,1,-64\n"
/* ---- install SIGSEGV(11) handler with SA_SIGINFO(4) ---- */
"    lis 6,sigact@ha\n"
"    addi 6,6,sigact@l\n"
"    addi 7,31,h_segv-getpc\n"
"    stw 7,0(6)\n"
"    li 7,4\n"
"    stw 7,4(6)\n"
"    li 7,0\n"
"    stw 7,8(6)\n"
"    stw 7,12(6)\n"
"    stw 7,16(6)\n"
"    li 3,11\n"
"    mr 4,6\n"
"    li 5,0\n"
"    li 6,8\n"
"    li 0,173\n"
"    .long 0x44000002\n"
/* ---- mmap2 3 pages (12288 B), RW anon; site 1: no error ---- */
"    li 3,0\n"
"    li 4,12288\n"
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
"    li 5,1\n"
"    bl check_eq\n"
"    lis 6,region@ha\n"
"    stw 9,region@l(6)\n"
/* ---- sentinels before the split: RX[0], RW[0] ---- */
"    lis 7,0xA5A5\n"
"    ori 7,7,0x5A5A@l\n"
"    stw 7,0(9)\n"
"    lis 7,0x5A5A\n"
"    ori 7,7,0xA5A5@l\n"
"    stw 7,4096(9)\n"
/* ---- stub bytes before the split: li 11,0x5A ; bcctr (branch to CTR).
 * Stored here while the page is still writable; executed at site 7
 * after the mprotect(RX). Two instructions fit before the RW page. */
"    addi 10,9,4088\n"
"    lis 7,0x3960\n"
"    ori 7,7,0x005A@l\n"
"    stw 7,0(10)\n"
"    lis 7,0x4E80\n"
"    ori 7,7,0x0420@l\n"
"    stw 7,4(10)\n"
/* ---- mprotect [base,base+4K) -> RX(5); site 2 ---- */
"    mr 3,9\n"
"    li 4,4096\n"
"    li 5,5\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,2\n"
"    bl check_eq\n"
/* ---- mprotect [base+8K,base+12K) -> NONE(0); site 3 ---- */
"    lis 6,region@ha\n"
"    lwz 9,region@l(6)\n"
"    addi 3,9,8192\n"
"    li 4,4096\n"
"    li 5,0\n"
"    li 0,125\n"
"    .long 0x44000002\n"
"    mfcr 7\n"
"    rlwinm 7,7,4,31,31\n"
"    mr 3,7\n"
"    li 4,0\n"
"    li 5,3\n"
"    bl check_eq\n"
/* ---- site 4: read from the RX page ---- */
"    lis 6,region@ha\n"
"    lwz 9,region@l(6)\n"
"    lwz 3,0(9)\n"
"    lis 4,0xA5A5\n"
"    ori 4,4,0x5A5A@l\n"
"    li 5,4\n"
"    bl check_eq\n"
/* ---- site 5: read from the RW page ---- */
"    lwz 3,4096(9)\n"
"    lis 4,0x5A5A\n"
"    ori 4,4,0xA5A5@l\n"
"    li 5,5\n"
"    bl check_eq\n"
/* ---- site 6: write to the RW page reads back ---- */
"    lis 4,0x1234\n"
"    ori 4,4,0x5678@l\n"
"    stw 4,4100(9)\n"
"    lwz 3,4100(9)\n"
"    lis 4,0x1234\n"
"    ori 4,4,0x5678@l\n"
"    li 5,6\n"
"    bl check_eq\n"
/* ---- site 7: RX stub round trip (li + bcctr to CTR) ----
 * Two instructions fit before the RW page: the stub sets r11 to a
 * magic, then branches to CTR (resumed). Data-cache flush + isync
 * first, as in tests/test_p1_isa.c sites 40-42. */
"    lis 6,region@ha\n"
"    lwz 10,region@l(6)\n"
"    addi 10,10,4088\n"
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
"    li 5,7\n"
"    bl fail\n"
"resumed:\n"
"    mr 3,11\n"
"    li 4,0x5A\n"
"    li 5,7\n"
"    bl check_eq\n"
/* ---- sites 8-10: fault probes. Before each faulting access the
 * continuation address goes to resume_nip; the handler records si_addr
 * and resumes there (rather than nip += 4, which only suits faults
 * whose nip points at mapped code). ---- */
/* ---- site 8: write to the RX page faults exactly on the page ---- */
"    lis 6,saved_addr@ha\n"
"    li 7,0\n"
"    stw 7,saved_addr@l(6)\n"
"    lis 6,region@ha\n"
"    lwz 10,region@l(6)\n"
"    addi 7,31,after8-getpc\n"
"    lis 6,resume_nip@ha\n"
"    stw 7,resume_nip@l(6)\n"
"    li 3,0x11\n"
"    stw 3,0(10)\n"
"after8:\n"
"    lis 6,saved_addr@ha\n"
"    lwz 3,saved_addr@l(6)\n"
"    mr 4,10\n"
"    li 5,8\n"
"    bl check_eq\n"
/* ---- site 9: read from the guard page faults exactly on it ---- */
"    lis 6,saved_addr@ha\n"
"    li 7,0\n"
"    stw 7,saved_addr@l(6)\n"
"    addi 7,31,after9-getpc\n"
"    lis 6,resume_nip@ha\n"
"    stw 7,resume_nip@l(6)\n"
"    lwz 3,8192(10)\n"
"after9:\n"
"    lis 6,saved_addr@ha\n"
"    lwz 3,saved_addr@l(6)\n"
"    addi 4,10,8192\n"
"    li 5,9\n"
"    bl check_eq\n"
/* ---- site 10: write to the guard page faults exactly on it ---- */
"    lis 6,saved_addr@ha\n"
"    li 7,0\n"
"    stw 7,saved_addr@l(6)\n"
"    addi 7,31,after10-getpc\n"
"    lis 6,resume_nip@ha\n"
"    stw 7,resume_nip@l(6)\n"
"    li 3,0x22\n"
"    stw 3,8196(10)\n"
"after10:\n"
"    lis 6,saved_addr@ha\n"
"    lwz 3,saved_addr@l(6)\n"
"    addi 4,10,8196\n"
"    li 5,10\n"
"    bl check_eq\n"
/* ---- PASS + exit(0) ---- */
"    addi 3,31,s_pass-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
/* ---- SIGSEGV handler: save si_addr, resume at resume_nip ----
 * siginfo_t on PPC32 Linux is 3 ints (signo/errno/code) followed by
 * the fault union, so si_addr sits at offset 12 (not 16: that is the
 * 64-bit layout). */
"h_segv:\n"
"    lis 6,saved_addr@ha\n"
"    lwz 7,12(4)\n"
"    stw 7,saved_addr@l(6)\n"
"    lis 6,resume_nip@ha\n"
"    lwz 7,resume_nip@l(6)\n"
"    stw 7,0x140(5)\n"
"    blr\n"
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
"    .data\n"
"    .align 2\n"
"region: .long 0\n"
"saved_addr: .long 0\n"
"resume_nip: .long 0\n"
"sigact: .long 0, 0, 0, 0, 0\n"
);

#else /* host-native self-check of the same expectations */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf p6_jb;
static volatile unsigned long p6_fault;

static void p6_on_fault(int signo, siginfo_t *si, void *uc)
{
    (void)signo;
    (void)uc;
    p6_fault = (unsigned long)si->si_addr;
    siglongjmp(p6_jb, 1);
}

#define P6_CHECK(cond, id) do { \
        if (!(cond)) { \
            printf("FAIL %d\n", (id)); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    struct sigaction sa;
    long ps = sysconf(_SC_PAGESIZE);
    size_t stride;
    unsigned char *base;
    unsigned char *rx;
    unsigned char *rw;
    unsigned char *guard;
    unsigned v0 = 0xA5A55A5AU;
    unsigned v1 = 0x5A5AA5A5U;
    unsigned got;

    P6_CHECK(ps > 0, 1);
    stride = (size_t)ps;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p6_on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    P6_CHECK(sigaction(SIGSEGV, &sa, NULL) == 0, 1);
#ifdef SIGBUS
    P6_CHECK(sigaction(SIGBUS, &sa, NULL) == 0, 1);
#endif

    /* Three adjacent pages: RX | RW | NONE (strides are the host page
     * size; the 4 KiB adjacency is a guest-side property). */
    base = (unsigned char *)mmap(NULL, 3U * stride,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    P6_CHECK(base != MAP_FAILED, 1);
    rx = base;
    rw = base + stride;
    guard = base + 2U * stride;
    memcpy(rx, &v0, sizeof(v0));
    memcpy(rw, &v1, sizeof(v1));
    P6_CHECK(mprotect(rx, stride, PROT_READ | PROT_EXEC) == 0, 2);
    P6_CHECK(mprotect(guard, stride, PROT_NONE) == 0, 3);

    memcpy(&got, rx, sizeof(got));
    P6_CHECK(got == v0, 4);
    memcpy(&got, rw, sizeof(got));
    P6_CHECK(got == v1, 5);
    got = 0x12345678U;
    memcpy(rw + 4, &got, sizeof(got));
    memcpy(&got, rw + 4, sizeof(got));
    P6_CHECK(got == 0x12345678U, 6);

    /* Site 7 (RX execute round trip) has no portable host equivalent:
     * calling into a data page is platform-specific, so the host
     * check covers the permission split and the fault addresses. */

    /* Site 8: write to the RX page faults exactly on the page. */
    p6_fault = 0UL;
    if (sigsetjmp(p6_jb, 1) == 0) {
        *rx = 0x11;
        P6_CHECK(0, 8);
    } else {
        P6_CHECK(p6_fault == (unsigned long)rx, 8);
    }
    /* Site 9: read from the guard page faults exactly on it. */
    p6_fault = 0UL;
    if (sigsetjmp(p6_jb, 1) == 0) {
        got = *guard;
        (void)got;
        P6_CHECK(0, 9);
    } else {
        P6_CHECK(p6_fault == (unsigned long)guard, 9);
    }
    /* Site 10: write to the guard page faults exactly on it. */
    p6_fault = 0UL;
    if (sigsetjmp(p6_jb, 1) == 0) {
        guard[4] = 0x22;
        P6_CHECK(0, 10);
    } else {
        P6_CHECK(p6_fault == (unsigned long)(guard + 4), 10);
    }
    printf("PASS\n");
    return 0;
}

#endif
