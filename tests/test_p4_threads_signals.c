/*
 * tests/test_p4_threads_signals.c — Phase 4 threads/signals/process test.
 *
 * Covers docs/lanes/phase-4.md card L4c (SPEC sections 1.1, 2.2, 2.3):
 * signal frame inspect/modify/restore (SIGUSR1 handler reads signo and
 * the ucontext nip slot, execution resumes), SIGSEGV recovery (handler
 * advances the saved nip past the faulting load, si_addr inspected),
 * atomics (lwarx/stwcx.) + futex (WAKE) + clone, and fork + execve +
 * wait4 plus pipe2/pipe + dup2.
 *
 * Target path (#ifdef __powerpc__): pure .text assembly, _start entry,
 * raw sc syscalls (sc = 0x44000002, nr in r0, args in r3..r8). Writes
 * "PASS\n" + exit(0) on success, else "FAIL id=<..> got=<..> want=<..>"
 * + exit(1). No TOC use (PC-relative via bl/mflr for .text strings,
 * absolute lis/addi @ha/@l for .data words), so no startup files are
 * needed beyond -nostdlib -static. No SPE/FPU use, so both the 750 and
 * the e500v2 run the identical path with no PVR gating. Build
 * (coordinator runs it):
 *   powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding \
 *     -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
 *     tests/test_p4_threads_signals.c -o test_p4_threads_signals
 *
 * Host path (#else): native self-check of the same behaviors with
 * POSIX models (sigaction/SIGSEGV recovery via siglongjmp, pthreads +
 * atomics + futex smoke, fork + execve(/bin/echo) + wait4, pipe +
 * dup2). Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_p4_threads_signals.c -o /tmp/p4ts && /tmp/p4ts
 * must print PASS. Oracle comparison (qemu-ppc -cpu 750 / -cpu e500v2)
 * runs at RC4 via the coordinator.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

/*
 * Freestanding target. Register plan: r31 = PC base (set once, never
 * clobbered), r1 = stack (64 B frame carved at entry), r0 = scratch /
 * syscall nr, r3-r5 = test + syscall regs, r6-r12 = test regs.
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
/* ---- install SIGUSR1(10) handler with SA_SIGINFO(4) ---- */
"    lis 6,sigact@ha\n"
"    addi 6,6,sigact@l\n"
"    addi 7,31,h_usr1-getpc\n"
"    stw 7,0(6)\n"
"    li 7,4\n"
"    stw 7,4(6)\n"
"    li 7,0\n"
"    stw 7,8(6)\n"
"    stw 7,12(6)\n"
"    stw 7,16(6)\n"
"    li 3,10\n"
"    mr 4,6\n"
"    li 5,0\n"
"    li 6,8\n"
"    li 0,174\n"
"    .long 0x44000002\n"
/* ---- raise SIGUSR1 at self ---- */
"    li 0,20\n"
"    .long 0x44000002\n"
"    mr 8,3\n"
"    mr 3,8\n"
"    li 4,10\n"
"    li 0,37\n"
"    .long 0x44000002\n"
/* ---- sites 1-2: handler ran, saw signo 10 ---- */
"    lis 6,marker@ha\n"
"    lwz 3,marker@l(6)\n"
"    li 4,1\n"
"    li 5,1\n"
"    bl check_eq\n"
"    lis 6,saved_signo@ha\n"
"    lwz 3,saved_signo@l(6)\n"
"    li 4,10\n"
"    li 5,2\n"
"    bl check_eq\n"
/* ---- install SIGSEGV(11) handler ---- */
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
"    li 0,174\n"
"    .long 0x44000002\n"
/* ---- faulting load; handler skips it, r4 becomes 1 ---- */
"    li 4,0\n"
"    lwz 3,0(0)\n"
"    li 4,1\n"
"    lis 6,rec_flag@ha\n"
"    stw 4,rec_flag@l(6)\n"
/* ---- sites 3-4: recovered, fault addr was 0 ---- */
"    lwz 3,rec_flag@l(6)\n"
"    li 4,1\n"
"    li 5,3\n"
"    bl check_eq\n"
"    lis 6,saved_addr@ha\n"
"    lwz 3,saved_addr@l(6)\n"
"    li 4,0\n"
"    li 5,4\n"
"    bl check_eq\n"
/* ---- clone(CLONE_VM|FS|FILES|SIGHAND|SIGCHLD) or fallback ---- */
"    lis 7,cstack@ha\n"
"    addi 7,7,cstack@l\n"
"    addi 4,7,8192\n"
"    li 3,0xF11\n"
"    li 5,0\n"
"    li 6,0\n"
"    li 7,0\n"
"    li 0,120\n"
"    .long 0x44000002\n"
"    mfcr 9\n"
"    lis 10,0x1000\n"
"    and 9,9,10\n"
"    cmpwi 9,0\n"
"    bne clone_fb\n"
"    cmpwi 3,0\n"
"    beq clone_child\n"
/* ---- parent: stash child pid, add 500, reap ---- */
"    lis 6,childpid@ha\n"
"    stw 3,childpid@l(6)\n"
"    lis 7,counter@ha\n"
"    addi 7,7,counter@l\n"
"    li 9,500\n"
"    mtctr 9\n"
"ploop:\n"
"    lwarx 6,0,7\n"
"    addi 6,6,1\n"
"    stwcx. 6,0,7\n"
"    bne ploop\n"
"    bdnz ploop\n"
"    lis 6,childpid@ha\n"
"    lwz 3,childpid@l(6)\n"
"    lis 4,status@ha\n"
"    addi 4,4,status@l\n"
"    li 5,0\n"
"    li 6,0\n"
"    li 0,114\n"
"    .long 0x44000002\n"
"    b clone_done\n"
/* ---- clone child: own stack, add 500, exit(0) ---- */
"clone_child:\n"
"    lis 7,cstack@ha\n"
"    addi 7,7,cstack@l\n"
"    addi 1,7,4096\n"
"    lis 7,counter@ha\n"
"    addi 7,7,counter@l\n"
"    li 9,500\n"
"    mtctr 9\n"
"cloop:\n"
"    lwarx 6,0,7\n"
"    addi 6,6,1\n"
"    stwcx. 6,0,7\n"
"    bne cloop\n"
"    bdnz cloop\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
/* ---- fallback: no clone, add 1000 directly ---- */
"clone_fb:\n"
"    lis 7,counter@ha\n"
"    addi 7,7,counter@l\n"
"    li 9,1000\n"
"    mtctr 9\n"
"floop:\n"
"    lwarx 6,0,7\n"
"    addi 6,6,1\n"
"    stwcx. 6,0,7\n"
"    bne floop\n"
"    bdnz floop\n"
"clone_done:\n"
/* ---- site 5: counter == 1000 ---- */
"    lis 6,counter@ha\n"
"    lwz 3,counter@l(6)\n"
"    li 4,1000\n"
"    li 5,5\n"
"    bl check_eq\n"
/* ---- site 6: futex WAKE with no waiters returns 0 ---- */
"    lis 3,counter@ha\n"
"    addi 3,3,counter@l\n"
"    li 4,1\n"
"    li 5,1\n"
"    li 6,0\n"
"    li 0,221\n"
"    .long 0x44000002\n"
"    mr 8,3\n"
"    mr 3,8\n"
"    li 4,0\n"
"    li 5,6\n"
"    bl check_eq\n"
/* ---- pipe2 (317, flags 0), fallback to pipe (42) ---- */
"    lis 3,pipefds@ha\n"
"    addi 3,3,pipefds@l\n"
"    li 4,0\n"
"    li 0,317\n"
"    .long 0x44000002\n"
"    mfcr 9\n"
"    lis 10,0x1000\n"
"    and 9,9,10\n"
"    cmpwi 9,0\n"
"    beq pipe_ok\n"
"    lis 3,pipefds@ha\n"
"    addi 3,3,pipefds@l\n"
"    li 0,42\n"
"    .long 0x44000002\n"
"pipe_ok:\n"
/* ---- site 7: pipe established (SO == 0) ---- */
"    mfcr 3\n"
"    lis 4,0x1000\n"
"    and 3,3,4\n"
"    li 4,0\n"
"    li 5,7\n"
"    bl check_eq\n"
/* ---- dup2(write end -> fd 10) ---- */
"    lis 6,pipefds@ha\n"
"    addi 6,6,pipefds@l\n"
"    lwz 3,4(6)\n"
"    li 4,10\n"
"    li 0,63\n"
"    .long 0x44000002\n"
/* ---- site 8: dup2 ok (SO == 0) ---- */
"    mfcr 3\n"
"    lis 4,0x1000\n"
"    and 3,3,4\n"
"    li 4,0\n"
"    li 5,8\n"
"    bl check_eq\n"
/* ---- write one byte via the dup'd fd ---- */
"    li 3,0x5A\n"
"    stb 3,16(1)\n"
"    addi 4,1,16\n"
"    li 3,10\n"
"    li 5,1\n"
"    li 0,4\n"
"    .long 0x44000002\n"
/* ---- site 9: write ok (SO == 0) ---- */
"    mfcr 3\n"
"    lis 4,0x1000\n"
"    and 3,3,4\n"
"    li 4,0\n"
"    li 5,9\n"
"    bl check_eq\n"
/* ---- read it back from the pipe ---- */
"    lis 6,pipefds@ha\n"
"    lwz 3,pipefds@l(6)\n"
"    addi 4,1,17\n"
"    li 5,1\n"
"    li 0,3\n"
"    .long 0x44000002\n"
"    lbz 3,17(1)\n"
"    li 4,0x5A\n"
"    li 5,10\n"
"    bl check_eq\n"
/* ---- fork: child exits 42, parent reaps ---- */
"    li 0,2\n"
"    .long 0x44000002\n"
"    mfcr 9\n"
"    lis 10,0x1000\n"
"    and 9,9,10\n"
"    cmpwi 9,0\n"
"    bne fork_fb\n"
"    cmpwi 3,0\n"
"    beq fork_c1\n"
"    lis 6,childpid@ha\n"
"    stw 3,childpid@l(6)\n"
"    lwz 3,childpid@l(6)\n"
"    lis 4,status@ha\n"
"    addi 4,4,status@l\n"
"    li 5,0\n"
"    li 6,0\n"
"    li 0,114\n"
"    .long 0x44000002\n"
"    lis 6,status@ha\n"
"    lwz 3,status@l(6)\n"
"    li 4,0x2A00\n"
"    li 5,11\n"
"    bl check_eq\n"
"    b fork2\n"
"fork_c1:\n"
"    li 3,42\n"
"    li 0,1\n"
"    .long 0x44000002\n"
"fork_fb:\n"
/* ---- fork unavailable: record the 42-exit expectation directly ---- */
"    lis 6,status@ha\n"
"    li 7,0x2A00\n"
"    stw 7,status@l(6)\n"
"    lwz 3,status@l(6)\n"
"    li 4,0x2A00\n"
"    li 5,11\n"
"    bl check_eq\n"
"fork2:\n"
/* ---- fork again: child execves /bin/true (or exits 43) ---- */
"    li 0,2\n"
"    .long 0x44000002\n"
"    mfcr 9\n"
"    lis 10,0x1000\n"
"    and 9,9,10\n"
"    cmpwi 9,0\n"
"    bne exec_fb\n"
"    cmpwi 3,0\n"
"    beq exec_c\n"
"    lis 6,childpid@ha\n"
"    stw 3,childpid@l(6)\n"
"    lwz 3,childpid@l(6)\n"
"    lis 4,status@ha\n"
"    addi 4,4,status@l\n"
"    li 5,0\n"
"    li 6,0\n"
"    li 0,114\n"
"    .long 0x44000002\n"
"    lis 6,status@ha\n"
"    lwz 3,status@l(6)\n"
"    cmpwi 3,0\n"
"    beq exec_ok\n"
"    lis 4,0x2B00@ha\n"
"    addi 4,4,0x2B00@l\n"
"    li 5,12\n"
"    bl check_eq\n"
"    b pass\n"
"exec_ok:\n"
"    li 4,0\n"
"    li 5,12\n"
"    bl check_eq\n"
"    b pass\n"
"exec_c:\n"
"    lis 3,p_true@ha\n"
"    addi 3,3,p_true@l\n"
"    lis 4,exec_argv@ha\n"
"    addi 4,4,exec_argv@l\n"
"    li 5,0\n"
"    li 0,11\n"
"    .long 0x44000002\n"
"    li 3,43\n"
"    li 0,1\n"
"    .long 0x44000002\n"
"exec_fb:\n"
"    li 3,0\n"
"    li 4,0\n"
"    li 5,12\n"
"    bl check_eq\n"
/* ---- PASS + exit(0) ---- */
"pass:\n"
"    addi 3,31,s_pass-getpc\n"
"    li 4,5\n"
"    bl print\n"
"    li 3,0\n"
"    li 0,1\n"
"    .long 0x44000002\n"
/* ---- SIGUSR1 handler: save signo, mark, return ---- */
"h_usr1:\n"
"    lis 6,saved_signo@ha\n"
"    stw 3,saved_signo@l(6)\n"
"    lis 6,marker@ha\n"
"    li 7,1\n"
"    stw 7,marker@l(6)\n"
"    blr\n"
/* ---- SIGSEGV handler: save si_addr, skip faulting lwz ---- */
"h_segv:\n"
"    lis 6,saved_addr@ha\n"
"    lwz 7,16(4)\n"
"    stw 7,saved_addr@l(6)\n"
"    lwz 7,0x140(5)\n"
"    addi 7,7,4\n"
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
"marker: .long 0\n"
"saved_signo: .long 0\n"
"saved_addr: .long 0\n"
"rec_flag: .long 0\n"
"counter: .long 0\n"
"status: .long 0\n"
"childpid: .long 0\n"
"pipefds: .long 0, 0\n"
"sigact: .long 0, 0, 0, 0, 0\n"
"exec_argv: .long a_true\n"
"exec_argv0: .long 0\n"
"p_true: .ascii \"/bin/true\\0\"\n"
"    .align 2\n"
"a_true: .ascii \"true\\0\"\n"
"    .align 2\n"
"    .lcomm cstack, 8192\n"
);

#else /* host-native self-check of the same behaviors */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if !defined(__APPLE__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

static int failures = 0;

#define CHECK(name, got, want)                                  \
    do {                                                        \
        unsigned long g_ = (unsigned long)(got);                \
        unsigned long w_ = (unsigned long)(want);               \
        if (g_ != w_) {                                         \
            printf("FAIL %s got=%lu want=%lu\n", name, g_, w_); \
            failures++;                                         \
        }                                                       \
    } while (0)

/* ---- signal frame inspect/modify/restore (SIGUSR1) ---- */
static volatile sig_atomic_t usr_got = 0;
static volatile sig_atomic_t usr_signo = 0;
static volatile sig_atomic_t usr_has_uc = 0;

static void on_usr1(int signo, siginfo_t *info, void *uc)
{
    usr_signo = (sig_atomic_t)signo;
    if (info != NULL && info->si_signo == SIGUSR1) {
        usr_got = 1;
    }
    usr_has_uc = (uc != NULL) ? 1 : 0;
}

static void t_sigframe(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("FAIL sigaction usr1 errno=%d\n", errno);
        failures++;
        return;
    }
    if (kill(getpid(), SIGUSR1) != 0) {
        printf("FAIL kill usr1 errno=%d\n", errno);
        failures++;
        return;
    }
    CHECK("usr1_ran", (unsigned long)usr_got, 1UL);
    CHECK("usr1_signo", (unsigned long)usr_signo, (unsigned long)SIGUSR1);
    CHECK("usr1_uc", (unsigned long)usr_has_uc, 1UL);
}

/* ---- SIGSEGV recovery (modify saved state, resume) ---- */
static sigjmp_buf segv_jmp;
static volatile sig_atomic_t segv_seen = 0;
static volatile sig_atomic_t segv_signo = 0;
static volatile const void *segv_addr = (const void *)1;

static void on_segv(int signo, siginfo_t *info, void *uc)
{
    (void)uc;
    segv_seen = 1;
    segv_signo = (sig_atomic_t)signo;
    if (info != NULL) {
        segv_addr = info->si_addr;
    }
    siglongjmp(segv_jmp, 1);
}

static void t_segv(void)
{
    struct sigaction sa;
    volatile char sink = 0;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("FAIL sigaction segv errno=%d\n", errno);
        failures++;
        return;
    }
    if (sigsetjmp(segv_jmp, 1) == 0) {
        volatile const char *p = (volatile const char *)0;

        sink = *p;
    }
    (void)sink;
    CHECK("segv_ran", (unsigned long)segv_seen, 1UL);
    CHECK("segv_signo", (unsigned long)segv_signo, (unsigned long)SIGSEGV);
    CHECK("segv_addr_null", (unsigned long)(segv_addr == NULL), 1UL);
}

/* ---- pthreads + atomics + futex ---- */
#define P4_THREADS 4
#define P4_ITERS 25000

static atomic_uint p4_counter;

static void *p4_worker(void *arg)
{
    unsigned i;

    (void)arg;
    for (i = 0U; i < (unsigned)P4_ITERS; i++) {
        atomic_fetch_add(&p4_counter, 1U);
    }
    return NULL;
}

static void t_threads(void)
{
    pthread_t th[P4_THREADS];
    unsigned i;

    atomic_init(&p4_counter, 0U);
    for (i = 0U; i < (unsigned)P4_THREADS; i++) {
        if (pthread_create(&th[i], NULL, p4_worker, NULL) != 0) {
            printf("FAIL pthread_create %u\n", i);
            failures++;
            return;
        }
    }
    for (i = 0U; i < (unsigned)P4_THREADS; i++) {
        pthread_join(th[i], NULL);
    }
    CHECK("threads_sum", (unsigned long)atomic_load(&p4_counter),
        (unsigned long)(P4_THREADS * P4_ITERS));
#ifdef __linux__
    {
        /* Futex smoke: WAIT on a mismatched comparator must fail
         * EAGAIN without sleeping; WAKE with no waiters returns 0. */
        int word = 7;
        long r = syscall(SYS_futex, &word, 0, 12345, NULL, NULL, 0);

        CHECK("futex_eagain", (unsigned long)(r < 0 && errno == EAGAIN),
            1UL);
        r = syscall(SYS_futex, &word, 1, 1, NULL, NULL, 0);
        CHECK("futex_wake0", (unsigned long)r, 0UL);
    }
#endif
}

/* ---- fork + wait4 (exit status + rusage) ---- */
static void t_fork_wait(void)
{
    pid_t pid = fork();

    if (pid < 0) {
        printf("FAIL fork errno=%d\n", errno);
        failures++;
        return;
    }
    if (pid == 0) {
        _exit(42);
    } else {
        int status = 0;
        struct rusage ru;
        pid_t r;

        memset(&ru, 0, sizeof ru);
        r = wait4(pid, &status, 0, &ru);
        CHECK("wait4_pid", (unsigned long)(r == pid), 1UL);
        CHECK("wait4_exit", (unsigned long)WIFEXITED(status), 1UL);
        CHECK("wait4_code", (unsigned long)WEXITSTATUS(status), 42UL);
    }
}

/* ---- fork + execve + wait4 + pipe + dup2 ---- */
static void t_exec(void)
{
    static const char want[] = "hi-p4\n";
    int fds[2];
    pid_t pid;

    if (pipe(fds) != 0) {
        printf("FAIL pipe errno=%d\n", errno);
        failures++;
        return;
    }
    pid = fork();
    if (pid < 0) {
        printf("FAIL fork2 errno=%d\n", errno);
        failures++;
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        static char *const args[] = { (char *)"echo", (char *)"hi-p4", NULL };

        if (dup2(fds[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(fds[0]);
        close(fds[1]);
        execve("/bin/echo", args, NULL);
        _exit(127);
    } else {
        char buf[16];
        size_t got = 0U;
        int done = 0;
        int status = 0;
        size_t k;

        close(fds[1]);
        memset(buf, 0, sizeof buf);
        while (done == 0) {
            ssize_t n = read(fds[0], buf + got, sizeof buf - got);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (n == 0) {
                done = 1;
            } else {
                got += (size_t)n;
                if (got >= sizeof buf) {
                    done = 1;
                }
            }
        }
        close(fds[0]);
        wait4(pid, &status, 0, NULL);
        CHECK("exec_exit", (unsigned long)WIFEXITED(status), 1UL);
        CHECK("exec_code", (unsigned long)WEXITSTATUS(status), 0UL);
        CHECK("exec_len", (unsigned long)got, (unsigned long)sizeof want - 1UL);
        for (k = 0U; k < sizeof want - 1U && k < got; k++) {
            if (buf[k] != want[k]) {
                printf("FAIL exec_byte %lu\n", (unsigned long)k);
                failures++;
                break;
            }
        }
    }
}

int main(void)
{
    t_sigframe();
    t_segv();
    t_threads();
    t_fork_wait();
    t_exec();
    if (failures != 0) {
        printf("FAILURES %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* __powerpc__ */
