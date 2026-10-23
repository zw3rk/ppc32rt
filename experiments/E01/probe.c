/*
 * Phase E lane E01 probe: PPC32 `sc` syscall convention.
 *
 * Subject: `sc` encoding, syscall number/argument registers, the CR0.SO
 * error flag with +errno in r3, and 64-bit argument pair placement
 * (high word first).
 *
 * Build (host syntax check, always runnable):
 *   cc -fsyntax-only -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     experiments/E01/probe.c
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -o /tmp/e01probe experiments/E01/probe.c && /tmp/e01probe
 *
 * Cross (PowerPC 32-bit) and run under the ground-truth oracle:
 *   powerpc-linux-gnu-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra \
 *     -Werror -static -o _build/e01probe experiments/E01/probe.c
 *   qemu-ppc -cpu 750      _build/e01probe
 *   qemu-ppc -cpu e500v2   _build/e01probe
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* PowerPC `sc` instruction word and CR0.SO mask (SPEC 2.3). */
#define E01_SC_INSN 0x44000002u
#define E01_CR0_SO 0x10000000u
#define E01_MAX_ERRNO 4095

/* Linux errno values relevant to the test vectors below. These are Linux
 * numbers, not the host's (e.g. ENOSYS differs on macOS), so spell them
 * out instead of using host errno macros. */
#define E01_LINUX_EPERM 1
#define E01_LINUX_ENOSYS 38

/* `sc`: primary opcode 17 (bits 0:5), fixed suffix 0b10 (bits 30:31). */
_Static_assert((E01_SC_INSN >> 26) == 17u, "sc primary opcode must be 17");
_Static_assert((E01_SC_INSN & 3u) == 2u, "sc fixed suffix bits must be 10b");
/* CR0 occupies word bits 0:3; SO is the low bit of each CR field, so
 * CR0.SO is word bit 3. Matches Linux `regs->ccr |= 0x10000000`. */
_Static_assert(E01_CR0_SO == (1u << 28), "CR0.SO must be word bit 3");

/*
 * Minimal mirror of the SPEC 2.1 unified context prefix. Only the fields
 * this lane touches (gpr[3] result, cr flag word). Compile-time offsets
 * must match SPEC: gpr at 0x000, gpr_hi at 0x080, nip at 0x100,
 * lr 0x104, ctr 0x108, cr 0x10c.
 */
struct e01_ctx_prefix {
    uint32_t gpr[32];
    uint32_t gpr_hi[32];
    uint32_t nip;
    uint32_t lr;
    uint32_t ctr;
    uint32_t cr;
    uint32_t xer;
    uint32_t fpscr;
    uint32_t spefscr;
};

_Static_assert(offsetof(struct e01_ctx_prefix, gpr) == 0x000u,
               "gpr must sit at context offset 0x000");
_Static_assert(offsetof(struct e01_ctx_prefix, gpr_hi) == 0x080u,
               "gpr_hi must sit at context offset 0x080");
_Static_assert(offsetof(struct e01_ctx_prefix, nip) == 0x100u,
               "nip must sit at context offset 0x100");
_Static_assert(offsetof(struct e01_ctx_prefix, lr) == 0x104u,
               "lr must sit at context offset 0x104");
_Static_assert(offsetof(struct e01_ctx_prefix, ctr) == 0x108u,
               "ctr must sit at context offset 0x108");
_Static_assert(offsetof(struct e01_ctx_prefix, cr) == 0x10cu,
               "cr must sit at context offset 0x10c");

/*
 * Host-runnable model of the kernel return path for `sc` syscalls
 * (Linux arch/powerpc/kernel/interrupt.c, syscall_exit_prepare):
 *   if (r3 is in [-MAX_ERRNO, -1]) { r3 = -r3; ccr |= 0x10000000; }
 * i.e. error is signalled by CR0.SO=1 with r3 = +errno; success leaves
 * CR0.SO=0 with r3 = return value. The emulator (SPEC 2.3) owns ctx->cr,
 * so it clears SO explicitly on success.
 */
static void e01_kernel_to_user(int32_t kret, uint32_t *r3_out,
                               uint32_t *cr_out)
{
    if (kret < 0 && kret >= -E01_MAX_ERRNO) {
        *r3_out = (uint32_t)(-(int32_t)kret);
        *cr_out = E01_CR0_SO;
    } else {
        *r3_out = (uint32_t)kret;
        *cr_out = 0u;
    }
}

static int e01_is_error(uint32_t cr)
{
    return (cr & E01_CR0_SO) != 0u;
}

/* 64-bit syscall argument model: high word first (Linux merge_64). */
static uint64_t e01_merge_64(uint32_t hi, uint32_t lo)
{
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static int failures = 0;

static void e01_check(const char *name, int32_t kret, uint32_t want_r3,
                      int want_err)
{
    uint32_t r3 = 0u;
    uint32_t cr = 0u;
    int got_err = 0;
    e01_kernel_to_user(kret, &r3, &cr);
    got_err = e01_is_error(cr);
    if (r3 != want_r3 || got_err != want_err) {
        (void)printf("FAIL %-14s kret=%d r3=%u(0x%x) so=%d\n", name,
                     (int)kret, r3, r3, got_err);
        failures++;
    } else {
        (void)printf("ok   %-14s kret=%d r3=%u(0x%x) so=%d\n", name,
                     (int)kret, r3, r3, got_err);
    }
}

#ifdef __powerpc__
/*
 * Target-only path: issue a raw `sc` (encoded explicitly so the probe
 * also pins the opcode) and capture r3 + CR.
 */
static void e01_raw_sc(uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2,
                       uint32_t a3, uint32_t a4, uint32_t a5,
                       uint32_t *r3_out, uint32_t *cr_out)
{
    register uint32_t r0 __asm__("r0") = nr;
    register uint32_t r3 __asm__("r3") = a0;
    register uint32_t r4 __asm__("r4") = a1;
    register uint32_t r5 __asm__("r5") = a2;
    register uint32_t r6 __asm__("r6") = a3;
    register uint32_t r7 __asm__("r7") = a4;
    register uint32_t r8 __asm__("r8") = a5;
    uint32_t cr = 0u;
    uint32_t r3res = 0u;
    __asm__ volatile(".long 0x44000002\n\t"
                     "mfcr %1"
                     : "=r"(r3res), "=r"(cr)
                     : "r"(r0), "r"(r3), "r"(r4), "r"(r5), "r"(r6),
                       "r"(r7), "r"(r8)
                     : "memory", "cr0");
    *r3_out = r3res;
    *cr_out = cr;
}

static void e01_target_probes(void)
{
    uint32_t r3 = 0u;
    uint32_t cr = 0u;
    /* getpid (__NR_getpid == 20 on powerpc): expect SO=0. */
    e01_raw_sc(20u, 0u, 0u, 0u, 0u, 0u, 0u, &r3, &cr);
    (void)printf("target getpid: r3=%u so=%d (want so=0, r3>0)\n", r3,
                 e01_is_error(cr));
    if (e01_is_error(cr) || r3 == 0u) {
        failures++;
    }
    /* Bogus syscall number: expect SO=1, r3 == ENOSYS (38). */
    e01_raw_sc(0x7ffffffu, 0u, 0u, 0u, 0u, 0u, 0u, &r3, &cr);
    (void)printf("target bad-nr: r3=%u so=%d (want so=1 r3=%u)\n", r3,
                 e01_is_error(cr), (unsigned)E01_LINUX_ENOSYS);
    if (!e01_is_error(cr) || r3 != (uint32_t)E01_LINUX_ENOSYS) {
        failures++;
    }
}
#endif

int main(void)
{
    uint64_t pair = 0u;
    (void)printf("e01 sc=0x%08x po=%u suffix=%u\n", E01_SC_INSN,
                 (unsigned)(E01_SC_INSN >> 26), (unsigned)(E01_SC_INSN & 3u));
    (void)printf("e01 cr0_so=0x%08x gpr3_off=0x%x cr_off=0x%x\n", E01_CR0_SO,
                 (unsigned)offsetof(struct e01_ctx_prefix, gpr[3]),
                 (unsigned)offsetof(struct e01_ctx_prefix, cr));

    /* Return-path vectors: (kernel-internal kret) -> (user r3, SO). */
    e01_check("success-0", 0, 0u, 0);
    e01_check("success-fd", 3, 3u, 0);
    e01_check("success-nread", 38, 38u, 0); /* 38 w/o SO is data, not err */
    e01_check("err-eperm", -E01_LINUX_EPERM, 1u, 1);
    e01_check("err-enosys", -E01_LINUX_ENOSYS, 38u, 1);
    e01_check("err-max", -E01_MAX_ERRNO, 4095u, 1);
    /* Boundary: -4096 is outside [-MAX_ERRNO,-1], kernel leaves it alone. */
    e01_check("neg-beyond", -4096, (uint32_t)0xfffff000u, 0);

    /* 64-bit pair packing: high word first. */
    pair = e01_merge_64(1u, 2u);
    (void)printf("e01 pair hi=1 lo=2 -> 0x%llx (want 0x100000002)\n",
                 (unsigned long long)pair);
    if (pair != 0x100000002ull) {
        failures++;
    }
    pair = e01_merge_64(0xdeadbeefu, 0xcafef00du);
    if ((uint32_t)(pair >> 32) != 0xdeadbeefu ||
        (uint32_t)pair != 0xcafef00du) {
        (void)printf("FAIL pair round-trip\n");
        failures++;
    } else {
        (void)printf("ok   pair round-trip hi=0xdeadbeef lo=0xcafef00d\n");
    }

#ifdef __powerpc__
    e01_target_probes();
#else
    (void)printf("e01 target sc probes skipped (not __powerpc__)\n");
#endif

    if (failures != 0) {
        (void)printf("e01 RESULT: %d FAILURES\n", failures);
        return 1;
    }
    (void)printf("e01 RESULT: PASS\n");
    return 0;
}
