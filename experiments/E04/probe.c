/* Phase E lane E04 probe: PPC32 ucontext/mcontext (992 B) & SPE evr overlay.
 *
 * Models of Linux arch/powerpc UAPI (32-bit):
 *   asm/ucontext.h: struct mcontext { mc_gregs[48]; mc_fregs[33];
 *                     mc_pad[2]; mc_vregs[528] aligned(16); }
 *   asm/elf.h:      elf_gregset_t = unsigned int[48] (ELF_NGREG),
 *                   elf_fpregset_t = double[33] (ELF_NFPREG),
 *                   elf_vrregset_t = 16-byte units[33] (ELF_NVRREG),
 *                   ELF_NEVRREG 34 (SPE: evr[32] + acc-as-2).
 *   asm/ptrace.h:   PT_R0..PT_R31, PT_NIP..PT_RESULT/PT_DSCR indices.
 *   asm/stat.h:     struct stat64 (ppc32, 104 bytes).
 *
 * Host-compilable (native check) and powerpc-cross-compilable; the same
 * vectors run under qemu-ppc -cpu 750 / -cpu e500v2.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Replica of the ppc32 kernel mcontext. mc_vregs carries _Alignas(16) so
 * the compiler inserts the same 8-byte pad the kernel's mc_pad[2]
 * provides, placing mc_vregs at 0x1d0. */
struct ppc32_mcontext {
    uint32_t mc_gregs[48];
    double mc_fregs[33];
    uint32_t mc_pad[2];
    _Alignas(16) uint8_t mc_vregs[528];
};

/* SPE overlay at the start of mc_vregs (e500v2, CONFIG_SPE):
 * evr[32] = gpr_hi[0..31], then 64-bit acc, then 32-bit spefscr. */
struct ppc32_spe_overlay {
    uint32_t evr[32];
    uint64_t acc;
    uint32_t spefscr;
};

/* Replica of the ppc32 kernel struct stat64 (asm/stat.h). */
struct ppc32_stat64 {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint16_t __pad2;
    int64_t st_size;
    int32_t st_blksize;
    int64_t st_blocks;
    int32_t st_atime;
    uint32_t st_atime_nsec;
    int32_t st_mtime;
    uint32_t st_mtime_nsec;
    int32_t st_ctime;
    uint32_t st_ctime_nsec;
    uint32_t __unused4;
    uint32_t __unused5;
};

enum {
    MC_GPR0 = 0, MC_NIP = 32, MC_MSR = 33, MC_ORIG_R3 = 34,
    MC_CTR = 35, MC_LINK = 36, MC_XER = 37, MC_CCR = 38,
    MC_MQ = 39, MC_TRAP = 40, MC_DAR = 41, MC_DSISR = 42,
    MC_RESULT = 43, MC_DSCR = 44
};

static int fails = 0;

static void check_size(const char *name, size_t got, size_t want)
{
    printf("%-22s sizeof = 0x%lX (%lu) want 0x%lX %s\n", name,
        (unsigned long)got, (unsigned long)got,
        (unsigned long)want, got == want ? "ok" : "MISMATCH");
    if (got != want) {
        fails++;
    }
}

static void check_off(const char *name, size_t got, size_t want)
{
    printf("%-22s offset = 0x%lX (%lu) want 0x%lX %s\n", name,
        (unsigned long)got, (unsigned long)got,
        (unsigned long)want, got == want ? "ok" : "MISMATCH");
    if (got != want) {
        fails++;
    }
}

int main(void)
{
    /* mcontext geometry: 192 + 264 + 8 + 528 = 992. */
    check_size("mcontext", sizeof(struct ppc32_mcontext), 992u);
    check_off("mc_gregs", offsetof(struct ppc32_mcontext, mc_gregs), 0x0u);
    check_off("mc_fregs", offsetof(struct ppc32_mcontext, mc_fregs), 0xc0u);
    check_off("mc_pad", offsetof(struct ppc32_mcontext, mc_pad), 0x1c8u);
    check_off("mc_vregs", offsetof(struct ppc32_mcontext, mc_vregs), 0x1d0u);
    check_size("mc_gregs[48]", sizeof(uint32_t[48]), 192u);
    check_size("mc_fregs[33]", sizeof(double[33]), 264u);

    /* mc_gregs index map (asm/ptrace.h PT_* values). */
    printf("gregs: R0=%d R31=%d NIP=%d MSR=%d ORIG_R3=%d CTR=%d LINK=%d\n",
        MC_GPR0, MC_GPR0 + 31, MC_NIP, MC_MSR, MC_ORIG_R3, MC_CTR, MC_LINK);
    printf("gregs: XER=%d CCR=%d MQ=%d TRAP=%d DAR=%d DSISR=%d RESULT=%d DSCR=%d\n",
        MC_XER, MC_CCR, MC_MQ, MC_TRAP, MC_DAR, MC_DSISR, MC_RESULT, MC_DSCR);
    if (MC_GPR0 != 0 || MC_NIP != 32 || MC_MSR != 33 || MC_ORIG_R3 != 34 ||
        MC_CTR != 35 || MC_LINK != 36 || MC_XER != 37 || MC_CCR != 38 ||
        MC_MQ != 39 || MC_TRAP != 40 || MC_DAR != 41 || MC_DSISR != 42 ||
        MC_RESULT != 43 || MC_DSCR != 44) {
        printf("greg index map MISMATCH\n");
        fails++;
    }

    /* SPE overlay inside mc_vregs: 128 + 8 + 4 = 140 payload, 144 with
     * the 8-alignment tail pad from acc; still far below 528. */
    check_size("spe_overlay", sizeof(struct ppc32_spe_overlay), 144u);
    check_off("spe.evr", offsetof(struct ppc32_spe_overlay, evr), 0x0u);
    check_off("spe.acc", offsetof(struct ppc32_spe_overlay, acc), 128u);
    check_off("spe.spefscr", offsetof(struct ppc32_spe_overlay, spefscr), 136u);
    if (sizeof(struct ppc32_spe_overlay) > sizeof(((struct ppc32_mcontext *)0)->mc_vregs)) {
        printf("spe overlay overflows mc_vregs: MISMATCH\n");
        fails++;
    }
    printf("spe words: evr[i]<->word %d..%d acc<->words 32..33 spefscr<->word 34\n",
        0, 31);

    /* stat64 geometry: expect 104 bytes. */
    check_size("stat64", sizeof(struct ppc32_stat64), 104u);
    check_off("st_dev", offsetof(struct ppc32_stat64, st_dev), 0x0u);
    check_off("st_ino", offsetof(struct ppc32_stat64, st_ino), 0x8u);
    check_off("st_mode", offsetof(struct ppc32_stat64, st_mode), 0x10u);
    check_off("st_uid", offsetof(struct ppc32_stat64, st_uid), 0x18u);
    check_off("st_rdev", offsetof(struct ppc32_stat64, st_rdev), 0x20u);
    check_off("st_size", offsetof(struct ppc32_stat64, st_size), 0x30u);
    check_off("st_blksize", offsetof(struct ppc32_stat64, st_blksize), 0x38u);
    check_off("st_blocks", offsetof(struct ppc32_stat64, st_blocks), 0x40u);
    check_off("st_atime", offsetof(struct ppc32_stat64, st_atime), 0x48u);
    check_off("st_mtime", offsetof(struct ppc32_stat64, st_mtime), 0x50u);
    check_off("st_ctime", offsetof(struct ppc32_stat64, st_ctime), 0x58u);

    printf(fails == 0 ? "E04 probe: ALL OK\n" : "E04 probe: %d FAILURES\n",
        fails);
    return fails != 0;
}
