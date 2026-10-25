/*
 * tests/test_p5_auxv.c — freestanding PPC32 Phase 5 auxv + /proc/self self-test
 *
 * A no-libc PowerPC 32-bit static ELF that checks the Phase 5 lane L5a
 * surface (docs/lanes/phase-5.md, card L5a): the initial-stack auxv
 * carries AT_PHDR/AT_ENTRY/AT_BASE/AT_HWCAP/AT_SECURE/AT_EXECFN, and
 * the synthetic /proc/self/{cmdline,maps,auxv} plus the /proc/self/exe
 * symlink agree with the loader-known values.
 *
 * Oracle notes (qemu-ppc 10.0, ground truth): argc counts the program
 * slot but argv[0] is NULL, so program identity comes from AT_EXECFN
 * (never argv[0]); cmdline entry 0 is empty and entries 1.. mirror
 * argv[1..]; maps names the executable path. The checks below hold on
 * the oracle and on the translator precisely because they anchor on
 * AT_EXECFN and skip index 0, and because every buffer stays small
 * (qemu serves big-BSS static binaries unreliably; total BSS ~2 KiB).
 *
 * Target path (#ifdef __powerpc__): freestanding C with raw sc
 * syscalls (sc = 0x44000002, nr in r0, args in r3..r5, E01 CR0.SO).
 * _start is a small asm stub that forwards the kernel stack pointer to
 * p5_main; all logic is plain C (no libc, no TOC use, no
 * multiply/divide path that matters), so no startup files are needed
 * beyond -nostdlib -static. Writes "PASS\n" + exit(0) on success, else
 * "FAIL id=<hex>\n" + exit(1).
 *
 * Check ids: 1 stack shape (argc, envp/auxv walk bounds), 2 AT_PHDR,
 * 3 AT_ENTRY, 4 AT_HWCAP, 5 AT_BASE nonzero, 6 AT_SECURE nonzero,
 * 7 AT_EXECFN missing/empty, 8 auxv file unusable, 9 file AT_ENTRY
 * missing/mismatch, a file AT_PHDR missing/mismatch, b0-b5 cmdline
 * (open/empty/entry0/overrun/bytes/trailing), c maps without the
 * executable basename, d0/d1 exe readlink (call/basename), e0/e1
 * exe open/ELF magic, f stat empty.
 *
 * Host path (#else): native self-check of the same expectations
 * (stack auxv via environ vs /proc/self/auxv, cmdline argv[0] prefix,
 * maps "[stack]"), with a synthetic fallback when /proc is absent
 * (e.g. macOS host). Build + run:
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     tests/test_p5_auxv.c -o /tmp/p5_selfcheck && /tmp/p5_selfcheck
 * must print PASS. Oracle comparison (qemu-ppc -cpu 750 / -cpu e500v2)
 * runs at RC5 via tools/build_fixture.sh + container.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifdef __powerpc__

#define P5_NR_EXIT 1U
#define P5_NR_READ 3U
#define P5_NR_WRITE 4U
#define P5_NR_OPEN 5U
#define P5_NR_CLOSE 6U
#define P5_NR_READLINK 85U

#define P5_AT_PHDR 3U
#define P5_AT_BASE 7U
#define P5_AT_ENTRY 9U
#define P5_AT_HWCAP 16U
#define P5_AT_SECURE 23U
#define P5_AT_EXECFN 31U

/* Small on purpose: every buffer is touched, total BSS stays ~2 KiB. */
#define P5_CMD_MAX 128U
#define P5_MAPS_MAX 512U
#define P5_AUXV_FILE_MAX 256U
#define P5_LINK_MAX 128U
#define P5_STAT_MAX 128U
#define P5_AUXV_PAIRS 32U

/* Compiler-generated copy insurance for -nostdlib (ILP32: unsigned
 * is size_t). The test itself only uses the p5_* helpers below. */
void *memcpy(void *d, const void *s, unsigned n)
{
    unsigned char *x = (unsigned char *)d;
    const unsigned char *y = (const unsigned char *)s;
    unsigned i;

    for (i = 0U; i < n; i++) {
        x[i] = y[i];
    }
    return d;
}

void *memset(void *d, int c, unsigned n)
{
    unsigned char *x = (unsigned char *)d;
    unsigned i;

    for (i = 0U; i < n; i++) {
        x[i] = (unsigned char)c;
    }
    return d;
}

/* Raw sc wrapper: kernel-style long (value, or negative errno). */
static long p5_sc(unsigned nr, unsigned a0, unsigned a1, unsigned a2)
{
    register unsigned r0 __asm__("r0") = nr;
    register unsigned r3 __asm__("r3") = a0;
    register unsigned r4 __asm__("r4") = a1;
    register unsigned r5 __asm__("r5") = a2;
    unsigned cr = 0U;

    /* cr is operand %4; %0-%3 are the r0/r3-r5 in-outs (mfcr must name
     * %4: naming %0 stores CR into r0 and leaves cr stale). */
    __asm__ volatile (
        ".long 0x44000002\n\t"
        "mfcr %4"
        : "+r" (r0), "+r" (r3), "+r" (r4), "+r" (r5), "=r" (cr)
        : : "memory", "cc", "r6", "r7", "r8", "r9", "r10", "r11", "r12");
    if ((cr & 0x10000000U) != 0U) {
        return -(long)r3;
    }
    return (long)r3;
}

static unsigned p5_strlen(const char *s)
{
    unsigned n = 0U;

    while (s[n] != '\0') {
        n++;
    }
    return n;
}

static int p5_memcmp(const void *a, const void *b, unsigned n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    unsigned i;

    for (i = 0U; i < n; i++) {
        if (x[i] != y[i]) {
            return (x[i] < y[i]) ? -1 : 1;
        }
    }
    return 0;
}

/* Basename: pointer past the last '/' (or the whole string). */
static const char *p5_base(const char *s)
{
    const char *b = s;

    while (*s != '\0') {
        if (*s == '/') {
            b = s + 1;
        }
        s++;
    }
    return b;
}

/* NUL-safe substring search (hay may hold cmdline NULs). */
static int p5_has(const char *hay, unsigned haylen, const char *ndl,
    unsigned ndl_len)
{
    unsigned i;

    if (ndl_len == 0U) {
        return 0;
    }
    if (ndl_len > haylen) {
        return 0;
    }
    for (i = 0U; i + ndl_len <= haylen; i++) {
        if (p5_memcmp(hay + i, ndl, ndl_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static void p5_print(const char *s, unsigned n)
{
    unsigned done = 0U;

    while (done < n) {
        long r = p5_sc(P5_NR_WRITE, 1U, (unsigned)(s + done), n - done);

        if (r <= 0L) {
            return;
        }
        done += (unsigned)r;
    }
}

/* Two hex digits (shifts only: no divide unit on the report path). */
static void p5_fail(unsigned id)
{
    char msg[12];
    const char pre[] = "FAIL id=";
    unsigned len = 0U;
    unsigned i = 0U;

    while (pre[i] != '\0') {
        msg[len] = pre[i];
        len++;
        i++;
    }
    {
        unsigned hi = (id >> 4) & 0xFU;
        unsigned lo = id & 0xFU;

        msg[len] = (char)((hi < 10U) ? ('0' + hi) : ('a' + hi - 10U));
        len++;
        msg[len] = (char)((lo < 10U) ? ('0' + lo) : ('a' + lo - 10U));
        len++;
    }
    msg[len] = '\n';
    len++;
    p5_print(msg, len);
    p5_sc(P5_NR_EXIT, 1U, 0U, 0U);
    for (;;) {
    }
}

static long p5_read_full(long fd, void *buf, unsigned max)
{
    unsigned total = 0U;

    while (total < max) {
        long n = p5_sc(P5_NR_READ, (unsigned)fd,
            (unsigned)((char *)buf + total), max - total);

        if (n < 0L) {
            return n;
        }
        if (n == 0L) {
            break;
        }
        total += (unsigned)n;
    }
    return (long)total;
}

static uint32_t p5_fval(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static char g_cmd[P5_CMD_MAX];
static char g_maps[P5_MAPS_MAX];
static unsigned char g_aux[P5_AUXV_FILE_MAX];
static char g_link[P5_LINK_MAX];
static char g_stat[P5_STAT_MAX];
static uint32_t s_auxv[2U * P5_AUXV_PAIRS];

__asm__(
".text\n"
"    .globl _start\n"
"    .align 2\n"
"_start:\n"
"    mr 3,1\n"
"    b p5_main\n"
);

void p5_main(unsigned ksp)
{
    uint32_t *w = (uint32_t *)(uintptr_t)ksp;
    uint32_t argc = w[0];
    uint32_t *ap;
    uint32_t *ep;
    uint32_t *avp;
    unsigned envc = 0U;
    unsigned i;
    unsigned pairs = 0U;
    uint32_t phdr = 0U;
    uint32_t entry = 0U;
    uint32_t base = 0U;
    uint32_t hwcap = 0U;
    uint32_t secure = 0U;
    uint32_t execfn_va = 0U;
    int have_phdr = 0;
    int have_entry = 0;
    int have_base = 0;
    int have_hwcap = 0;
    int have_secure = 0;
    int have_execfn = 0;
    const char *execfn;
    const char *bexec;
    unsigned bexeclen;
    long fd;
    long n;

    if (argc == 0U || argc > 64U) {
        p5_fail(1U);
    }
    ap = &w[1];
    ep = ap + argc + 1U;
    while (envc < 512U && ep[envc] != 0U) {
        envc++;
    }
    if (envc >= 512U) {
        p5_fail(1U);
    }
    avp = ep + envc + 1U;
    for (i = 0U; i < 64U; i++) {
        uint32_t k = avp[2U * i];
        uint32_t v = avp[2U * i + 1U];

        if (k == 0U) {
            break;
        }
        if (pairs < P5_AUXV_PAIRS) {
            s_auxv[2U * pairs] = k;
            s_auxv[2U * pairs + 1U] = v;
        }
        pairs++;
        switch (k) {
        case P5_AT_PHDR:
            phdr = v;
            have_phdr = 1;
            break;
        case P5_AT_BASE:
            base = v;
            have_base = 1;
            break;
        case P5_AT_ENTRY:
            entry = v;
            have_entry = 1;
            break;
        case P5_AT_HWCAP:
            hwcap = v;
            have_hwcap = 1;
            break;
        case P5_AT_SECURE:
            secure = v;
            have_secure = 1;
            break;
        case P5_AT_EXECFN:
            execfn_va = v;
            have_execfn = 1;
            break;
        default:
            break;
        }
    }
    if (i >= 64U) {
        p5_fail(1U);
    }
    if (have_phdr == 0 || phdr == 0U) {
        p5_fail(2U);
    }
    if (have_entry == 0 || entry == 0U) {
        p5_fail(3U);
    }
    if (have_hwcap == 0 || hwcap == 0U) {
        p5_fail(4U);
    }
    /* Static fixture: no interpreter, no privilege elevation. */
    if (have_base != 0 && base != 0U) {
        p5_fail(5U);
    }
    if (have_secure != 0 && secure != 0U) {
        p5_fail(6U);
    }
    if (have_execfn == 0 || execfn_va == 0U) {
        p5_fail(7U);
    }
    execfn = (const char *)(uintptr_t)execfn_va;
    bexec = p5_base(execfn);
    bexeclen = p5_strlen(bexec);
    if (bexeclen == 0U) {
        p5_fail(7U);
    }

    /* /proc/self/cmdline entries 1.. must repeat argv[1..] exactly
     * (index 0 is the program slot: empty on the oracle, the path on
     * the translator — skipped on both sides). */
    fd = p5_sc(P5_NR_OPEN, (unsigned)"/proc/self/cmdline", 0U, 0U);
    if (fd < 0L) {
        p5_fail(0xB0U);
    }
    n = p5_read_full(fd, g_cmd, P5_CMD_MAX);
    p5_sc(P5_NR_CLOSE, (unsigned)fd, 0U, 0U);
    if (n <= 0L) {
        p5_fail(0xB1U);
    }
    {
        unsigned coff = 0U;
        unsigned ai;

        while (coff < (unsigned)n && g_cmd[coff] != '\0') {
            coff++;
        }
        if (coff >= (unsigned)n) {
            p5_fail(0xB2U);
        }
        coff++;
        for (ai = 1U; ai < argc; ai++) {
            const char *a = (ap[ai] != 0U) ?
                (const char *)(uintptr_t)ap[ai] : "";
            unsigned al = p5_strlen(a);
            unsigned k;

            if (coff + al + 1U > (unsigned)n) {
                p5_fail(0xB3U);
            }
            for (k = 0U; k < al + 1U; k++) {
                if (g_cmd[coff + k] != a[k]) {
                    p5_fail(0xB4U);
                }
            }
            coff += al + 1U;
        }
        if (coff != (unsigned)n) {
            p5_fail(0xB5U);
        }
    }

    /* /proc/self/maps must name our executable (EXECFN basename). */
    fd = p5_sc(P5_NR_OPEN, (unsigned)"/proc/self/maps", 0U, 0U);
    if (fd < 0L) {
        p5_fail(0xCU);
    }
    n = p5_read_full(fd, g_maps, P5_MAPS_MAX);
    p5_sc(P5_NR_CLOSE, (unsigned)fd, 0U, 0U);
    if (n <= 0L) {
        p5_fail(0xCU);
    }
    if (p5_has(g_maps, (unsigned)n, bexec, bexeclen) == 0) {
        p5_fail(0xCU);
    }

    /* /proc/self/auxv must repeat the loader-known AT_ENTRY/AT_PHDR. */
    fd = p5_sc(P5_NR_OPEN, (unsigned)"/proc/self/auxv", 0U, 0U);
    if (fd < 0L) {
        p5_fail(8U);
    }
    n = p5_read_full(fd, g_aux, P5_AUXV_FILE_MAX);
    p5_sc(P5_NR_CLOSE, (unsigned)fd, 0U, 0U);
    if (n <= 0L || ((unsigned)n & 7U) != 0U) {
        p5_fail(8U);
    }
    {
        unsigned off;
        int fe = 0;
        int fp = 0;

        for (off = 0U; off + 8U <= (unsigned)n; off += 8U) {
            uint32_t k = p5_fval(&g_aux[off]);
            uint32_t v = p5_fval(&g_aux[off + 4U]);

            if (k == P5_AT_ENTRY) {
                fe = 1;
                if (v != entry) {
                    p5_fail(9U);
                }
            }
            if (k == P5_AT_PHDR) {
                fp = 1;
                if (v != phdr) {
                    p5_fail(0xAU);
                }
            }
        }
        if (fe == 0) {
            p5_fail(9U);
        }
        if (fp == 0) {
            p5_fail(0xAU);
        }
    }

    /* /proc/self/exe keeps symlink semantics: readlink names the same
     * program AT_EXECFN names (basename comparison: the oracle serves
     * the invoked absolute path, the translator its own argv[0]). */
    n = p5_sc(P5_NR_READLINK, (unsigned)"/proc/self/exe",
        (unsigned)g_link, P5_LINK_MAX);
    if (n <= 0L || n >= (long)P5_LINK_MAX) {
        p5_fail(0xD0U);
    }
    {
        unsigned total = (unsigned)n;
        unsigned start = total;

        while (start > 0U && g_link[start - 1U] != '/') {
            start--;
        }
        if (total - start != bexeclen ||
            p5_memcmp(g_link + start, bexec, bexeclen) != 0) {
            p5_fail(0xD1U);
        }
    }

    /* Opening exe reads the executable itself (ELF magic). */
    fd = p5_sc(P5_NR_OPEN, (unsigned)"/proc/self/exe", 0U, 0U);
    if (fd < 0L) {
        p5_fail(0xE0U);
    }
    {
        unsigned char magic[4];
        unsigned got = 0U;

        magic[0] = 0U;
        magic[1] = 0U;
        magic[2] = 0U;
        magic[3] = 0U;
        n = p5_read_full(fd, (char *)magic, 4U);
        got = (n > 0L) ? (unsigned)n : 0U;
        p5_sc(P5_NR_CLOSE, (unsigned)fd, 0U, 0U);
        if (got != 4U || magic[0] != 0x7FU || magic[1] != (unsigned char)'E' ||
            magic[2] != (unsigned char)'L' ||
            magic[3] != (unsigned char)'F') {
            p5_fail(0xE1U);
        }
    }

    /* /proc/self/stat exists and is non-empty. */
    fd = p5_sc(P5_NR_OPEN, (unsigned)"/proc/self/stat", 0U, 0U);
    if (fd < 0L) {
        p5_fail(0xFU);
    }
    n = p5_read_full(fd, g_stat, P5_STAT_MAX);
    p5_sc(P5_NR_CLOSE, (unsigned)fd, 0U, 0U);
    if (n <= 0L) {
        p5_fail(0xFU);
    }

    p5_print("PASS\n", 5U);
    p5_sc(P5_NR_EXIT, 0U, 0U, 0U);
    for (;;) {
    }
}

#else /* host-native self-check of the same expectations */

#include <stdio.h>
#include <string.h>

extern char **environ;

static int h_fail = 0;

#define HTEST(name, got, want)                                     \
    do {                                                           \
        unsigned long g_ = (unsigned long)(got);                   \
        unsigned long w_ = (unsigned long)(want);                  \
        if (g_ != w_) {                                            \
            printf("FAIL %s got=0x%lx want=0x%lx\n", name, g_, w_); \
            h_fail++;                                              \
        }                                                          \
    } while (0)

static int h_find_key(const unsigned long *av, unsigned long n,
    unsigned long key, unsigned long *val)
{
    unsigned long i;

    for (i = 0UL; i < n; i++) {
        if (av[2UL * i] == key) {
            *val = av[2UL * i + 1UL];
            return 1;
        }
    }
    return 0;
}

static int h_has(const char *hay, size_t haylen, const char *ndl)
{
    size_t nl = strlen(ndl);
    size_t i;

    if (nl == 0U) {
        return 1;
    }
    if (nl > haylen) {
        return 0;
    }
    for (i = 0U; i + nl <= haylen; i++) {
        if (memcmp(hay + i, ndl, nl) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *f = fopen("/proc/self/auxv", "rb");
    static unsigned long faux[64];
    size_t nread;
    size_t npairs;
    size_t i;
    unsigned long v = 0UL;
    unsigned long stack_entry = 0UL;
    int ok;
    char cmd[1024];
    char maps[32768];
    char *base;

    (void)argc;
    if (f == NULL) {
        /* No /proc (e.g. macOS host): same parser and file-shape
         * expectations against a synthetic auxv. */
        static const unsigned long saux[] = {
            3UL, 0x1000UL, 9UL, 0x2000UL, 7UL, 0UL,
            16UL, 0x8000000AUL, 23UL, 0UL, 0UL, 0UL
        };

        ok = h_find_key(saux, 6UL, 9UL, &v);
        HTEST("syn_entry_found", ok, 1);
        HTEST("syn_entry", v, 0x2000UL);
        ok = h_find_key(saux, 6UL, 3UL, &v);
        HTEST("syn_phdr_found", ok, 1);
        HTEST("syn_phdr", v, 0x1000UL);
        ok = h_find_key(saux, 6UL, 16UL, &v);
        HTEST("syn_hwcap_found", ok, 1);
        HTEST("syn_hwcap", v, 0x8000000AUL);
        ok = h_find_key(saux, 6UL, 7UL, &v);
        HTEST("syn_base_found", ok, 1);
        HTEST("syn_base", v, 0UL);
        ok = h_find_key(saux, 6UL, 23UL, &v);
        HTEST("syn_secure_found", ok, 1);
        HTEST("syn_secure", v, 0UL);
        if (h_has("xx[stack]yy", 10U, "[stack]") == 0) {
            printf("FAIL syn_maps\n");
            h_fail++;
        }
        if (h_fail != 0) {
            printf("FAILURES %d\n", h_fail);
            return 1;
        }
        printf("PASS\n");
        return 0;
    }
    nread = fread(faux, 1U, sizeof faux, f);
    fclose(f);
    HTEST("auxv_align", nread % (2U * sizeof(unsigned long)), 0U);
    npairs = nread / (2U * sizeof(unsigned long));

    ok = h_find_key(faux, (unsigned long)npairs, 9UL, &v);
    HTEST("entry_found", ok, 1);
    HTEST("entry_nonzero", (v != 0UL) ? 1 : 0, 1);
    ok = h_find_key(faux, (unsigned long)npairs, 3UL, &v);
    HTEST("phdr_found", ok, 1);
    HTEST("phdr_nonzero", (v != 0UL) ? 1 : 0, 1);
    ok = h_find_key(faux, (unsigned long)npairs, 16UL, &v);
    HTEST("hwcap_found", ok, 1);
    HTEST("hwcap_nonzero", (v != 0UL) ? 1 : 0, 1);
    ok = h_find_key(faux, (unsigned long)npairs, 23UL, &v);
    if (ok != 0) {
        HTEST("secure_zero", v, 0UL);
    }

    /* Stack auxv via environ (same layout the guest parses by hand). */
    {
        char **e = environ;
        unsigned long *sav;
        unsigned long sn = 0UL;

        while (*e != NULL) {
            e++;
        }
        sav = (unsigned long *)(e + 1);
        for (i = 0UL; i < 64UL; i++) {
            if (sav[2UL * i] == 0UL) {
                break;
            }
        }
        sn = i;
        ok = h_find_key(sav, sn, 9UL, &stack_entry);
        HTEST("stack_entry_found", ok, 1);
        ok = h_find_key(faux, (unsigned long)npairs, 9UL, &v);
        if (ok != 0) {
            HTEST("entry_match", v, stack_entry);
        }
    }

    /* cmdline starts with our own argv[0]. */
    f = fopen("/proc/self/cmdline", "rb");
    if (f == NULL) {
        printf("FAIL cmdline_open\n");
        return 1;
    }
    nread = fread(cmd, 1U, sizeof cmd, f);
    fclose(f);
    if (nread <= strlen(argv[0]) ||
        memcmp(cmd, argv[0], strlen(argv[0]) + 1U) != 0) {
        printf("FAIL cmdline\n");
        h_fail++;
    }

    /* maps describes a stack region. */
    f = fopen("/proc/self/maps", "rb");
    if (f == NULL) {
        printf("FAIL maps_open\n");
        return 1;
    }
    nread = fread(maps, 1U, sizeof maps, f);
    fclose(f);
    base = argv[0];
    (void)base;
    if (nread == 0U || h_has(maps, nread, "[stack]") == 0) {
        printf("FAIL maps\n");
        h_fail++;
    }

    if (h_fail != 0) {
        printf("FAILURES %d\n", h_fail);
        return 1;
    }
    printf("PASS\n");
    return 0;
}

#endif /* __powerpc__ */
