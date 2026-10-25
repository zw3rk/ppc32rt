#!/bin/sh
#
# tools/p6_host_check.sh — Lane L6a host-contract checks (phase-6.md, L6a)
#
# Exercises the Wave 1 CLI + /dev/a32host contract in src/main.c and
# src/rt32/ppc32_host.c: no-device fallback, PPC32RT_HOST=none,
# --no-host, --window (good + bad), --execfn custom argv[0],
# --image-fd load, and AT_EXECFN presence. Prints PASS/FAIL per check
# and exits 0 only when every check passes. Plain POSIX sh.
#
# Run inside the lane container (Debian + a powerpc toolchain; the
# script tries powerpc gccs, then clang+lld, then nix pkgsCross):
#   docker run --rm --name ppc32rt-l6a-<tag> --memory 2g --cpus 2 \
#     --platform linux/arm64 -v "$PWD:/w" -w /w debian:bookworm-slim \
#     sh -c "apt-get update && apt-get install -y make gcc file \
#       clang lld && sh tools/p6_host_check.sh"
# Every step is wall-clock bounded by the outer docker timeout.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$self_dir/.." && pwd)
p6=$root/_build/p6
guest=$p6/guest_p6

npass=0
nfail=0
ok() { npass=$((npass + 1)); echo "PASS: $1"; }
bad() { nfail=$((nfail + 1)); echo "FAIL: $1"; }

# tmo <cmd...> — bound one translator run when timeout(1) exists.
tmo() {
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=10s 60s "$@"
    else
        "$@"
    fi
}

if [ "$(uname -s)" != "Linux" ]; then
    echo "p6_host_check: Linux container required (have $(uname -s))" >&2
    exit 2
fi

mkdir -p "$p6"

# 1. Build the translator (native aarch64 cc in the container; clean
# first so objects from another toolchain are never mixed in). The
# Makefile's strict -D_POSIX_C_SOURCE hides MAP_ANONYMOUS/struct statx
# on glibc, so build with _GNU_SOURCE (the rt32 sources define it
# themselves; the nix musl cross is unaffected).
echo "p6_host_check: building ppc32rt" >&2
make -C "$root" clean >/dev/null 2>&1 || true
mkdir -p "$p6"
if ! make -C "$root" build 'CC=cc -D_GNU_SOURCE' >/dev/null 2>"$p6/make.log"; then
    bad "make build"
    sed 's/^/  /' "$p6/make.log" >&2
    echo "p6_host_check: $npass passed, $nfail failed" >&2
    exit 1
fi
ok "make build"
RT=$root/_build/ppc32rt

# 2. Emit the freestanding probe guest: prints argv0/argv1/argv2 from
# the initial stack plus the AT_EXECFN string, then P6HOST-OK, exit 0
# (FAIL + exit 1 when the stack/auxv walk breaks).
cat > "$p6/guest_p6.c" <<'EOF'
#include <stdint.h>

#ifdef __powerpc__

#define P6_NR_EXIT 1U
#define P6_NR_WRITE 4U
#define P6_AT_EXECFN 31U

/* -nostdlib copy insurance (ILP32: unsigned is size_t). */
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
static long p6_sc(unsigned nr, unsigned a0, unsigned a1, unsigned a2)
{
    register unsigned r0 __asm__("r0") = nr;
    register unsigned r3 __asm__("r3") = a0;
    register unsigned r4 __asm__("r4") = a1;
    register unsigned r5 __asm__("r5") = a2;
    unsigned cr = 0U;

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

static unsigned p6_strlen(const char *s)
{
    unsigned n = 0U;

    while (s[n] != '\0') {
        n++;
    }
    return n;
}

static void p6_puts(const char *s)
{
    unsigned n = p6_strlen(s);
    unsigned done = 0U;

    while (done < n) {
        long r = p6_sc(P6_NR_WRITE, 1U,
            (unsigned)(s + done), n - done);

        if (r <= 0L) {
            return;
        }
        done += (unsigned)r;
    }
}

static void p6_fail(void)
{
    p6_puts("FAIL\n");
    p6_sc(P6_NR_EXIT, 1U, 0U, 0U);
    for (;;) {
    }
}

__asm__(
".text\n"
"    .globl _start\n"
"    .align 2\n"
"_start:\n"
"    mr 3,1\n"
"    b p6_main\n"
);

void p6_main(unsigned ksp)
{
    uint32_t *w = (uint32_t *)(uintptr_t)ksp;
    uint32_t argc;
    uint32_t *ap;
    uint32_t *ep;
    uint32_t *avp;
    unsigned envc = 0U;
    unsigned i;
    const char *a0;
    const char *a1 = "";
    const char *a2 = "";
    const char *execfn = "";

    argc = w[0];
    if (argc == 0U || argc > 256U) {
        p6_fail();
    }
    ap = &w[1];
    a0 = (const char *)(uintptr_t)ap[0];
    if (argc > 1U) {
        a1 = (const char *)(uintptr_t)ap[1];
    }
    if (argc > 2U) {
        a2 = (const char *)(uintptr_t)ap[2];
    }
    ep = ap + argc + 1U;
    while (envc < 1024U && ep[envc] != 0U) {
        envc++;
    }
    if (envc >= 1024U) {
        p6_fail();
    }
    avp = ep + envc + 1U;
    for (i = 0U; i < 64U; i++) {
        uint32_t k = avp[2U * i];
        uint32_t v = avp[2U * i + 1U];

        if (k == 0U) {
            break;
        }
        if (k == P6_AT_EXECFN && v != 0U) {
            execfn = (const char *)(uintptr_t)v;
        }
    }
    p6_puts("argv0=");
    p6_puts(a0);
    p6_puts("\nargv1=");
    p6_puts(a1);
    p6_puts("\nargv2=");
    p6_puts(a2);
    p6_puts("\nexecfn=");
    p6_puts(execfn);
    p6_puts("\nP6HOST-OK\n");
    p6_sc(P6_NR_EXIT, 0U, 0U, 0U);
    for (;;) {
    }
}

#else
#error "p6 probe guest builds for __powerpc__ only"
#endif
EOF

# 3. Build the guest with the first powerpc toolchain that works:
# native powerpc gccs, then clang+lld with a powerpc target (Debian
# bookworm carries no big-endian powerpc gcc), then nix pkgsCross
# (the SPEC cross toolchain). The output must verify as a PPC32 MSB
# static ELF via file(1) when present.
verify_guest() {
    [ -x "$guest" ] || return 1
    if command -v file >/dev/null 2>&1; then
        case $(file -b "$guest") in
            *"ELF 32-bit MSB"*PowerPC*) return 0 ;;
            *) return 1 ;;
        esac
    fi
    return 0
}
built=""
# shellcheck disable=SC2086
for cc in ${PPC_CC:-} powerpc-linux-gnu-gcc powerpc-unknown-linux-gnu-gcc \
    powerpc-linux-musl-gcc powerpc-unknown-linux-gnueabi-gcc; do
    [ -n "$cc" ] || continue
    if command -v "$cc" >/dev/null 2>&1 &&
        "$cc" -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
            -fno-pie -no-pie -fno-stack-protector \
            -o "$guest" "$p6/guest_p6.c" 2>"$p6/cc.log" &&
        verify_guest; then
        built=$cc
        break
    fi
done
if [ -z "$built" ] && command -v clang >/dev/null 2>&1 && \
    command -v ld.lld >/dev/null 2>&1; then
    if clang --target=powerpc-unknown-linux-gnu \
        -std=c11 -Wall -Wextra -ffreestanding -nostdlib -static -O2 \
        -fno-pie -no-pie -fno-stack-protector -fuse-ld=lld \
        -o "$guest" "$p6/guest_p6.c" 2>"$p6/cc.log" &&
        verify_guest; then
        built="clang --target=powerpc-unknown-linux-gnu"
    fi
fi
if [ -z "$built" ] && command -v nix >/dev/null 2>&1; then
    for spec in \
        "nixpkgs#pkgsCross.ppc-embedded.stdenv.cc:powerpc-unknown-linux-gnueabi-gcc" \
        "nixpkgs#pkgsCross.musl-powerpc.stdenv.cc:powerpc-unknown-linux-musl-gcc"; do
        attr=${spec%%:*}
        tuple=${spec##*:}
        if timeout --kill-after=10s 90s nix shell "$attr" -c "$tuple" \
            -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
            -fno-pie -no-pie -fno-stack-protector \
            -o "$guest" "$p6/guest_p6.c" 2>"$p6/cc.log" &&
            verify_guest; then
            built="nix $attr"
            break
        fi
    done
fi
if [ -z "$built" ]; then
    bad "powerpc guest build (no powerpc gcc, clang+lld, or nix pkgsCross)"
    sed 's/^/  /' "$p6/cc.log" >&2
    echo "p6_host_check: $npass passed, $nfail failed" >&2
    exit 1
fi
ok "guest build ($built)"
if command -v file >/dev/null 2>&1; then
    ok "guest is PPC32 static ELF ($(file -b "$guest"))"
fi

# out_of <file> -- <cmd...> — run, save stdout, report nonzero with stderr.
out_of() {
    out_file=$1; shift
    if tmo "$@" >"$out_file" 2>"$p6/lasterr"; then
        return 0
    else
        rc=$?
        echo "  exit=$rc stderr: $(tr '\n' ' ' < "$p6/lasterr")" >&2
        return "$rc"
    fi
}

has_line() { grep -qF -- "$1" "$2"; }

# 4. No-device fallback (+ default path/argv[0] + AT_EXECFN presence).
if [ -e /dev/a32host ]; then
    echo "p6_host_check: note: /dev/a32host present (fallback untestable)" >&2
else
    echo "p6_host_check: note: /dev/a32host absent (fallback path)" >&2
fi
if out_of "$p6/o1" "$RT" -- "$guest"; then
    has_line "argv0=$guest" "$p6/o1" && has_line "P6HOST-OK" "$p6/o1" \
        && ok "default run (argv0=path, guest executes)" \
        || bad "default run output ($(tr '\n' ' ' < "$p6/o1"))"
    grep -q '^execfn=.' "$p6/o1" \
        && ok "AT_EXECFN present" \
        || bad "AT_EXECFN missing/empty"
else
    bad "default run"
fi

# 5. PPC32RT_HOST=none and --no-host skip the probe.
if out_of "$p6/o2" env PPC32RT_HOST=none "$RT" -- "$guest"; then
    has_line "P6HOST-OK" "$p6/o2" && ok "PPC32RT_HOST=none" \
        || bad "PPC32RT_HOST=none output"
else
    bad "PPC32RT_HOST=none"
fi
if out_of "$p6/o3" "$RT" --no-host -- "$guest"; then
    has_line "P6HOST-OK" "$p6/o3" && ok "--no-host" \
        || bad "--no-host output"
else
    bad "--no-host"
fi

# 6. --window good (explicit 4 GiB base) + PPC32RT_WINDOW good.
if out_of "$p6/o4" "$RT" --window 0x100000000 -- "$guest"; then
    has_line "P6HOST-OK" "$p6/o4" && ok "--window 0x100000000" \
        || bad "--window 0x100000000 output"
else
    bad "--window 0x100000000"
fi
if out_of "$p6/o5" env PPC32RT_WINDOW=0x100000000 "$RT" -- "$guest"; then
    has_line "P6HOST-OK" "$p6/o5" && ok "PPC32RT_WINDOW=0x100000000" \
        || bad "PPC32RT_WINDOW good output"
else
    bad "PPC32RT_WINDOW=0x100000000"
fi

# 7. --window / PPC32RT_WINDOW bad values fail hard (nonzero exit).
if "$RT" --window banana -- "$guest" >"$p6/x1" 2>&1; then
    bad "--window banana unexpectedly succeeded"
else
    ok "--window banana fails"
fi
if "$RT" --window 0xffffffffffffffff -- "$guest" >"$p6/x2" 2>&1; then
    bad "--window sentinel unexpectedly succeeded"
else
    ok "--window sentinel rejected"
fi
if "$RT" --window 0x123 -- "$guest" >"$p6/x3" 2>&1; then
    bad "--window 0x123 unexpectedly succeeded"
else
    ok "--window 0x123 reservation fails"
fi
if env PPC32RT_WINDOW=banana "$RT" -- "$guest" >"$p6/x4" 2>&1; then
    bad "PPC32RT_WINDOW=banana unexpectedly succeeded"
else
    ok "PPC32RT_WINDOW=banana fails"
fi
if "$RT" --image-fd xyz -- "$guest" >"$p6/x5" 2>&1; then
    bad "--image-fd xyz unexpectedly succeeded"
else
    ok "--image-fd xyz rejected"
fi

# 8. --execfn: the image loads from PATH while argv after -- stays
# verbatim (custom argv[0] decoupled from the path); a missing --execfn
# path fails.
if out_of "$p6/o6" "$RT" --execfn "$guest" -- custom-argv0 extra1 extra2; then
    if has_line "argv0=custom-argv0" "$p6/o6" \
        && has_line "argv1=extra1" "$p6/o6" \
        && has_line "argv2=extra2" "$p6/o6" \
        && has_line "P6HOST-OK" "$p6/o6"; then
        ok "--execfn custom argv[0] verbatim"
    else
        bad "--execfn output ($(tr '\n' ' ' < "$p6/o6"))"
    fi
else
    bad "--execfn run"
fi
if "$RT" --execfn /nonexistent-p6-path -- argv0 >"$p6/x6" 2>&1; then
    bad "--execfn missing path unexpectedly succeeded"
else
    ok "--execfn missing path fails"
fi

# 9. --image-fd: ELF loads from the open descriptor (fd 3 here); the
# loader closes exactly that fd after mapping and touches no other fd
# (guest stdout on fd 1 proves the rest survived).
if out_of "$p6/o7" "$RT" --image-fd 3 -- fdimg-argv0 3<"$guest"; then
    if has_line "argv0=fdimg-argv0" "$p6/o7" \
        && has_line "P6HOST-OK" "$p6/o7"; then
        ok "--image-fd load"
    else
        bad "--image-fd output ($(tr '\n' ' ' < "$p6/o7"))"
    fi
else
    bad "--image-fd run"
fi

# 10. Combined --image-fd + --execfn.
if out_of "$p6/o8" "$RT" --image-fd 4 --execfn /combo/path -- combo-argv0 c1 4<"$guest"; then
    if has_line "argv0=combo-argv0" "$p6/o8" \
        && has_line "argv1=c1" "$p6/o8" \
        && grep -q '^execfn=.' "$p6/o8" \
        && has_line "P6HOST-OK" "$p6/o8"; then
        ok "--image-fd + --execfn combined"
    else
        bad "combined output ($(tr '\n' ' ' < "$p6/o8"))"
    fi
else
    bad "--image-fd + --execfn run"
fi

echo "p6_host_check: $npass passed, $nfail failed"
[ "$nfail" -eq 0 ]
