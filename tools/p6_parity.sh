#!/bin/sh
#
# tools/p6_parity.sh — Phase 6 lane L6b full parity sweep (dual-engine,
# dual-CPU vs qemu-ppc goldens) + adjacent-4 KiB permission coverage.
#
# Runs INSIDE the Phase 6 lane container (Debian --platform linux/arm64
# with gcc-powerpc-linux-gnu, libc6-dev-powerpc-cross, qemu-user, file,
# make, gcc): every build/Docker/qemu-ppc step is wrapped in
# timeout --kill-after=30s. Re-runs, under --interp and --dbt on both
# CPUs vs qemu-ppc goldens with 0 divergences (stdout bytes + exit
# status): test_p1_isa, test_p2_libc, test_p3_fp_spe,
# test_p4_threads_signals, test_p5_auxv, test_p5_dyn (+ the new
# test_p6_perms: RX-next-to-RW RELRO-style split with exact si_addr
# fault checks), plus tools/qualify_busybox.sh, plus
# tools/p6_host_check.sh when L6a has merged.
#
# CPU gating (documented oracle negatives, both reproduced here):
#   - freestanding static fixtures (p1/p3/p4/p5_auxv/p6_perms): 750 +
#     e500v2 (p3 self-dispatches on PVR).
#   - test_p2_libc (static libc): 750 only (RC2 IFUNC note: the static
#     startup SIGILLs on -cpu e500v2).
#   - test_p5_dyn + BusyBox (dynamic): 750 only (RC5 E1: Debian
#     powerpc userspace SIGILLs on -cpu e500v2).
#
# Environment overrides:
#   PPC32RT  translator binary (default _build/ppc32rt; rebuilt with
#            `make build` when missing)
#   SYSROOT  Debian powerpc sysroot (default /usr/powerpc-linux-gnu)
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: sh tools/p6_parity.sh

set -eu

STEP_TIMEOUT="timeout --kill-after=30s"
SYSROOT=${SYSROOT:-/usr/powerpc-linux-gnu}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
PPC32RT=${PPC32RT:-"$root/_build/ppc32rt"}
OUTDIR="$root/_build/parity"

log() {
    printf 'p6_parity: %s\n' "$*"
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "missing required tool: $1"
        exit 2
    fi
}

need powerpc-linux-gnu-gcc
need qemu-ppc
need timeout
need make
need cmp

if [ ! -x "$PPC32RT" ]; then
    log "building translator ($PPC32RT missing)"
    $STEP_TIMEOUT 280s make build
fi
if [ ! -x "$PPC32RT" ]; then
    log "translator not executable: $PPC32RT"
    exit 2
fi
if [ ! -d "$SYSROOT" ]; then
    log "sysroot missing: $SYSROOT"
    exit 2
fi
mkdir -p "$OUTDIR" _build

fail=0
pass=0

# build_static <name> — freestanding fixture via build_fixture.sh.
build_static() {
    log "build $1"
    $STEP_TIMEOUT 120s sh tools/build_fixture.sh "tests/$1.c" \
        "_build/$1" >/dev/null
}

log "building fixtures"
for t in test_p1_isa test_p3_fp_spe test_p4_threads_signals \
    test_p5_auxv test_p6_perms; do
    build_static "$t"
done
log "build test_p2_libc (static libc)"
$STEP_TIMEOUT 120s powerpc-linux-gnu-gcc -static -O2 tests/test_p2_libc.c \
    -o _build/test_p2_libc
log "build test_p5_dyn + companion .so"
$STEP_TIMEOUT 120s powerpc-linux-gnu-gcc -O2 -fPIC -shared \
    tests/test_p5_dynlib.c -o _build/test_p5_dynlib.so
$STEP_TIMEOUT 120s powerpc-linux-gnu-gcc -O2 -no-pie tests/test_p5_dyn.c \
    -o _build/test_p5_dyn -ldl

# run_case <label> <elf> <cpu> <dyn:0|1> — oracle golden vs both
# engines; stdout bytes and exit status must all agree.
run_case() {
    label=$1
    elf=$2
    cpu=$3
    dyn=$4
    base="$OUTDIR/${label}-${cpu}"
    o_out="$base-oracle.out"
    o_rc="$base-oracle.rc"

    if [ "$dyn" = 1 ]; then
        # shellcheck disable=SC2086
        set +e
        $STEP_TIMEOUT 60s qemu-ppc -cpu "$cpu" -L "$SYSROOT" \
            "$root/_build/$elf" >"$o_out" 2>"$base-oracle.err"
        echo "$?" >"$o_rc"
        set -e
    else
        set +e
        $STEP_TIMEOUT 60s qemu-ppc -cpu "$cpu" "$root/_build/$elf" \
            >"$o_out" 2>"$base-oracle.err"
        echo "$?" >"$o_rc"
        set -e
    fi
    orc=$(cat "$o_rc")
    log "$label [$cpu] oracle exit=$orc"
    if [ "$orc" != 0 ]; then
        log "DIVERGENCE: $label [$cpu] oracle itself failed (exit=$orc)"
        fail=$((fail + 1))
        return 0
    fi
    for eng in interp dbt; do
        e_out="$base-$eng.out"
        e_rc="$base-$eng.rc"
        set +e
        if [ "$dyn" = 1 ]; then
            $STEP_TIMEOUT 60s "$PPC32RT" "--$eng" \
                --sysroot "$SYSROOT" -- "$root/_build/$elf" \
                >"$e_out" 2>"$base-$eng.err"
            echo "$?" >"$e_rc"
        else
            $STEP_TIMEOUT 60s "$PPC32RT" "--$eng" -- \
                "$root/_build/$elf" >"$e_out" 2>"$base-$eng.err"
            echo "$?" >"$e_rc"
        fi
        set -e
        erc=$(cat "$e_rc")
        if [ "$erc" != "$orc" ]; then
            log "DIVERGENCE: $label [$cpu/$eng] exit=$erc != oracle $orc"
            fail=$((fail + 1))
        elif cmp -s "$o_out" "$e_out"; then
            log "identical: $label [$cpu/$eng] (exit=$erc)"
            pass=$((pass + 1))
        else
            log "DIVERGENCE: $label [$cpu/$eng] stdout differs"
            fail=$((fail + 1))
        fi
    done
}

log "static freestanding fixtures (both CPUs)"
for t in test_p1_isa test_p3_fp_spe test_p4_threads_signals \
    test_p5_auxv test_p6_perms; do
    for cpu in 750 e500v2; do
        run_case "$t" "$t" "$cpu" 0
    done
done

log "static libc fixture (750 only; e500v2 SIGILLs, RC2 IFUNC note)"
run_case test_p2_libc test_p2_libc 750 0

log "dynamic fixture (750 only; e500v2 SIGILLs, RC5 E1)"
run_case test_p5_dyn test_p5_dyn 750 1

log "busybox qualification"
set +e
$STEP_TIMEOUT 850s sh tools/qualify_busybox.sh >/dev/null 2>"$OUTDIR/busybox.err"
brc=$?
set -e
if [ "$brc" = 0 ]; then
    log "identical: qualify_busybox.sh exit=0"
    pass=$((pass + 1))
else
    log "DIVERGENCE: qualify_busybox.sh exit=$brc"
    fail=$((fail + 1))
fi

if [ -x tools/p6_host_check.sh ]; then
    log "L6a host contract check"
    set +e
    $STEP_TIMEOUT 280s sh tools/p6_host_check.sh >/dev/null 2>"$OUTDIR/host_check.err"
    hrc=$?
    set -e
    if [ "$hrc" = 0 ]; then
        log "identical: p6_host_check.sh exit=0"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: p6_host_check.sh exit=$hrc"
        fail=$((fail + 1))
    fi
else
    log "SKIP p6_host_check.sh (L6a has not merged yet)"
fi

log "pass=$pass divergences=$fail"
if [ "$fail" -ne 0 ]; then
    exit 1
fi
log "all outputs identical"
exit 0
