#!/bin/sh
#
# tools/p7_cxx.sh — Phase 7 lane H4 C++17 gate (exceptions/RTTI/TLS).
#
# Builds tests/test_h4_cxx17.cc with the powerpc C++ driver (static) and
# runs the oracle/engine matrix: qemu-ppc -cpu 750 golden vs --interp and
# --dbt (stdout bytes + exit status must agree) plus --difftest EQUAL.
# -cpu e500v2 is best-effort: the static libstdc++/libc startup executes
# classic-FPU/VMX instructions that are illegal on Book-E, so the oracle
# itself SIGILLs there (same documented class as the RC5 E1 and RC2 IFUNC
# negatives); an oracle failure is recorded as SKIP, an oracle pass
# requires the engines to match too.
#
# Every build/qemu step is wrapped in timeout --kill-after=30s.
#
# Environment overrides:
#   PPC32RT  translator binary (default _build/ppc32rt; rebuilt with
#            `make build` when missing)
#
# Usage: sh tools/p7_cxx.sh
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

STEP_TIMEOUT="timeout --kill-after=30s"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
PPC32RT=${PPC32RT:-"$root/_build/ppc32rt"}
OUTDIR="$root/_build/cxx"
FIX="$root/_build/test_h4_cxx17"

log() {
    printf 'p7_cxx: %s\n' "$*"
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "missing required tool: $1"
        log "lane container setup: apt-get install -y g++-powerpc-linux-gnu qemu-user file make"
        exit 2
    fi
}

need powerpc-linux-gnu-g++
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
mkdir -p "$OUTDIR" _build

log "build test_h4_cxx17 (static C++17)"
$STEP_TIMEOUT 180s powerpc-linux-gnu-g++ -std=c++17 -static -pthread -O2 \
    tests/test_h4_cxx17.cc -o _build/test_h4_cxx17

fail=0
pass=0

# run_case <label> <cpu> — oracle golden vs both engines.
run_case() {
    label=$1
    cpu=$2
    base="$OUTDIR/${label}-${cpu}"
    # Caller runs run_case with `set +e` (errexit stays off for this whole
    # body); this function must not toggle `set` itself.
    $STEP_TIMEOUT 60s qemu-ppc -cpu "$cpu" "$FIX" >"$base-oracle.out" 2>"$base-oracle.err"
    echo "$?" >"$base-oracle.rc"
    orc=$(cat "$base-oracle.rc")
    log "$label [$cpu] oracle exit=$orc"
    if [ "$orc" != 0 ]; then
        return 1
    fi
    for eng in interp dbt; do
        $STEP_TIMEOUT 90s "$PPC32RT" "--$eng" -- "$FIX" \
            >"$base-$eng.out" 2>"$base-$eng.err"
        echo "$?" >"$base-$eng.rc"
        erc=$(cat "$base-$eng.rc")
        if [ "$erc" != "$orc" ]; then
            log "DIVERGENCE: $label [$cpu/$eng] exit=$erc != oracle $orc"
            fail=$((fail + 1))
        elif cmp -s "$base-oracle.out" "$base-$eng.out"; then
            log "identical: $label [$cpu/$eng] (exit=$erc)"
            pass=$((pass + 1))
        else
            log "DIVERGENCE: $label [$cpu/$eng] stdout differs"
            fail=$((fail + 1))
        fi
    done
    return 0
}

log "oracle/engine matrix (750, required)"
if run_case test_h4_cxx17 750; then
    :
else
    log "DIVERGENCE: test_h4_cxx17 [750] oracle itself failed"
    fail=$((fail + 1))
fi

log "difftest (interp vs dbt, required)"
set +e
$STEP_TIMEOUT 120s "$PPC32RT" --difftest -- "$FIX" \
    >"$OUTDIR/difftest.out" 2>"$OUTDIR/difftest.err"
drc=$?
set -e
if [ "$drc" = 0 ] && grep -q "DIFFTEST: EQUAL" "$OUTDIR/difftest.out"; then
    log "identical: difftest EQUAL"
    pass=$((pass + 1))
else
    log "DIVERGENCE: difftest exit=$drc (want 0 + DIFFTEST: EQUAL)"
    fail=$((fail + 1))
fi

log "oracle/engine matrix (e500v2, best-effort)"
set +e
run_case test_h4_cxx17 e500v2
erc=$?
set -e
if [ "$erc" != 0 ]; then
    log "SKIP e500v2: oracle cannot start the static C++ fixture here"
    log "SKIP e500v2: (classic-FPU/VMX in libc startup SIGILLs on Book-E;"
    log "SKIP e500v2: same class as the RC5 E1 / RC2 IFUNC negatives)"
fi

log "pass=$pass divergences=$fail"
if [ "$fail" -ne 0 ]; then
    exit 1
fi
log "all outputs identical"
exit 0
