#!/bin/sh
#
# tools/p7_coremark.sh — Lane H3 CoreMark 6-step loop reproduction.
#
# Runs INSIDE the lane container (Debian --platform linux/arm64 with
# gcc-powerpc-linux-gnu, libc6-dev-powerpc-cross, qemu-user, file,
# make, gcc): every build/Docker/qemu-ppc step is wrapped in
# timeout --kill-after=30s. Fetches CoreMark, builds two powerpc
# static binaries (-O0 baseline, -O2 fixed), and runs the canonical
# 2K performance workload (args: 0x0 0x0 0x66 <iters> 7 1 2000):
#   - auto-calibrated runs (iters 0, each engine self-tunes to ~10 s,
#     every run must print "Correct operation validated"),
#   - fixed 6000-iteration runs of the -O0 binary on all three
#     engines (identical work; asserts equal crcfinal and
#     dbt Iterations/Sec > interp Iterations/Sec).
# Exit 0 only when every assertion in docs/h3-coremark.md holds.
#
# Environment overrides:
#   PPC32RT  translator binary (default _build/ppc32rt; rebuilt with
#            `make build` when missing)
#   COREMARK_SRC  CoreMark checkout dir (default _build/coremark)
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: sh tools/p7_coremark.sh

set -eu

STEP_TIMEOUT="timeout --kill-after=30s"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
PPC32RT=${PPC32RT:-"$root/_build/ppc32rt"}
COREMARK_SRC=${COREMARK_SRC:-"$root/_build/coremark"}
OUTDIR="$root/_build/h3"
COREMARK_URL="https://github.com/eembc/coremark.git"

log() {
    printf 'p7_coremark: %s\n' "$*"
}

fail() {
    printf 'p7_coremark: FAIL: %s\n' "$*" >&2
    exit 1
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "missing required tool: $1"
    fi
}

need powerpc-linux-gnu-gcc
need qemu-ppc
need timeout
need make
need file
need awk

# CPU pinning is best-effort noise control; plain runs stay valid.
PIN=""
if command -v taskset >/dev/null 2>&1 && taskset -c 5 true >/dev/null 2>&1; then
    PIN="taskset -c 5"
fi

if [ ! -x "$PPC32RT" ]; then
    log "building translator ($PPC32RT missing)"
    $STEP_TIMEOUT 280s make build
fi
[ -x "$PPC32RT" ] || fail "translator not executable: $PPC32RT"

if [ ! -d "$COREMARK_SRC" ]; then
    log "cloning CoreMark"
    $STEP_TIMEOUT 200s git clone --depth 1 "$COREMARK_URL" "$COREMARK_SRC" \
        || fail "CoreMark clone failed"
fi
log "CoreMark HEAD: $(git -C "$COREMARK_SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

file "$PPC32RT" | grep -q "aarch64" || fail "translator is not an AArch64 binary"
mkdir -p "$OUTDIR"

# build_guest <tag> <xcflags...> — static powerpc binary via link only.
build_guest() {
    tag=$1
    shift
    log "building guest $tag ($*)"
    (cd "$COREMARK_SRC" && \
        $STEP_TIMEOUT 200s make PORT_DIR=linux CC=powerpc-linux-gnu-gcc \
            "XCFLAGS=$*" LFLAGS_END="-static" \
            OPATH="./h3-$tag/" ITERATIONS=0 link) \
        || fail "guest build $tag failed"
    desc=$(file -b "$COREMARK_SRC/h3-$tag/coremark.exe")
    case $desc in
        *"ELF 32-bit MSB"*PowerPC*"statically linked"*) ;;
        *) fail "guest $tag is not a PPC32 static ELF: $desc" ;;
    esac
    rm -f "$COREMARK_SRC/h3-$tag"/run*.log
}

build_guest o0 "-static -O0"
build_guest o2 "-static"

ARGS="0x0 0x0 0x66"
TAIL="7 1 2000"

# run_engine <log> <engine...> — engine is "qemu" or a ppc32rt flag.
run_engine() {
    lg=$1
    shift
    if [ "$1" = "qemu" ]; then
        # shellcheck disable=SC2086
        $STEP_TIMEOUT 200s $PIN qemu-ppc -cpu 750 "$BIN" $ARGS "$ITERS" $TAIL \
            >"$OUTDIR/$lg" 2>&1
    else
        # 900 s budget: --interp needs ~390 s for the fixed 6000-iter
        # -O0 run on a moderately loaded host (15.4 it/s measured) and
        # more when sibling sessions saturate the machine; the gate
        # asserts validity/CRCs and dbt > interp, never absolute rates.
        # A hang still fails the budget, only slower.
        # shellcheck disable=SC2086
        $STEP_TIMEOUT 900s $PIN "$PPC32RT" "$1" -- "$BIN" $ARGS "$ITERS" $TAIL \
            >"$OUTDIR/$lg" 2>&1
    fi
}

score_of() {
    grep "Iterations/Sec" "$OUTDIR/$1" | awk '{print $3}' | head -1
}

crc_of() {
    # $1 = log, $2 = crclist|crcmatrix|crcstate|crcfinal
    grep "\[0\]$2" "$OUTDIR/$1" | awk '{print $3}' | head -1
}

check_valid() {
    # $1 = log; every gated run must self-validate (the one documented
    # exception is the sub-10 s oracle quick-check, handled by its caller).
    grep -q "Correct operation validated" "$OUTDIR/$1" \
        || fail "$1: missing 'Correct operation validated'"
}

check_algo_crcs() {
    # $1 = log; algo CRCs must equal the 2K performance known values.
    [ "$(crc_of "$1" crclist)" = "0xe714" ] \
        || fail "$1: crclist $(crc_of "$1" crclist) != 0xe714"
    [ "$(crc_of "$1" crcmatrix)" = "0x1fd7" ] \
        || fail "$1: crcmatrix $(crc_of "$1" crcmatrix) != 0x1fd7"
    [ "$(crc_of "$1" crcstate)" = "0x8e3a" ] \
        || fail "$1: crcstate $(crc_of "$1" crcstate) != 0x8e3a"
}

BIN="$COREMARK_SRC/h3-o0/coremark.exe"

# Auto-calibration picks the iteration count from a short timing probe,
# so a host that changes speed mid-run can land just under the 10 s
# validity rule (observed: dbt-o2-auto 2000 iters in 9.18 s with correct
# CRCs). Recalibrate boundedly: rerun an auto log while it misses
# validation, up to 2 extra attempts. Fixed-work logs (ITERS=6000)
# never retry — their workload is deterministic.
retry_auto() {
    lg=$1
    shift
    tries=0
    while [ "$tries" -lt 2 ] \
        && ! grep -q "Correct operation validated" "$OUTDIR/$lg"; do
        tries=$((tries + 1))
        log "recalibrating $lg (attempt $tries)"
        # shellcheck disable=SC2086
        run_engine "$lg" "$@" || fail "$lg recalibration run failed"
    done
}

ITERS=0
run_engine qemu-o0-auto.log qemu || fail "qemu o0 auto failed"
run_engine interp-o0-auto.log --interp || fail "interp o0 auto failed"
run_engine dbt-o0-auto.log --dbt || fail "dbt o0 auto failed"
retry_auto qemu-o0-auto.log qemu
retry_auto interp-o0-auto.log --interp
retry_auto dbt-o0-auto.log --dbt

ITERS=6000
run_engine qemu-o0-f6000.log qemu || fail "qemu o0 f6000 failed"
run_engine interp-o0-f6000.log --interp || fail "interp o0 f6000 failed"
run_engine dbt-o0-f6000.log --dbt || fail "dbt o0 f6000 failed"

BIN="$COREMARK_SRC/h3-o2/coremark.exe"
ITERS=0
run_engine qemu-o2-auto.log qemu || fail "qemu o2 auto failed"
run_engine interp-o2-auto.log --interp || fail "interp o2 auto failed"
run_engine dbt-o2-auto.log --dbt || fail "dbt o2 auto failed"
retry_auto qemu-o2-auto.log qemu
retry_auto interp-o2-auto.log --interp
retry_auto dbt-o2-auto.log --dbt

# Validity + correctness on every run but the documented sub-10 s
# oracle quick-check (qemu-o0-f6000 finishes in ~5 s by design).
for lg in qemu-o0-auto.log interp-o0-auto.log dbt-o0-auto.log \
    interp-o0-f6000.log dbt-o0-f6000.log \
    qemu-o2-auto.log interp-o2-auto.log dbt-o2-auto.log; do
    check_valid "$lg"
    check_algo_crcs "$lg"
done
grep -q "Must execute for at least 10 secs" "$OUTDIR/qemu-o0-f6000.log" \
    || fail "qemu-o0-f6000: expected the documented <10 s note"
check_algo_crcs qemu-o0-f6000.log

# Fixed-work trio: identical iteration counts, so crcfinal must agree
# exactly across all three engines.
[ "$(crc_of interp-o0-f6000.log crcfinal)" = "$(crc_of qemu-o0-f6000.log crcfinal)" ] \
    || fail "interp f6000 crcfinal diverges from oracle"
[ "$(crc_of dbt-o0-f6000.log crcfinal)" = "$(crc_of qemu-o0-f6000.log crcfinal)" ] \
    || fail "dbt f6000 crcfinal diverges from oracle"

I_RATE=$(score_of interp-o0-f6000.log)
D_RATE=$(score_of dbt-o0-f6000.log)
[ -n "$I_RATE" ] && [ -n "$D_RATE" ] || fail "could not parse fixed-work scores"
awk -v d="$D_RATE" -v i="$I_RATE" 'BEGIN { exit !(d > i) }' \
    || fail "dbt ($D_RATE) not above interp ($I_RATE) on fixed-work -O0"

log "fixed-work -O0: qemu $(score_of qemu-o0-f6000.log) | interp $I_RATE | dbt $D_RATE it/s"
log "auto -O0: qemu $(score_of qemu-o0-auto.log) | interp $(score_of interp-o0-auto.log) | dbt $(score_of dbt-o0-auto.log) it/s"
log "auto -O2: qemu $(score_of qemu-o2-auto.log) | interp $(score_of interp-o2-auto.log) | dbt $(score_of dbt-o2-auto.log) it/s"
log "PASS: all H3 assertions hold (see docs/h3-coremark.md)"
