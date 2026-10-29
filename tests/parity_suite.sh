#!/bin/sh
# tests/parity_suite.sh — Wave C1 catalogue parity gate (lane C1-3).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# 32-bit PowerPC (Classic 750 / e500v2 SPE) Tier S gate. Sources the
# frozen cross-repo contract ../../rt-series/tools/parity_contract.sh
# and emits one structured PARITY_ROW per executed check, finishing
# with parity_summary (non-zero exit on any FAIL/GAP/SKIP).
#
# Rows:
#   struct  make check (syntax + line limits + ABI invariants, the
#           C1-3 Makefile fix), make check-line-limits, make
#           check-abi-invariants, make build-darwin, host P1/P3
#           self-checks, host AOT round-trip check.
#   ppc32-classic / ppc32-spe guest execution parity (--interp,
#           --dbt, --difftest with --profile classic|spe) on
#           _build/parity/{p1_classic,p3_both} against committed
#           goldens in tests/golden/ (from the pinned oracle below),
#           plus bench-ppc32 --smoke (when present).
#
# Oracle pinning: qemu-ppc -cpu 750 (Classic) and -cpu e500v2 (SPE).
# A native qemu-ppc is trusted only when it reproduces the committed
# golden (self-validating oracle); otherwise a trixie container
# (qemu-user) runs the oracle legs.
#
# Environments: translator legs prefer a native _build/ppc32rt, then
# hyper-linux (../rt-series/_build/hl), then a Linux container; guest
# builds need powerpc-linux-gnu-gcc (native or trixie container).
# Missing capability rows are omitted with a `note:` line (fewer
# rows, never GAP-masked); any executed mismatch is FAIL.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
CONTRACT="$ROOT/../rt-series/tools/parity_contract.sh"
if [ ! -f "$CONTRACT" ]; then
    echo "parity_suite: frozen contract missing: $CONTRACT" >&2
    exit 2
fi
. "$CONTRACT"
parity_init "ppc32rt"

OUT="$ROOT/_build/parity"
mkdir -p "$OUT"
HOST="$(uname -s 2>/dev/null || echo unknown)"
GOLDEN_DIR="$ROOT/tests/golden"
BENCH="$ROOT/../rt-series/_build/bench/bench-ppc32"
RT_LINUX="$ROOT/_build/ppc32rt"
RT_DARWIN="$ROOT/_build/ppc32rt-darwin"
HL="$ROOT/../rt-series/_build/hl"

RT_MODE="none"
if [ -x "$RT_LINUX" ] && "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="native"
elif [ -x "$HL" ] && [ -x "$RT_LINUX" ] && \
        "$HL" "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="hl"
elif command -v docker >/dev/null 2>&1; then
    RT_MODE="docker"
fi

have_docker() { command -v docker >/dev/null 2>&1; }

DOCKER_NAME="ppc32rt-c13-$$"
docker_cleanup() { docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true; }

# rt_run <profile> <guest> <outfile> <engine-flags...>: runs the
# translator via the resolved mode. Returns the guest exit code.
rt_run() {
    local _prof="$1" _guest="$2" _ofile="$3" _crel _rc
    shift 3
    case "$RT_MODE" in
        native)
            timeout --kill-after=10s 90s "$RT_LINUX" --profile "$_prof" \
                "$@" -- "$_guest" >"$_ofile" 2>&1
            ;;
        hl)
            timeout --kill-after=10s 90s "$HL" "$RT_LINUX" \
                --profile "$_prof" "$@" -- "$_guest" >"$_ofile" 2>&1
            ;;
        docker)
            _crel="_build/parity/$(basename "$_guest")"
            trap docker_cleanup EXIT INT TERM
            timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:trixie-slim \
                /w/_build/ppc32rt --profile "$_prof" "$@" -- "$_crel" \
                >"$_ofile" 2>&1
            _rc=$?
            trap - EXIT INT TERM
            docker_cleanup
            return $_rc
            ;;
        *) return 127 ;;
    esac
}

# golden_row <abi> <host> <case> <engine> <golden> <actual> <exit>
golden_row() {
    local _t0 _abi _host _case _eng _golden _actual _exit _ms
    _t0="$(parity_now_ms)"
    _abi="$1"; _host="$2"; _case="$3"; _eng="$4"
    _golden="$5"; _actual="$6"; _exit="$7"
    _ms=0
    if [ ! -f "$_golden" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "GAP" "$_ms" \
            "golden missing: $_golden"
        return
    fi
    if [ "$_exit" -ne 0 ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "exit=$_exit"
        return
    fi
    if parity_check_golden "$_golden" "$_actual"; then
        _ms=$(( $(parity_now_ms) - _t0 ))
        parity_row "$_abi" "$_host" "$_case" "$_eng" "PASS" "$_ms" \
            "byte-identical, exit 0"
    else
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "stdout differs from golden"
    fi
}

# ---- structural + host unit rows --------------------------------------
_t0="$(parity_now_ms)"
if make check-line-limits >/dev/null 2>&1; then
    parity_row "struct" "$HOST" "check-line-limits" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "every src .c/.h/.S <= 900 lines"
else
    parity_row "struct" "$HOST" "check-line-limits" "host" "FAIL" "0" \
        "see make check-line-limits"
fi

_t0="$(parity_now_ms)"
if make check-abi-invariants >"$OUT/host-abi.log" 2>&1; then
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "ALL OK"
else
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "FAIL" "0" \
        "see $OUT/host-abi.log"
fi

_t0="$(parity_now_ms)"
if make check >"$OUT/host-check.log" 2>&1; then
    parity_row "struct" "$HOST" "make-check" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "syntax + limits + abi"
else
    parity_row "struct" "$HOST" "make-check" "host" "FAIL" "0" \
        "see $OUT/host-check.log"
fi

if [ ! -x "$RT_DARWIN" ]; then
    echo "note: building missing $RT_DARWIN (make build-darwin)"
    make build-darwin >/dev/null 2>&1 || true
fi
_t0="$(parity_now_ms)"
if [ -x "$RT_DARWIN" ]; then
    parity_row "struct" "$HOST" "build-darwin" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "$RT_DARWIN present"
else
    parity_row "struct" "$HOST" "build-darwin" "host" "GAP" "0" \
        "no darwin translator (make build-darwin failed)"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_p1_isa.c -o "$OUT/host_p1_selfcheck" \
        2>"$OUT/host-p1.log" \
    && "$OUT/host_p1_selfcheck" >"$OUT/host-p1.out" 2>&1 \
    && grep -q "^PASS$" "$OUT/host-p1.out"; then
    parity_row "struct" "$HOST" "host-p1-selfcheck" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "C models PASS"
else
    parity_row "struct" "$HOST" "host-p1-selfcheck" "host" "FAIL" "0" \
        "see $OUT/host-p1.log"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        tests/test_p3_fp_spe.c -o "$OUT/host_p3_selfcheck" -lm \
        2>"$OUT/host-p3.log" \
    && "$OUT/host_p3_selfcheck" >"$OUT/host-p3.out" 2>&1 \
    && grep -q "^PASS$" "$OUT/host-p3.out"; then
    parity_row "struct" "$HOST" "host-p3-selfcheck" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "FP/SPE C models PASS"
else
    parity_row "struct" "$HOST" "host-p3-selfcheck" "host" "FAIL" "0" \
        "see $OUT/host-p3.log"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_aot_roundtrip.c \
        src/dbt/aot/aot_cache.c -o "$OUT/host_aot_roundtrip" \
        2>"$OUT/host-aot.log" \
    && "$OUT/host_aot_roundtrip" >"$OUT/host-aot.out" 2>&1 \
    && grep -q "AOT-ROUNDTRIP: PASS" "$OUT/host-aot.out"; then
    parity_row "struct" "$HOST" "host-aot-roundtrip" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "append/lookup/magic PASS"
else
    parity_row "struct" "$HOST" "host-aot-roundtrip" "host" "FAIL" "0" \
        "see $OUT/host-aot.log"
fi

# ---- guest builds -------------------------------------------------------
# Freestanding guests (_build/parity/, gitignored): reuse when newer
# than their sources, else build with a native powerpc gcc, else in a
# trixie container. Each guest gets an availability row.
need_build=""
for _g in p1_classic p3_both; do
    _src="tests/test_p1_isa.c"
    [ "$_g" = "p3_both" ] && _src="tests/test_p3_fp_spe.c"
    if [ -x "$OUT/$_g" ] && [ "$OUT/$_g" -nt "$ROOT/$_src" ]; then
        parity_row "ppc32" "$HOST" "$_g-guest-build" "host" "PASS" "0" \
            "cached, newer than $_src"
    else
        need_build="$need_build $_g"
    fi
done

ppc_build_one() {
    local _cc="$1" _src="$2" _out="$3"
    $_cc -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
        -fno-pie -no-pie -fno-stack-protector \
        "$ROOT/$_src" -o "$_out"
}

if [ -n "$need_build" ]; then
    if command -v powerpc-linux-gnu-gcc >/dev/null 2>&1; then
        for _g in $need_build; do
            _src="tests/test_p1_isa.c"
            [ "$_g" = "p3_both" ] && _src="tests/test_p3_fp_spe.c"
            _t0="$(parity_now_ms)"
            if ppc_build_one powerpc-linux-gnu-gcc "$_src" "$OUT/$_g" \
                    >"$OUT/build-$_g.log" 2>&1; then
                parity_row "ppc32" "$HOST" "$_g-guest-build" "host" \
                    "PASS" "$(( $(parity_now_ms) - _t0 ))" "native build"
            else
                parity_row "ppc32" "$HOST" "$_g-guest-build" "host" \
                    "GAP" "0" "native build failed, see $OUT/build-$_g.log"
            fi
        done
    elif have_docker; then
        _t0="$(parity_now_ms)"
        trap docker_cleanup EXIT INT TERM
        if timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:trixie-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq qemu-user gcc-powerpc-linux-gnu >/dev/null 2>&1
mkdir -p _build/parity
powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding -static \
    -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
    tests/test_p1_isa.c -o _build/parity/p1_classic
powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding -static \
    -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
    tests/test_p3_fp_spe.c -o _build/parity/p3_both
' >"$OUT/docker-build.log" 2>&1; then
            for _g in $need_build; do
                if [ -x "$OUT/$_g" ]; then
                    parity_row "ppc32" "$HOST" "$_g-guest-build" "host" \
                        "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                        "trixie container build"
                else
                    parity_row "ppc32" "$HOST" "$_g-guest-build" "host" \
                        "GAP" "0" "container build missed $_g"
                fi
            done
        else
            for _g in $need_build; do
                parity_row "ppc32" "$HOST" "$_g-guest-build" "host" \
                    "GAP" "0" "container build failed"
            done
        fi
        trap - EXIT INT TERM
        docker_cleanup
    else
        for _g in $need_build; do
            parity_row "ppc32" "$HOST" "$_g-guest-build" "host" "GAP" \
                "0" "no powerpc gcc and no docker"
        done
    fi
fi

# ---- oracle vs golden ---------------------------------------------------
ORACLE_MODE="none"
if command -v qemu-ppc >/dev/null 2>&1; then
    _ok=1
    for _spec in "p1_classic:750" "p3_both:750" "p3_both:e500v2"; do
        _g="${_spec%%:*}"; _cpu="${_spec##*:}"
        _golden="p1_classic_750.txt"
        [ "$_g" = "p3_both" ] && [ "$_cpu" = "750" ] && \
            _golden="p3_classic_750.txt"
        [ "$_g" = "p3_both" ] && [ "$_cpu" = "e500v2" ] && \
            _golden="p3_spe_e500v2.txt"
        if [ -x "$OUT/$_g" ] && \
                timeout --kill-after=10s 60s qemu-ppc -cpu "$_cpu" \
                    "$OUT/$_g" >"$OUT/oracle-native-$_g-$_cpu.txt" 2>&1 && \
                parity_check_golden "$GOLDEN_DIR/$_golden" \
                    "$OUT/oracle-native-$_g-$_cpu.txt"; then
            :
        else
            _ok=0
        fi
    done
    if [ "$_ok" -eq 1 ]; then
        ORACLE_MODE="native"
        echo "note: native $(qemu-ppc --version | head -1) reproduces goldens"
    else
        echo "note: native qemu-ppc diverges from goldens"
    fi
fi
if [ "$ORACLE_MODE" = "none" ] && have_docker; then
    trap docker_cleanup EXIT INT TERM
    if timeout --kill-after=30s 400s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -w /w \
            debian:trixie-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq qemu-user >/dev/null 2>&1
qemu-ppc --version | head -1
for spec in p1_classic:750 p3_both:750 p3_both:e500v2; do
    g="${spec%%:*}"; cpu="${spec##*:}"
    rc=0
    timeout --kill-after=10s 60s qemu-ppc -cpu "$cpu" _build/parity/$g \
        > _build/parity/oracle-$g-$cpu.txt 2>&1 || rc=$?
    echo "$g/$cpu oracle exit=$rc"
done
' >"$OUT/docker-oracle.log" 2>&1; then
        ORACLE_MODE="docker"
    else
        echo "note: oracle container failed, see $OUT/docker-oracle.log"
    fi
    trap - EXIT INT TERM
    docker_cleanup
fi

for _spec in "p1_classic:750:ppc32-classic" "p3_both:750:ppc32-classic" \
        "p3_both:e500v2:ppc32-spe"; do
    _g="${_spec%%:*}"; _rest="${_spec#*:}"; _cpu="${_rest%%:*}"
    _abi="${_rest##*:}"
    _golden="p1_classic_750.txt"
    [ "$_g" = "p3_both" ] && [ "$_cpu" = "750" ] && \
        _golden="p3_classic_750.txt"
    [ "$_g" = "p3_both" ] && [ "$_cpu" = "e500v2" ] && \
        _golden="p3_spe_e500v2.txt"
    _t0="$(parity_now_ms)"
    case "$ORACLE_MODE" in
        native) _of="$OUT/oracle-native-$_g-$_cpu.txt" ;;
        docker) _of="$OUT/oracle-$_g-$_cpu.txt" ;;
        *)
            echo "note: no oracle for $_g/$_cpu (no qemu, no docker)"
            continue
            ;;
    esac
    if [ ! -x "$OUT/$_g" ]; then
        parity_row "$_abi" "$HOST" "oracle-vs-golden" "oracle" "GAP" \
            "0" "guest missing"
    elif parity_check_golden "$GOLDEN_DIR/$_golden" "$_of"; then
        parity_row "$_abi" "$HOST" "oracle-vs-golden" "oracle" "PASS" \
            "$(( $(parity_now_ms) - _t0 ))" "qemu-ppc -cpu $_cpu"
    else
        parity_row "$_abi" "$HOST" "oracle-vs-golden" "oracle" "FAIL" \
            "0" "oracle output differs from golden"
    fi
done

# ---- translator vs golden + difftest ------------------------------------
if [ "$RT_MODE" = "none" ]; then
    for _spec in "classic:p1_classic" "classic:p3_both" "spe:p3_both"; do
        _prof="${_spec%%:*}"; _g="${_spec##*:}"
        _abi="ppc32-classic"
        [ "$_prof" = "spe" ] && _abi="ppc32-spe"
        for _eng in interp dbt difftest; do
            parity_row "$_abi" "$HOST" "vs-golden" "$_eng" "GAP" "0" \
                "no translator runner"
        done
    done
else
    for _spec in "classic:p1_classic" "classic:p3_both" "spe:p3_both"; do
        _prof="${_spec%%:*}"; _g="${_spec##*:}"
        _abi="ppc32-classic"
        [ "$_prof" = "spe" ] && _abi="ppc32-spe"
        _golden="p1_classic_750.txt"
        [ "$_g" = "p3_both" ] && [ "$_prof" = "classic" ] && \
            _golden="p3_classic_750.txt"
        [ "$_g" = "p3_both" ] && [ "$_prof" = "spe" ] && \
            _golden="p3_spe_e500v2.txt"
        if [ ! -x "$OUT/$_g" ]; then
            for _eng in interp dbt difftest; do
                parity_row "$_abi" "$HOST" "vs-golden" "$_eng" "GAP" \
                    "0" "guest missing"
            done
            continue
        fi
        for _eng in interp dbt; do
            _rc=0
            rt_run "$_prof" "$OUT/$_g" "$OUT/rt-$_prof-$_eng.txt" \
                "--$_eng" || _rc=$?
            golden_row "$_abi" "$HOST/$RT_MODE" "vs-golden" "$_eng" \
                "$GOLDEN_DIR/$_golden" "$OUT/rt-$_prof-$_eng.txt" "$_rc"
        done
        _t0="$(parity_now_ms)"
        _rc=0
        rt_run "$_prof" "$OUT/$_g" "$OUT/rt-$_prof-difftest.txt" \
            --dbt --difftest || _rc=$?
        if [ "$_rc" -eq 0 ] && \
                grep -q "DIFFTEST: EQUAL" "$OUT/rt-$_prof-difftest.txt"; then
            parity_row "$_abi" "$HOST/$RT_MODE" "vs-golden" "difftest" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "DIFFTEST: EQUAL"
        else
            parity_row "$_abi" "$HOST/$RT_MODE" "vs-golden" "difftest" \
                "FAIL" "0" "exit=$_rc, see $OUT/rt-$_prof-difftest.txt"
        fi
    done
fi

# ---- bench smoke (when present) -----------------------------------------
if [ -x "$BENCH" ] && [ -x "$RT_DARWIN" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        timeout --kill-after=10s 60s "$RT_DARWIN" "--$_eng" -- "$BENCH" \
            --smoke >"$OUT/bench-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && grep -q "ALL_PASS" "$OUT/bench-$_eng.txt" \
                && ! grep -q "FAIL" "$OUT/bench-$_eng.txt"; then
            parity_row "ppc32" "$HOST/darwin" "bench-smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "ppc32" "$HOST/darwin" "bench-smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-$_eng.txt"
        fi
    done
else
    echo "note: bench smoke skipped (bench or darwin translator missing)"
fi

parity_summary
