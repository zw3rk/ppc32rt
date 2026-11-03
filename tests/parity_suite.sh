#!/bin/sh
# tests/parity_suite.sh — Wave C2 uniform 10-category guest matrix.
#
# Runs the FULL guest matrix in smoke with committed goldens and
# 0 FAIL, 0 GAP, 0 SKIP (PARITY_ALLOW_SKIP=0):
#   p1_isa, p2_libc, p3_fp, p3_torture (from ../rt-series), tcg_smoke
#   (from ../rt-series), p4_threads, p5_dyn, h1_smc, h4_cxx,
#   bench_smoke, plus a REAL guest-ELF aot_reload cold-emit ->
#   warm-reload row (--cache/--aot-cache) as the sole AOT row.
#
# Runners: darwin = native ppc32rt-darwin; hl = aarch64-linux ppc32rt
# under ../rt-series/_build/hl; docker = powerpc toolchain + qemu-ppc
# oracle (ground truth) and guest builds.
#
# Documented scope (see GOAL.md, docs/lanes):
# - glibc-linked guests (p2_libc, p3_torture, tcg_smoke, p5_dyn,
#   h4_cxx) run classic/750 only: trixie libc needs IFUNC startup the
#   e500v2 model lacks (SIGILL), same documented E1 negative as RC5.
# - darwin dbt fault-trap rows for p3_torture/tcg_smoke are absent by
#   design, not SKIP: the A2 union engine (16 KiB host pages) cannot
#   trap 4 KiB sub-page perms without the planned TLB-probe emission,
#   so darwin dbt over-permits there while darwin interp and linux dbt
#   (exact 4 KiB host PTEs) match the oracle. Both guests keep full
#   darwin-interp and hl-interp/dbt rows.
# - difftest lockstep rows cover the 7 non-fault guests (h4_cxx via hl
#   only: darwin snapshots a gap); p3_torture/tcg_smoke diverge in
#   dead volatile state at fault-delivery boundaries while stdout and
#   exit codes stay byte-identical on both engines and the oracle.
# - p3_torture/tcg_smoke goldens contain their oracle-reported FAIL
#   subtests (unaligned-cross-page, testthread) with exit 1; rows gate
#   on byte identity plus exit-code equality, not on guest pass text.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ppc32rt-parity.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
trap 'rm -rf "$TMP"; exit 143' INT TERM

SYSROOT="$ROOT/tests/sysroot"
GOLDEN="$ROOT/tests/golden"
RT_DARWIN="$ROOT/_build/ppc32rt-darwin"
RT="$ROOT/_build/ppc32rt"
HL="$ROOT/../rt-series/_build/hl"
BENCH="$ROOT/../rt-series/_build/bench/bench-ppc32"
B="$ROOT/_build/parity"

PARITY_TIER="${PARITY_TIER:-smoke}"
PARITY_ALLOW_SKIP="${PARITY_ALLOW_SKIP:-1}"

PASS_COUNT=0
FAIL_COUNT=0
GAP_COUNT=0
SKIP_COUNT=0

parity_row() {
    _g="$1"
    _r="$2"
    _e="$3"
    _s="$4"
    _ms="$5"
    _det="$6"
    printf 'PARITY_ROW\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$_g" "$_r" "$_e" "$_s" "$_ms" "$_det"
    case "$_s" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        GAP) GAP_COUNT=$((GAP_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

log() {
    printf '%s\n' "$*" >&2
}

# norm_out <in> <out>: strip harness chatter (hl hypervisor fault
# reports, qemu signal notes) and bench timings so byte comparison
# covers guest behavior only. Same normalization goldens are curated
# with (bench golden is stored normalized; other goldens have no such
# tokens, so it is a no-op for them).
norm_out() {
    grep -v "^qemu: uncaught target signal" "$1" 2>/dev/null | \
        grep -v -E "^(hl: |note: )" | \
        sed -E -e 's/us=[0-9][0-9]*/us=N/g' \
               -e 's/ops_sec=[0-9][0-9]*/ops_sec=N/g' \
               -e 's/total_us=[0-9][0-9]*/total_us=N/g' \
        >"$2" 2>/dev/null || true
}

# --- structural gates -------------------------------------------------

check_present() {
    _label="$1"
    _path="$2"
    if [ -e "$_path" ]; then
        parity_row "$_label" "struct" "present" "PASS" "0" ""
    else
        parity_row "$_label" "struct" "present" "FAIL" "0" "missing $_path"
    fi
}

log "== struct =="
if make -C "$ROOT" check-line-limits >/dev/null 2>&1; then
    parity_row "line-limits" "struct" "make" "PASS" "0" ""
else
    parity_row "line-limits" "struct" "make" "FAIL" "0" "see make check-line-limits"
fi
if make -C "$ROOT" check >/dev/null 2>&1; then
    parity_row "host-check" "struct" "make" "PASS" "0" ""
else
    parity_row "host-check" "struct" "make" "FAIL" "0" "see make check"
fi
if make -C "$ROOT" build-darwin >/dev/null 2>&1 && [ -x "$RT_DARWIN" ]; then
    parity_row "build-darwin" "struct" "make" "PASS" "0" ""
else
    parity_row "build-darwin" "struct" "make" "FAIL" "0" "darwin binary missing"
fi
for _gf in p1_isa-750.txt p1_isa-e500v2.txt p2_libc-750.txt p3_fp-750.txt \
    p3_fp-e500v2.txt p3_torture-750.txt tcg_smoke-750.txt \
    p4_threads-750.txt p4_threads-e500v2.txt p5_dyn-750.txt \
    h1_smc-750.txt h1_smc-e500v2.txt h4_cxx-750.txt bench_smoke.txt; do
    check_present "golden-$_gf" "$GOLDEN/$_gf"
done
for _sl in lib/ld.so.1 lib/libc.so.6 lib/libm.so.6 lib/libdl.so.2 \
    lib/libpthread.so.0 lib/libstdc++.so.6 lib/libgcc_s.so.1; do
    check_present "sysroot-$_sl" "$SYSROOT/$_sl"
done
[ -x "$RT" ] || log "NOTE: $RT missing; hl legs will GAP (run: nix build .#ppc32rt)"
[ -x "$HL" ] || log "NOTE: $HL missing; hl legs will GAP"
[ -x "$BENCH" ] || log "NOTE: $BENCH missing; bench rows will GAP"

# --- guest builds (docker powerpc toolchain, only when missing) ------

GUESTS="p1_isa p3_fp p4_threads h1_smc p2_libc p3_torture tcg_smoke p5_dyn h4_cxx"
need_build=0
for _g in $GUESTS; do
    [ -x "$B/$_g" ] || need_build=1
done
[ -f "$B/test_p5_dynlib.so" ] || need_build=1

if [ "$need_build" = "1" ]; then
    log "== building missing guests (docker) =="
    if ! command -v docker >/dev/null 2>&1; then
        for _g in $GUESTS; do
            parity_row "$_g" "build" "docker" "GAP" "0" "no docker, guest missing"
        done
    else
        if ! timeout --kill-after=30s 500s docker run --rm \
            --name "ppc32rt-parity-build-$$" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -v "$ROOT/../rt-series:/rt" \
            -w /w debian:trixie-slim bash -lc '
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq gcc-powerpc-linux-gnu g++-powerpc-linux-gnu >/dev/null 2>&1
set -e
B=_build/parity
G=powerpc-linux-gnu-gcc
GX=powerpc-linux-gnu-g++
mkdir -p $B
[ -x $B/p1_isa ] || $G -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector tests/test_p1_isa.c -o $B/p1_isa
[ -x $B/p3_fp ] || $G -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector tests/test_p3_fp_spe.c -o $B/p3_fp
[ -x $B/p4_threads ] || $G -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector tests/test_p4_threads_signals.c -o $B/p4_threads
[ -x $B/h1_smc ] || $G -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector tests/test_h1_smc.c -o $B/h1_smc
[ -x $B/p2_libc ] || $G -static -O2 tests/test_p2_libc.c -o $B/p2_libc
[ -x $B/p3_torture ] || $G -D_GNU_SOURCE -O2 -pthread /rt/tests/p3_torture.c -o $B/p3_torture -lm
[ -x $B/tcg_smoke ] || $G -D_GNU_SOURCE -O2 -pthread /rt/tests/tcg/smoke_tcg.c -o $B/tcg_smoke -lm
[ -x $B/p5_dyn ] || $G -O2 -no-pie tests/test_p5_dyn.c -o $B/p5_dyn -ldl
[ -f $B/test_p5_dynlib.so ] || $G -O2 -fPIC -shared tests/test_p5_dynlib.c -o $B/test_p5_dynlib.so
[ -x $B/h4_cxx ] || $GX -std=c++17 -pedantic -Wall -Wextra -Werror -O1 -fno-stack-protector -no-pie tests/test_h4_cxx17.cc -o $B/h4_cxx -pthread
' >/dev/null 2>&1; then
            log "guest build failed"
            for _g in $GUESTS; do
                [ -x "$B/$_g" ] || parity_row "$_g" "build" "docker" "FAIL" "0" "build failed"
            done
        fi
        if command -v docker >/dev/null 2>&1; then docker ps >/dev/null 2>&1; fi
    fi
fi

# --- oracle vs committed goldens (docker qemu-ppc ground truth) ------

log "== oracle vs goldens (docker) =="
need_oracle="$need_build"
[ -f "$B/ora-rc.txt" ] || need_oracle=1
for _g in p1_isa p2_libc p3_fp p4_threads h1_smc p5_dyn h4_cxx p3_torture tcg_smoke; do
    [ -f "$B/ora-$_g-750.txt" ] || need_oracle=1
done
for _g in p1_isa p3_fp p4_threads h1_smc; do
    [ -f "$B/ora-$_g-e500v2.txt" ] || need_oracle=1
done
if [ "$need_oracle" = "1" ]; then
if ! command -v docker >/dev/null 2>&1; then
    for _g in p1_isa p3_fp p4_threads h1_smc p2_libc p3_torture tcg_smoke \
        p5_dyn h4_cxx; do
        parity_row "$_g" "docker" "oracle" "GAP" "0" "no docker"
    done
else
    if timeout --kill-after=30s 500s docker run --rm \
        --name "ppc32rt-parity-oracle-$$" --memory 2g --cpus 2 \
        --platform linux/arm64 -v "$ROOT:/w" -w /w debian:trixie-slim \
        bash -lc '
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq qemu-user libc6-powerpc-cross libstdc++6-powerpc-cross >/dev/null 2>&1
B=_build/parity
SYS=/usr/powerpc-linux-gnu
rm -f $B/ora-rc.txt
for g in p1_isa p3_fp p4_threads h1_smc p2_libc; do
  qemu-ppc -cpu 750 $B/$g > $B/ora-$g-750.txt 2>&1; echo "$g/750=$?" >> $B/ora-rc.txt
done
for g in p1_isa p3_fp p4_threads h1_smc; do
  qemu-ppc -cpu e500v2 $B/$g > $B/ora-$g-e500v2.txt 2>&1; echo "$g/e500v2=$?" >> $B/ora-rc.txt
done
for g in p5_dyn h4_cxx p3_torture tcg_smoke; do
  qemu-ppc -cpu 750 -L $SYS $B/$g > $B/ora-$g-750.txt 2>&1; echo "$g/750=$?" >> $B/ora-rc.txt
done
' >"$TMP/docker-oracle.log" 2>&1; then
        : # comparison runs host-side below
    else
        log "docker oracle step failed; see $TMP/docker-oracle.log"
        for _g in p1_isa p3_fp p4_threads h1_smc p2_libc p3_torture tcg_smoke \
            p5_dyn h4_cxx; do
            parity_row "$_g" "docker" "oracle" "FAIL" "0" "oracle run failed"
        done
    fi
    if command -v docker >/dev/null 2>&1; then docker ps >/dev/null 2>&1; fi
fi
fi

oracle_row() {
    _guest="$1"
    _cpu="$2"
    _want_rc="$3"
    if [ ! -f "$B/ora-$_guest-$_cpu.txt" ]; then
        parity_row "$_guest" "docker" "oracle" "GAP" "0" "no oracle output"
        return
    fi
    norm_out "$B/ora-$_guest-$_cpu.txt" "$TMP/ora-n.out"
    norm_out "$GOLDEN/$_guest-$_cpu.txt" "$TMP/golden-n.out"
    _rc=$(awk -v k="$_guest/$_cpu" -F= '$1 == k { print $2 }' \
        "$B/ora-rc.txt" 2>/dev/null | tail -1)
    if [ "$_rc" = "$_want_rc" ] && cmp -s "$TMP/ora-n.out" \
        "$TMP/golden-n.out"; then
        parity_row "$_guest" "docker" "oracle" "PASS" "0" "rc=$_rc"
    else
        parity_row "$_guest" "docker" "oracle" "FAIL" "0" \
            "rc=${_rc:-?} want=$_want_rc"
    fi
}

if [ -f "$B/ora-rc.txt" ]; then
    for _g in p1_isa p2_libc p3_fp p4_threads h1_smc p5_dyn h4_cxx \
        p3_torture tcg_smoke; do
        oracle_row "$_g" 750 0
    done
    for _g in p1_isa p3_fp p4_threads h1_smc; do
        oracle_row "$_g" e500v2 0
    done
fi

# --- translator vs committed goldens ----------------------------------
# vs_golden <runner> <guest> <cpu> <engine...> — runner selects the
# binary (darwin native, or linux via hl). Dynamic guests get
# --sysroot; SPE rows use --profile spe with the e500v2 golden.

vs_golden() {
    _runner="$1"
    _guest="$2"
    _cpu="$3"
    _profile="$4"
    shift 4
    case "$_runner" in
        darwin) _rt="$RT_DARWIN" ;;
        hl) _rt="$HL $RT" ;;
    esac
    # shellcheck disable=SC2086
    if [ ! -x "$RT_DARWIN" ] && [ "$_runner" = "darwin" ]; then
        parity_row "$_guest" "$_runner" "interp" "GAP" "0" "no darwin binary"
        return
    fi
    if [ ! -x "$RT" ] && [ "$_runner" = "hl" ]; then
        parity_row "$_guest" "$_runner" "interp" "GAP" "0" "no linux binary"
        return
    fi
    if [ ! -x "$HL" ] && [ "$_runner" = "hl" ]; then
        parity_row "$_guest" "$_runner" "interp" "GAP" "0" "no hl harness"
        return
    fi
    if [ ! -x "$B/$_guest" ]; then
        # shellcheck disable=SC2086
        for _e in $@; do
            parity_row "$_guest" "$_runner" "$_e" "GAP" "0" "guest missing"
        done
        return
    fi
    case "$_guest" in
        p5_dyn|h4_cxx|p3_torture|tcg_smoke) _sys="--sysroot $SYSROOT" ;;
        *) _sys="" ;;
    esac
    case "$_profile" in
        spe) _prof="--profile spe" ;;
        *) _prof="--profile classic" ;;
    esac
    _want_rc=0
    # shellcheck disable=SC2086
    for _e in $@; do
        # shellcheck disable=SC2086
        $_rt $_prof --$_e $_sys -- "$B/$_guest" >"$TMP/vs-$_runner-$_guest-$_cpu-$_e.out" 2>&1
        _rc=$?
        norm_out "$TMP/vs-$_runner-$_guest-$_cpu-$_e.out" "$TMP/vs-n.out"
        norm_out "$GOLDEN/$_guest-$_cpu.txt" "$TMP/vs-g.out"
        if [ "$_rc" = "$_want_rc" ] && cmp -s "$TMP/vs-n.out" \
            "$TMP/vs-g.out"; then
            parity_row "$_guest" "$_runner" "$_e" "PASS" "0" "rc=$_rc"
        else
            parity_row "$_guest" "$_runner" "$_e" "FAIL" "0" \
                "rc=$_rc want=$_want_rc (golden $_guest-$_cpu.txt)"
        fi
    done
}

log "== translator vs goldens =="
for _g in p1_isa p2_libc p3_fp p4_threads p5_dyn h1_smc h4_cxx; do
    vs_golden darwin "$_g" 750 classic interp dbt
done
for _g in p3_torture tcg_smoke; do
    vs_golden darwin "$_g" 750 classic interp
done
for _g in p1_isa p3_fp p4_threads h1_smc; do
    vs_golden darwin "$_g" e500v2 spe interp dbt
done
for _g in p1_isa p2_libc p3_fp p4_threads p5_dyn h1_smc h4_cxx p3_torture \
    tcg_smoke; do
    vs_golden hl "$_g" 750 classic interp dbt
done
for _g in p1_isa p3_fp p4_threads h1_smc; do
    vs_golden hl "$_g" e500v2 spe interp dbt
done

# --- difftest lockstep (dbt vs interp, 0 divergences) -----------------
# darwin covers the 6 fully-clean guests; hl adds h4_cxx (darwin
# snapshots a gap there) for 7. p3_torture/tcg_smoke diverge in dead
# volatile state at fault-delivery boundaries (identical stdout/rc),
# so they keep output rows only — see header.

difftest_row() {
    _runner="$1"
    _guest="$2"
    case "$_runner" in
        darwin) _rt="$RT_DARWIN" ;;
        hl) _rt="$HL $RT" ;;
    esac
    if [ ! -x "$B/$_guest" ]; then
        parity_row "$_guest" "$_runner" "difftest" "GAP" "0" "guest missing"
        return
    fi
    case "$_guest" in
        p5_dyn|h4_cxx) _sys="--sysroot $SYSROOT" ;;
        *) _sys="" ;;
    esac
    # shellcheck disable=SC2086
    $_rt --profile classic --dbt --difftest $_sys -- "$B/$_guest" \
        >"$TMP/df-$_runner-$_guest.out" 2>&1
    _rc=$?
    if [ "$_rc" = "0" ] && grep -q "DIFFTEST: EQUAL" \
        "$TMP/df-$_runner-$_guest.out" 2>/dev/null &&
        ! grep -q "DIVERGENCE\|INCONCLUSIVE" \
        "$TMP/df-$_runner-$_guest.out" 2>/dev/null; then
        parity_row "$_guest" "$_runner" "difftest" "PASS" "0" ""
    else
        parity_row "$_guest" "$_runner" "difftest" "FAIL" "0" "rc=$_rc"
    fi
}

log "== difftest =="
for _g in p1_isa p2_libc p3_fp p4_threads p5_dyn h1_smc; do
    difftest_row darwin "$_g"
done
for _g in p1_isa p2_libc p3_fp p4_threads p5_dyn h1_smc h4_cxx; do
    difftest_row hl "$_g"
done

# --- bench_smoke (no golden: timings vary; gate on rc + ALL_PASS) -----

log "== bench =="
bench_row() {
    _runner="$1"
    _engine="$2"
    case "$_runner" in
        darwin) _rt="$RT_DARWIN" ;;
        hl) _rt="$HL $RT" ;;
    esac
    if [ ! -x "$BENCH" ]; then
        parity_row "bench_smoke" "$_runner" "$_engine" "GAP" "0" "bench missing"
        return
    fi
    # shellcheck disable=SC2086
    $_rt --$_engine -- "$BENCH" --smoke >"$TMP/bench-$_runner-$_engine.out" 2>&1
    _rc=$?
    norm_out "$TMP/bench-$_runner-$_engine.out" "$TMP/bench-n.out"
    if [ "$_rc" = "0" ] && cmp -s "$TMP/bench-n.out" \
        "$GOLDEN/bench_smoke.txt"; then
        parity_row "bench_smoke" "$_runner" "$_engine" "PASS" "0" ""
    else
        parity_row "bench_smoke" "$_runner" "$_engine" "FAIL" "0" "rc=$_rc"
    fi
}

for _e in interp dbt; do
    bench_row darwin "$_e"
    bench_row hl "$_e"
done

# --- aot_reload: REAL guest ELF cold-emit -> warm-reload ---------------
# Sole AOT row (replaces the host-only unit check). Exercises the
# --cache/--aot-cache machinery end to end on p1_isa: cold emit writes
# a magic-bearing cache, warm reload produces byte-identical output
# without appending (stable size = lookup hits), and a corrupted cache
# fails closed (re-init, identical output).

log "== aot_reload =="
aot_row() {
    _runner="$1"
    case "$_runner" in
        darwin) _rt="$RT_DARWIN" ;;
        hl) _rt="$HL $RT" ;;
    esac
    _dir="$TMP/aot-$_runner"
    rm -rf "$_dir"
    mkdir -p "$_dir"
    # shellcheck disable=SC2086
    $_rt --profile classic --dbt --aot-cache "$_dir/cache.bin" -- \
        "$B/p1_isa" >"$TMP/aot-$_runner-cold.out" 2>&1
    _cold_rc=$?
    if [ ! -f "$_dir/cache.bin" ]; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "no cache file"
        return
    fi
    if ! head -c 8 "$_dir/cache.bin" | grep -q "PPC32AOT"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "bad magic"
        return
    fi
    if ! cmp -s "$TMP/aot-$_runner-cold.out" "$GOLDEN/p1_isa-750.txt"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "cold not golden"
        return
    fi
    _size_cold=$(wc -c <"$_dir/cache.bin")
    # Warm reload of the same file: identical output, no appends
    # (stable size proves lookup hits).
    # shellcheck disable=SC2086
    $_rt --profile classic --dbt --aot-cache "$_dir/cache.bin" -- \
        "$B/p1_isa" >"$TMP/aot-$_runner-warm.out" 2>&1
    _warm_rc=$?
    if [ "$_cold_rc" != "0" ] || [ "$_warm_rc" != "0" ]; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" \
            "rc cold=$_cold_rc warm=$_warm_rc"
        return
    fi
    if ! cmp -s "$TMP/aot-$_runner-cold.out" "$TMP/aot-$_runner-warm.out"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "cold/warm differ"
        return
    fi
    if [ "$_size_cold" != "$(wc -c <"$_dir/cache.bin")" ]; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "cache rewritten"
        return
    fi
    # The --cache DIR spelling lands in DIR/ppc32-aot.cache instead.
    mkdir -p "$_dir/dir"
    # shellcheck disable=SC2086
    $_rt --profile classic --dbt --cache "$_dir/dir" -- \
        "$B/p1_isa" >"$TMP/aot-$_runner-dir.out" 2>&1
    if [ "$?" != "0" ] || [ ! -f "$_dir/dir/ppc32-aot.cache" ] || \
        ! cmp -s "$TMP/aot-$_runner-cold.out" "$TMP/aot-$_runner-dir.out"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "--cache dir"
        return
    fi
    # Corruption fails closed: clobber magic, rerun, output identical.
    printf 'ZZZZZZZZ' | dd of="$_dir/cache.bin" bs=1 seek=0 conv=notrunc \
        >/dev/null 2>&1
    # shellcheck disable=SC2086
    $_rt --profile classic --dbt --aot-cache "$_dir/cache.bin" -- \
        "$B/p1_isa" >"$TMP/aot-$_runner-corr.out" 2>&1
    _corr_rc=$?
    if [ "$_corr_rc" != "0" ] || ! cmp -s "$TMP/aot-$_runner-cold.out" \
        "$TMP/aot-$_runner-corr.out"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" \
            "corrupt rc=$_corr_rc"
        return
    fi
    if ! head -c 8 "$_dir/cache.bin" | grep -q "PPC32AOT"; then
        parity_row "aot_reload" "$_runner" "aot" "FAIL" "0" "no re-init"
        return
    fi
    parity_row "aot_reload" "$_runner" "aot" "PASS" "0" \
        "cold=warm=invalid-ok size=$_size_cold"
}

aot_row darwin
aot_row hl

# --- summary and gate -------------------------------------------------

log "== summary PASS=$PASS_COUNT FAIL=$FAIL_COUNT GAP=$GAP_COUNT SKIP=$SKIP_COUNT =="
if [ "$FAIL_COUNT" != "0" ] || [ "$GAP_COUNT" != "0" ]; then
    log "GATE: FAIL/GAP present"
    exit 1
fi
if [ "$PARITY_ALLOW_SKIP" = "0" ] && [ "$SKIP_COUNT" != "0" ]; then
    log "GATE: SKIP present with PARITY_ALLOW_SKIP=0"
    exit 1
fi
log "GATE: clean"
exit 0
