#!/bin/sh
#
# tools/p7_libc.sh — Phase 7 lane H2 gate: libc-test + LTP syscall subset.
#
# Fetches, builds (powerpc), and runs target libc-test areas (math, string,
# pthread, sig, functional) plus the LTP syscall subset under
#   qemu-ppc -cpu 750 (oracle), ppc32rt --interp, ppc32rt --dbt,
# and asserts the state recorded in docs/h2-report.md:
#   * every ENFORCED test: rc 0 on all three runners, byte-identical stdout;
#   * every SKIP test: still not a clean oracle pass (quoted oracle log in
#     the report);
#   * every BLOCKED LTP test: oracle passes, translator stops at the known
#     gap signature (setup_ipc SAFE_CHMOD -> ENOSYS);
#   * every GAP probe: oracle passes (or documented oracle state),
#     translator still fails in the documented way.
# Exit 0 only when all assertions hold (0 unexpected failures).
#
# Runs INSIDE the lane container (Debian --platform linux/arm64 with
# gcc-powerpc-linux-gnu, qemu-user, file, make, gcc, git preinstalled;
# apt-get install as needed). Every build/Docker/qemu-ppc step is wrapped
# in timeout --kill-after=30s. The kill(0/-pgid) probes run under setsid
# so a guest group-kill can only ever hit its own session.
#
# Safety: kill02/kill10/kill12 translator runs are session-contained
# (setsid) by design; see docs/h2-report.md section G7.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: sh tools/p7_libc.sh

set -eu

STEP_TIMEOUT="timeout --kill-after=30s"
SYSROOT=${SYSROOT:-/usr/powerpc-linux-gnu}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
PPC32RT=${PPC32RT:-"$root/_build/ppc32rt"}
WORKDIR=${WORKDIR:-"$root/_build/p7-libc"}
LIBC_DIR="$WORKDIR/libc-test"
LTP_DIR="$WORKDIR/ltp"
BIN_DIR="$WORKDIR/bin"
OBJ_DIR="$WORKDIR/obj/common"
OUT_DIR="$WORKDIR/out"
LIBC_URL=${LIBC_URL:-https://repo.or.cz/libc-test.git}
LTP_URL=${LTP_URL:-https://github.com/linux-test-project/ltp}

log() {
    printf 'p7_libc: %s\n' "$*"
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "missing required tool: $1"
        log "lane container needs: gcc-powerpc-linux-gnu qemu-user file make gcc git"
        log "  (apt-get install as needed)"
        exit 2
    fi
}

need powerpc-linux-gnu-gcc
need qemu-ppc
need timeout
need make
need git
need cmp
need setsid
command -v cc >/dev/null 2>&1 || {
    log "missing required tool: cc (apt-get install gcc)"
    exit 2
}

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
mkdir -p "$BIN_DIR" "$OBJ_DIR" "$OUT_DIR"

# ---- fetch (clone once; reuses the checkout on re-runs) ----
if [ ! -d "$LIBC_DIR/.git" ]; then
    log "fetching libc-test ($LIBC_URL)"
    $STEP_TIMEOUT 280s git clone --depth 1 "$LIBC_URL" "$LIBC_DIR"
fi
if [ ! -d "$LTP_DIR/.git" ]; then
    log "fetching LTP ($LTP_URL)"
    $STEP_TIMEOUT 280s git clone --depth 1 "$LTP_URL" "$LTP_DIR"
    (cd "$LTP_DIR" && $STEP_TIMEOUT 280s make autotools >/dev/null)
    (cd "$LTP_DIR" && CC=powerpc-linux-gnu-gcc \
        $STEP_TIMEOUT 280s ./configure --host=powerpc-linux-gnu \
        --prefix="$WORKDIR/ltp-install" >/dev/null)
fi
log "libc-test rev: $(git -C "$LIBC_DIR" log -1 --format='%h %cs' 2>/dev/null)"
log "ltp rev: $(git -C "$LTP_DIR" log -1 --format='%h %cs' 2>/dev/null)"

# ---- build libc-test support objects ----
log "building libtest.a"
for f in "$LIBC_DIR"/src/common/fdfill.c "$LIBC_DIR"/src/common/memfill.c \
    "$LIBC_DIR"/src/common/mtest.c "$LIBC_DIR"/src/common/path.c \
    "$LIBC_DIR"/src/common/print.c "$LIBC_DIR"/src/common/rand.c \
    "$LIBC_DIR"/src/common/setrlim.c "$LIBC_DIR"/src/common/utf8.c \
    "$LIBC_DIR"/src/common/vmfill.c; do
    b=$(basename "$f" .c)
    $STEP_TIMEOUT 120s powerpc-linux-gnu-gcc -static -O2 \
        -I"$LIBC_DIR/src/common" -c "$f" -o "$OBJ_DIR/$b.o"
done
powerpc-linux-gnu-ar rcs "$OBJ_DIR/libtest.a" "$OBJ_DIR"/*.o

# build_lc <name> <area:math|func> — static powerpc binary in $BIN_DIR.
build_lc() {
    nm=$1
    area=$2
    if [ "$area" = math ]; then
        src="$LIBC_DIR/src/math/$nm.c"
        flags="-fno-builtin -frounding-math"
        inc="-I$LIBC_DIR/src/math"
        libs="-lm"
    else
        src="$LIBC_DIR/src/functional/$nm.c"
        flags=""
        inc=""
        libs=""
        # tgmath lives in functional/ but needs libm (sqrt/pow/lrint).
        if [ "$nm" = tgmath ]; then
            libs="-lm"
        fi
    fi
    # shellcheck disable=SC2086
    $STEP_TIMEOUT 120s powerpc-linux-gnu-gcc -static -O2 -pthread \
        $flags -I"$LIBC_DIR/src/common" $inc "$src" \
        "$OBJ_DIR/libtest.a" $libs -o "$BIN_DIR/lc-$nm"
}

# build_ltp <dir> — every test binary of one LTP syscall dir.
build_ltp() {
    (cd "$LTP_DIR" && $STEP_TIMEOUT 200s make -C "testcases/kernel/syscalls/$1" -j10 >/dev/null)
}

LTP_LIB_SENTINEL="$WORKDIR/.ltp-lib-built"
if [ ! -f "$LTP_LIB_SENTINEL" ]; then
    log "building LTP libltp.a"
    (cd "$LTP_DIR" && $STEP_TIMEOUT 280s make -C lib -j10 >/dev/null)
    touch "$LTP_LIB_SENTINEL"
fi

fail=0
pass=0

# run3_lc <name> — enforced libc-test: rc 0 + identical bytes on all three.
# 280 s budget (build-step grade): store-heavy libc tests need ~90 s
# under --dbt on this host (measured: lc-string_memset 88 s idle), so a
# 60 s budget times out green tests instead of catching hangs. A hang
# still fails the budget, only slower.
run3_lc() {
    nm=$1
    bin="$BIN_DIR/lc-$nm"
    base="$OUT_DIR/lc-$nm"
    set +e
    $STEP_TIMEOUT 280s qemu-ppc -cpu 750 "$bin" >"$base-oracle.out" 2>&1
    orc=$?
    $STEP_TIMEOUT 280s "$PPC32RT" --interp -- "$bin" >"$base-interp.out" 2>&1
    irc=$?
    $STEP_TIMEOUT 280s "$PPC32RT" --dbt -- "$bin" >"$base-dbt.out" 2>&1
    drc=$?
    set -e
    if [ "$orc" = 0 ] && [ "$irc" = 0 ] && [ "$drc" = 0 ] \
        && cmp -s "$base-oracle.out" "$base-interp.out" \
        && cmp -s "$base-oracle.out" "$base-dbt.out"; then
        log "identical: lc-$nm (all rc=0)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: lc-$nm oracle=$orc interp=$irc dbt=$drc"
        fail=$((fail + 1))
    fi
}

# run3_ltp <dir/test> — enforced LTP test: rc 0 + identical verdicts.
run3_ltp() {
    t=$1
    bin="$LTP_DIR/testcases/kernel/syscalls/$t"
    n=$(printf '%s' "$t" | tr '/' '_')
    base="$OUT_DIR/ltp-$n"
    set +e
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s qemu-ppc -cpu 750 -L "$SYSROOT" "./$t" \
        >"$base-oracle.out" 2>&1)
    orc=$?
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s "$PPC32RT" --interp --sysroot "$SYSROOT" -- "./$t" \
        >"$base-interp.out" 2>&1)
    irc=$?
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s "$PPC32RT" --dbt --sysroot "$SYSROOT" -- "./$t" \
        >"$base-dbt.out" 2>&1)
    drc=$?
    set -e
    of=$(grep -cE 'TFAIL|TBROK' "$base-oracle.out" || true)
    inf=$(grep -cE 'TFAIL|TBROK' "$base-interp.out" || true)
    df=$(grep -cE 'TFAIL|TBROK' "$base-dbt.out" || true)
    if [ "$orc" = 0 ] && [ "$irc" = 0 ] && [ "$drc" = 0 ] \
        && [ "$of" = 0 ] && [ "$inf" = 0 ] && [ "$df" = 0 ] \
        && cmp -s "$base-oracle.out" "$base-interp.out" \
        && cmp -s "$base-oracle.out" "$base-dbt.out"; then
        log "identical: ltp-$n (all rc=0, 0 FAIL)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: ltp-$n oracle=$orc/$of interp=$irc/$inf dbt=$drc/$df"
        fail=$((fail + 1))
    fi
}

# expect_oracle_nonpass <label> <runner...> — skip: oracle must not pass.
expect_oracle_nonpass() {
    label=$1
    shift
    set +e
    # shellcheck disable=SC2068
    $STEP_TIMEOUT 65s "$@" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" != 0 ]; then
        log "skip-holds: $label (oracle rc=$rc)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: $label now passes on oracle (rc=0); update report"
        fail=$((fail + 1))
    fi
}

# expect_translator_blocked <label> <oracle-bin> <eng> <bin> ...
# gap: oracle rc 0, every translator run rc != 0 (fast-failing gaps
# only; hangs use expect_hang). Engines/bins come in <eng> <bin> pairs.
expect_translator_blocked() {
    label=$1
    oracle_bin=$2
    shift 2
    set +e
    $STEP_TIMEOUT 60s qemu-ppc -cpu 750 "$oracle_bin" >/dev/null 2>&1
    orc=$?
    set -e
    ok=1
    if [ "$orc" != 0 ]; then
        ok=0
    fi
    while [ "$#" -ge 2 ]; do
        eng=$1
        bin=$2
        shift 2
        set +e
        $STEP_TIMEOUT 60s "$PPC32RT" "$eng" -- "$bin" >/dev/null 2>&1
        rc=$?
        set -e
        if [ "$rc" = 0 ]; then
            ok=0
        fi
    done
    if [ "$ok" = 1 ]; then
        log "gap-holds: $label"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: $label changed state; update report"
        fail=$((fail + 1))
    fi
}

# expect_oracle_pass <label> <runner...> — oracle must still pass (rc 0).
expect_oracle_pass() {
    label=$1
    shift
    set +e
    # shellcheck disable=SC2068
    $STEP_TIMEOUT 60s "$@" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" = 0 ]; then
        log "oracle-holds: $label"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: $label oracle now rc=$rc; update report"
        fail=$((fail + 1))
    fi
}

# expect_dbt_only_gap <label> <bin> — gap: oracle and interp agree
# (rc 0, identical bytes) but dbt still fails. Documents a DBT-only
# divergence (report G4).
expect_dbt_only_gap() {
    label=$1
    bin=$2
    base="$OUT_DIR/$label"
    set +e
    $STEP_TIMEOUT 60s qemu-ppc -cpu 750 "$bin" >"$base-oracle.out" 2>&1
    orc=$?
    $STEP_TIMEOUT 60s "$PPC32RT" --interp -- "$bin" >"$base-interp.out" 2>&1
    irc=$?
    $STEP_TIMEOUT 60s "$PPC32RT" --dbt -- "$bin" >"$base-dbt.out" 2>&1
    drc=$?
    set -e
    if [ "$orc" = 0 ] && [ "$irc" = 0 ] \
        && cmp -s "$base-oracle.out" "$base-interp.out" \
        && [ "$drc" != 0 ]; then
        log "gap-holds: $label (dbt-only divergence)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: $label changed state (o=$orc i=$irc d=$drc); update report"
        fail=$((fail + 1))
    fi
}

# expect_hang <label> <secs> <runner...> — gap: must still time out (124).
expect_hang() {
    label=$1
    secs=$2
    shift 2
    set +e
    # shellcheck disable=SC2068
    $STEP_TIMEOUT "${secs}s" "$@" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" = 124 ]; then
        log "gap-holds: $label (still hangs, rc=124)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: $label no longer hangs (rc=$rc); update report"
        fail=$((fail + 1))
    fi
}

ENFORCED_LC_STRING="string string_memcpy string_memset string_strchr string_strstr string_strcspn string_memmem"
ENFORCED_LC_FUNC="setjmp qsort snprintf random clock_gettime stat time memstream fdopen search_tsearch strtod inet_pton env ungetc strptime fcntl"
ENFORCED_LC_THR="pthread_tsd"
SKIP_LC="fnmatch sscanf ipc_sem strftime strtol wordexp swprintf pthread_cancel-points pthread_robust"
GAP_LC_FUNC="vfork socket ipc_msg ipc_shm sem_init sem_open utime popen spawn"
ENFORCED_LTP="pipe/pipe04 pipe/pipe05 pipe/pipe09 mmap/mmap11 sigaction/sigaction02"

log "building enforced + skip + fast-gap libc-test binaries"
for t in $ENFORCED_LC_STRING $ENFORCED_LC_FUNC $ENFORCED_LC_THR $SKIP_LC $GAP_LC_FUNC; do
    build_lc "$t" func
done

log "building LTP syscall dirs"
for d in pipe mmap sigaction open openat read write close stat fstat \
    mkdir dup fork waitpid execve nanosleep kill uname chdir umask \
    signal brk getcwd clock_gettime getpid getppid getuid; do
    build_ltp "$d"
done

log "phase A: enforced set (must be green on all three runners)"
for t in $ENFORCED_LC_STRING $ENFORCED_LC_FUNC $ENFORCED_LC_THR; do
    run3_lc "$t"
done
for t in $ENFORCED_LTP; do
    run3_ltp "$t"
done

log "phase B: oracle skips (must still not pass on oracle)"
expect_oracle_nonpass "lc-func-fnmatch" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-fnmatch"
expect_oracle_nonpass "lc-func-sscanf" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-sscanf"
expect_oracle_nonpass "lc-func-ipc_sem" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-ipc_sem"
expect_oracle_nonpass "lc-func-strftime" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-strftime"
expect_oracle_nonpass "lc-func-strtol" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-strtol"
expect_oracle_nonpass "lc-func-wordexp" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-wordexp"
expect_oracle_nonpass "lc-func-swprintf" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-swprintf"
expect_oracle_nonpass "lc-functional-pthread_cancel-points" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-pthread_cancel-points"
expect_oracle_nonpass "lc-functional-pthread_robust" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-pthread_robust"
LTP_SC="$LTP_DIR/testcases/kernel/syscalls"
expect_oracle_nonpass "ltp-waitpid01" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./waitpid/waitpid01"
expect_oracle_nonpass "ltp-chdir01" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./chdir/chdir01"
expect_oracle_nonpass "ltp-getcwd01" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./getcwd/getcwd01"
expect_oracle_nonpass "ltp-clock_gettime01" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./clock_gettime/clock_gettime01"
expect_oracle_nonpass "ltp-clock_gettime03" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./clock_gettime/clock_gettime03"
expect_oracle_nonpass "ltp-waitpid06" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./waitpid/waitpid06"
expect_oracle_nonpass "ltp-signal06" \
    sh -c "cd '$LTP_SC' && exec qemu-ppc -cpu 750 -L '$SYSROOT' ./signal/signal06"
expect_oracle_nonpass "ltp-execve01" \
    sh -c "cd '$LTP_SC/execve' && PATH=\"\$PWD:\$PATH\" exec qemu-ppc -cpu 750 -L '$SYSROOT' ./execve01"

log "phase C: LTP blocked set (oracle passes, translator hits G6)"
n=0
for t in getpid/getpid01 getppid/getppid01 getuid/getuid01 open/open01 \
    openat/openat01 read/read01 write/write01 close/close01 stat/stat01 \
    fstat/fstat02 mkdir/mkdir02 pipe/pipe01 dup/dup01 fork/fork01 \
    waitpid/waitpid03 nanosleep/nanosleep02 mmap/mmap01 uname/uname01 \
    chdir/chdir02 umask/umask01 signal/signal01 brk/brk01 \
    getcwd/getcwd02 clock_gettime/clock_gettime02; do
    base="$OUT_DIR/ltp-blocked-$n"
    n=$((n + 1))
    set +e
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s qemu-ppc -cpu 750 -L "$SYSROOT" "./$t" \
        >"$base-oracle.out" 2>&1)
    orc=$?
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s "$PPC32RT" --interp --sysroot "$SYSROOT" \
        -- "./$t" >"$base-interp.out" 2>&1)
    irc=$?
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s "$PPC32RT" --dbt --sysroot "$SYSROOT" \
        -- "./$t" >"$base-dbt.out" 2>&1)
    drc=$?
    set -e
    of=$(grep -cE 'TFAIL|TBROK' "$base-oracle.out" || true)
    isig=$(grep -c 'chmod' "$base-interp.out" || true)
    dsig=$(grep -c 'chmod' "$base-dbt.out" || true)
    if [ "$orc" = 0 ] && [ "$of" = 0 ] \
        && [ "$irc" != 0 ] && [ "$isig" != 0 ] \
        && [ "$drc" != 0 ] && [ "$dsig" != 0 ]; then
        log "blocked-holds: $t (G6 chmod signature)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: blocked $t changed (o=$orc/$of i=$irc/$isig d=$drc/$dsig)"
        fail=$((fail + 1))
    fi
done
# kill02 translator runs are session-contained: guest kill(0,...) must
# not reach this script's process group (see G7). Oracle still checked.
set +e
(cd "$LTP_DIR/testcases/kernel/syscalls" && \
    $STEP_TIMEOUT 60s qemu-ppc -cpu 750 -L "$SYSROOT" \
    ./kill/kill02 >"$OUT_DIR/ltp-blocked-kill02-oracle.out" 2>&1)
orc=$?
(cd "$LTP_DIR/testcases/kernel/syscalls" && \
    $STEP_TIMEOUT 30s setsid "$PPC32RT" --interp --sysroot "$SYSROOT" \
    -- ./kill/kill02 >"$OUT_DIR/ltp-blocked-kill02-interp.out" 2>&1)
irc=$?
(cd "$LTP_DIR/testcases/kernel/syscalls" && \
    $STEP_TIMEOUT 30s setsid "$PPC32RT" --dbt --sysroot "$SYSROOT" \
    -- ./kill/kill02 >"$OUT_DIR/ltp-blocked-kill02-dbt.out" 2>&1)
drc=$?
set -e
of=$(grep -cE 'TFAIL|TBROK' "$OUT_DIR/ltp-blocked-kill02-oracle.out" || true)
if [ "$orc" = 0 ] && [ "$of" = 0 ] && [ "$irc" != 0 ] && [ "$drc" != 0 ]; then
    log "blocked-holds: kill/kill02 (G7 group-kill, session-contained)"
    pass=$((pass + 1))
else
    log "DIVERGENCE: blocked kill/kill02 changed (o=$orc/$of i=$irc d=$drc)"
    fail=$((fail + 1))
fi

log "phase D: gap probes (must still fail on translator as documented)"
for t in acos asin atan2 cos exp log pow sin sqrt fmod; do
    build_lc "$t" math
    expect_translator_blocked "lc-math-$t" \
        "$BIN_DIR/lc-$t" \
        --interp "$BIN_DIR/lc-$t" --dbt "$BIN_DIR/lc-$t"
done
build_lc isless math
expect_translator_blocked "lc-math-isless" \
    "$BIN_DIR/lc-isless" \
    --interp "$BIN_DIR/lc-isless" --dbt "$BIN_DIR/lc-isless"
build_lc fpclassify math
expect_dbt_only_gap "lc-math-fpclassify" "$BIN_DIR/lc-fpclassify"
set +e
$STEP_TIMEOUT 60s "$PPC32RT" --interp -- "$BIN_DIR/lc-sqrt" \
    >"$OUT_DIR/lc-math-sqrt-interp.out" 2>&1
sqrt_rc=$?
set -e
if [ "$sqrt_rc" != 0 ] \
    && grep -q 'stopped, reason 3' "$OUT_DIR/lc-math-sqrt-interp.out"; then
    log "gap-holds: lc-math-sqrt (G1 mtfsb trap signature)"
    pass=$((pass + 1))
else
    log "DIVERGENCE: lc-math-sqrt trap signature changed; update report"
    fail=$((fail + 1))
fi
build_lc tgmath func
expect_dbt_only_gap "lc-functional-tgmath" "$BIN_DIR/lc-tgmath"
for t in pthread_mutex pthread_cond pthread_cancel pthread_mutex_pi; do
    build_lc "$t" func
done
for t in pthread_mutex pthread_cond pthread_cancel; do
    expect_oracle_pass "lc-thr-$t/oracle" \
        qemu-ppc -cpu 750 "$BIN_DIR/lc-$t"
done
expect_oracle_pass "lc-functional-pthread_mutex_pi/oracle" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-pthread_mutex_pi"
expect_oracle_pass "lc-func-popen/oracle" \
    qemu-ppc -cpu 750 "$BIN_DIR/lc-popen"
expect_hang "lc-thr-pthread_mutex/interp" 25 \
    "$PPC32RT" --interp -- "$BIN_DIR/lc-pthread_mutex"
expect_hang "lc-thr-pthread_mutex/dbt" 25 \
    "$PPC32RT" --dbt -- "$BIN_DIR/lc-pthread_mutex"
expect_hang "lc-thr-pthread_cond/interp" 25 \
    "$PPC32RT" --interp -- "$BIN_DIR/lc-pthread_cond"
expect_hang "lc-thr-pthread_cancel/interp" 25 \
    "$PPC32RT" --interp -- "$BIN_DIR/lc-pthread_cancel"
expect_hang "lc-functional-pthread_mutex_pi/interp" 25 \
    "$PPC32RT" --interp -- \
    "$BIN_DIR/lc-pthread_mutex_pi"
for t in vfork socket ipc_msg ipc_shm sem_init sem_open utime spawn; do
    expect_translator_blocked "lc-func-$t" \
        "$BIN_DIR/lc-$t" \
        --interp "$BIN_DIR/lc-$t" --dbt "$BIN_DIR/lc-$t"
done
expect_hang "lc-func-popen/interp" 25 \
    "$PPC32RT" --interp -- "$BIN_DIR/lc-popen"
expect_hang "lc-func-popen/dbt" 25 \
    "$PPC32RT" --dbt -- "$BIN_DIR/lc-popen"
set +e
(cd "$LTP_DIR/testcases/kernel/syscalls" && \
    $STEP_TIMEOUT 60s "$PPC32RT" --interp --sysroot "$SYSROOT" \
    -- ./openat/openat03 >"$OUT_DIR/ltp-gap-openat03-interp.out" 2>&1)
irc=$?
set -e
if grep -q 'mkdtemp.*ENOSYS' "$OUT_DIR/ltp-gap-openat03-interp.out" \
    && [ "$irc" != 0 ]; then
    log "gap-holds: ltp-openat03 (G6 mkdir ENOSYS)"
    pass=$((pass + 1))
else
    log "DIVERGENCE: ltp-openat03 changed; update report"
    fail=$((fail + 1))
fi
set +e
(cd "$LTP_DIR/testcases/kernel/syscalls" && \
    $STEP_TIMEOUT 60s "$PPC32RT" --interp --sysroot "$SYSROOT" \
    -- ./sigaction/sigaction01 >"$OUT_DIR/ltp-gap-sigaction01-interp.out" 2>&1)
irc=$?
set -e
if grep -q 'SA_RESETHAND should not cause SA_SIGINFO' \
    "$OUT_DIR/ltp-gap-sigaction01-interp.out" && [ "$irc" != 0 ]; then
    log "gap-holds: ltp-sigaction01 (G8 SA_SIGINFO)"
    pass=$((pass + 1))
else
    log "DIVERGENCE: ltp-sigaction01 changed; update report"
    fail=$((fail + 1))
fi
for k in kill10 kill12; do
    set +e
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 60s qemu-ppc -cpu 750 -L "$SYSROOT" \
        "./kill/$k" >"$OUT_DIR/ltp-gap-$k-oracle.out" 2>&1)
    orc=$?
    (cd "$LTP_DIR/testcases/kernel/syscalls" && \
        $STEP_TIMEOUT 30s setsid "$PPC32RT" --interp \
        --sysroot "$SYSROOT" -- "./kill/$k" \
        >"$OUT_DIR/ltp-gap-$k-interp.out" 2>&1)
    irc=$?
    set -e
    of=$(grep -cE 'TFAIL|TBROK' "$OUT_DIR/ltp-gap-$k-oracle.out" || true)
    if [ "$orc" = 0 ] && [ "$of" = 0 ] && [ "$irc" = 124 ]; then
        log "gap-holds: ltp-kill/$k (G7 group-kill hang, session-contained)"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: ltp-kill/$k changed (o=$orc/$of i=$irc)"
        fail=$((fail + 1))
    fi
done

log "phase E: report cross-check"
report="$root/docs/h2-report.md"
if [ ! -f "$report" ]; then
    log "DIVERGENCE: $report missing"
    fail=$((fail + 1))
else
    for t in $ENFORCED_LC_STRING $ENFORCED_LC_FUNC $ENFORCED_LC_THR; do
        if grep -q "lc-$t" "$report"; then
            pass=$((pass + 1))
        else
            log "DIVERGENCE: report omits lc-$t"
            fail=$((fail + 1))
        fi
    done
    for t in $ENFORCED_LTP; do
        n=$(printf '%s' "$t" | tr '/' '_')
        if grep -q "$n" "$report"; then
            pass=$((pass + 1))
        else
            log "DIVERGENCE: report omits ltp $t"
            fail=$((fail + 1))
        fi
    done
    if grep -q 'Enforced pass: 29/29' "$report" \
        && grep -q 'Unexpected failures: 0' "$report"; then
        log "report summary lines present"
        pass=$((pass + 1))
    else
        log "DIVERGENCE: report summary lines missing/changed"
        fail=$((fail + 1))
    fi
fi

log "RESULT pass=$pass fail=$fail"
if [ "$fail" = 0 ]; then
    log "0 unexpected failures; report assertions hold"
    exit 0
else
    log "$fail assertion(s) failed; see $OUT_DIR and docs/h2-report.md"
    exit 1
fi
