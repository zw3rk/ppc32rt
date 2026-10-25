#!/bin/sh
# tools/p7_smc.sh — Phase 7 lane H1 (SMC + W^X) acceptance.
#
# Builds the translator (native in-container rebuild, like
# tools/p6_host_check.sh) and the freestanding tests/test_h1_smc.c
# fixture, then requires a FULL match:
#   1. qemu-ppc -cpu 750 and -cpu e500v2 oracle goldens agree
#      byte-for-byte (stdout "PASS\n", exit 0).
#   2. ppc32rt --interp and --dbt agree byte-for-byte with the
#      oracle golden (stdout + exit status).
#   3. ppc32rt --difftest prints the golden stdout plus
#      "DIFFTEST: EQUAL", exit 0.
#   4. W^X probe: a blocking RW-page guest runs under --interp and
#      --dbt with a forced 4 GiB window base; while it sleeps, no
#      guest-window mapping in /proc/<pid>/maps may carry PROT_EXEC
#      (guest data pages are never PROT_EXEC on the host; only the
#      JIT's own mappings may execute).
# Exits 0 only on full match, nonzero otherwise.
#
# Run INSIDE the lane container (Debian: apt-get provides the
# toolchain when missing):
#   sh tools/p7_smc.sh
# From macOS, run it in Docker (unique name, wall-clock bound):
#   timeout --kill-after=30s 280s docker run --rm --name ppc32rt-p7smc-$$ \
#     --memory 2g --cpus 2 --platform linux/arm64 \
#     -v "$PWD:/w" -w /w debian:stable-slim sh tools/p7_smc.sh
# and check `docker ps` afterwards for stray containers.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3k pte. ltd.
# SPDX-License-Identifier: Apache-2.0
set -eu

STEP_TIMEOUT="timeout --kill-after=30s"
LONG_TIMEOUT=120s
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
FAIL=0
OUT=_build/p7smc
RT=_build/ppc32rt
FIX=_build/test_h1_smc
WX=_build/p7smc_wx

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "p7_smc: missing required command: $1" >&2
        exit 2
    fi
}

install_toolchain() {
    if command -v powerpc-linux-gnu-gcc >/dev/null 2>&1 && \
       command -v qemu-ppc >/dev/null 2>&1 && \
       command -v make >/dev/null 2>&1; then
        return 0
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1
        apt-get install -y gcc-powerpc-linux-gnu qemu-user file make \
            >/dev/null 2>&1
    fi
}

if [ "$(uname -s)" != "Linux" ]; then
    echo "p7_smc: must run on Linux (use the Docker form from macOS)" >&2
    exit 2
fi
install_toolchain
need powerpc-linux-gnu-gcc
need qemu-ppc
need make
need file
echo "== build translator (clean native rebuild)"
make clean >/dev/null 2>&1 || true
mkdir -p "$OUT"
$STEP_TIMEOUT $LONG_TIMEOUT make build 'CC=cc -D_GNU_SOURCE' \
    >"$OUT/build.log" 2>&1 || {
    echo "BUILD-FAIL translator:"; tail -5 "$OUT/build.log"; FAIL=1
}
echo "== build fixture"
if [ "$FAIL" = 0 ]; then
    sh tools/build_fixture.sh tests/test_h1_smc.c "$FIX" \
        >"$OUT/fixture.log" 2>&1 || {
        echo "BUILD-FAIL fixture:"; cat "$OUT/fixture.log"; FAIL=1
    }
fi

golden() { # cpu outfile
    $STEP_TIMEOUT 60s qemu-ppc -cpu "$1" "$FIX" >"$2" 2>"$2.err"
    echo "$?" >"$2.rc"
}

if [ "$FAIL" = 0 ]; then
    echo "== oracle goldens (750, e500v2)"
    golden 750 "$OUT/o750"
    golden e500v2 "$OUT/o500"
    if [ "$(cat "$OUT/o750.rc")" != 0 ] || \
       [ "$(cat "$OUT/o500.rc")" != 0 ]; then
        echo "ORACLE-FAIL rc750=$(cat "$OUT/o750.rc") rc500=$(cat "$OUT/o500.rc")"
        FAIL=1
    elif ! cmp -s "$OUT/o750" "$OUT/o500"; then
        echo "ORACLE-DIVERGE (750 vs e500v2):"; FAIL=1
        cmp "$OUT/o750" "$OUT/o500" | head -3 || true
    elif [ "$(cat "$OUT/o750")" != "PASS" ]; then
        echo "ORACLE-UNEXPECTED stdout:"; cat "$OUT/o750"; FAIL=1
    else
        echo "goldens agree: PASS"
    fi
fi

if [ "$FAIL" = 0 ]; then
    for eng in interp dbt; do
        echo "== engine --$eng"
        $STEP_TIMEOUT 60s "$RT" --$eng -- "$FIX" >"$OUT/e_$eng" \
            2>"$OUT/e_$eng.err"
        echo "$?" >"$OUT/e_$eng.rc"
        if [ "$(cat "$OUT/e_$eng.rc")" != "$(cat "$OUT/o750.rc")" ] || \
           ! cmp -s "$OUT/e_$eng" "$OUT/o750"; then
            echo "DIVERGE --$eng rc=$(cat "$OUT/e_$eng.rc"):"
            head -3 "$OUT/e_$eng" || true
            head -3 "$OUT/e_$eng.err" || true
            FAIL=1
        else
            echo "ok --$eng matches golden"
        fi
        if [ ! -s "$OUT/e_$eng" ]; then
            echo "EMPTY-STDOUT --$eng"; FAIL=1
        fi
    done
fi

if [ "$FAIL" = 0 ]; then
    echo "== difftest --dbt-vs-interp lockstep"
    $STEP_TIMEOUT 60s "$RT" --difftest -- "$FIX" >"$OUT/e_difftest" \
        2>"$OUT/e_difftest.err"
    echo "$?" >"$OUT/e_difftest.rc"
    if [ "$(cat "$OUT/e_difftest.rc")" != 0 ] || \
       ! head -1 "$OUT/e_difftest" | grep -q "^PASS$" || \
       ! grep -q "DIFFTEST: EQUAL" "$OUT/e_difftest"; then
        echo "DIFFTEST-DIVERGE rc=$(cat "$OUT/e_difftest.rc"):"
        head -5 "$OUT/e_difftest" || true
        FAIL=1
    else
        echo "ok difftest EQUAL"
    fi
fi

# ---- W^X probe guest: mmap 1 RW page, print its guest VA (8 hex +
# newline), then block in read(0) until the script closes stdin. ----
write_wx() {
    cat >"$OUT/wx.c" <<'EOF'
#include <stdint.h>
#ifdef __powerpc__
__asm__(
".text\n"
"    .globl _start\n"
"    .align 2\n"
"_start:\n"
"    bl getpc\n"
"getpc:\n"
"    mflr 31\n"
"    addi 1,1,-64\n"
"    li 3,0\n"
"    li 4,4096\n"
"    li 5,3\n"
"    li 6,0x22\n"
"    li 7,-1\n"
"    li 8,0\n"
"    li 0,192\n"
"    .long 0x44000002\n"
"    mr 9,3\n"
"    mr 3,9\n"
"    bl print_hex8\n"
"    li 3,0\n"
"    lis 4,rdbuf@ha\n"
"    addi 4,4,rdbuf@l\n"
"    li 5,1\n"
"    li 0,3\n"
"    .long 0x44000002\n"
"    mr 3,3\n"
"    cmpwi 3,0\n"
"    li 3,1\n"
"    bne 1f\n"
"    li 3,0\n"
"1:\n"
"    li 0,1\n"
"    .long 0x44000002\n"
"print_hex8:\n"
"    mflr 0\n"
"    addi 1,1,-32\n"
"    stw 0,20(1)\n"
"    stw 3,4(1)\n"
"    li 6,8\n"
"    addi 5,1,8\n"
"2:\n"
"    lwz 0,4(1)\n"
"    rlwinm 0,0,4,28,31\n"
"    cmpwi 0,10\n"
"    blt 3f\n"
"    li 7,87\n"
"    add 0,0,7\n"
"    b 4f\n"
"3:\n"
"    li 7,48\n"
"    add 0,0,7\n"
"4:\n"
"    stb 0,0(5)\n"
"    addi 5,5,1\n"
"    lwz 0,4(1)\n"
"    rlwinm 0,0,4,0,31\n"
"    stw 0,4(1)\n"
"    addi 6,6,-1\n"
"    cmpwi 6,0\n"
"    bne 2b\n"
"    li 7,10\n"
"    stb 7,0(5)\n"
"    addi 4,1,8\n"
"    li 5,9\n"
"    li 3,1\n"
"    li 0,4\n"
"    .long 0x44000002\n"
"    lwz 0,20(1)\n"
"    mtlr 0\n"
"    addi 1,1,32\n"
"    blr\n"
"    .data\n"
"    .align 2\n"
"rdbuf: .long 0\n"
);
#else
int main(void) { return 0; }
#endif
EOF
    powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding \
        -static -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
        -o "$WX" "$OUT/wx.c"
}

# wx_probe engine: force the window base, run the blocking guest in
# the background, assert no 'x' mapping intersects the 4 GiB window,
# then close stdin (guest reads EOF and exits 0).
wx_probe() { # engine
    eng=$1
    echo "== W^X probe --$eng"
    LO=68719476736
    HI=137438953472
    rm -f "$OUT/in_$eng" "$OUT/out_$eng"
    mkfifo "$OUT/in_$eng" "$OUT/out_$eng"
    PPC32RT_WINDOW=0x1000000000 $RT --$eng -- "$WX" \
        <"$OUT/in_$eng" >"$OUT/out_$eng" 2>"$OUT/wx_$eng.err" &
    pid=$!
    exec 9>"$OUT/in_$eng"
    va=""
    if ! va=$(timeout --kill-after=10s 20s head -1 "$OUT/out_$eng"); then
        echo "WX-FAIL --$eng: no VA line from guest"
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        FAIL=1; exec 9>&- 2>/dev/null || true
        rm -f "$OUT/in_$eng" "$OUT/out_$eng"; return 0
    fi
    if [ -z "$va" ]; then
        echo "WX-FAIL --$eng: empty VA line (translator died?)"
        head -3 "$OUT/wx_$eng.err" || true
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        FAIL=1; exec 9>&- 2>/dev/null || true
        rm -f "$OUT/in_$eng" "$OUT/out_$eng"; return 0
    fi
    echo "guest RW page VA: $va"
    bad=0
    while read -r range perms _rest; do
        case $perms in
        *x*)
            s=${range%-*}; e=${range#*-}
            s=$((0x$s)); e=$((0x$e))
            if [ "$s" -lt "$HI" ] && [ "$e" -gt "$LO" ]; then
                echo "WX-FAIL --$eng: executable window mapping: $range $perms"
                bad=1
            fi
            ;;
        esac
    done <"/proc/$pid/maps" || true
    if [ "$bad" != 0 ]; then FAIL=1; fi
    exec 9>&-
    (sleep 45; kill -0 "$pid" 2>/dev/null && kill -9 "$pid") >/dev/null 2>&1 &
    wd=$!
    rc=0
    wait "$pid" || rc=$?
    kill "$wd" 2>/dev/null || true
    rm -f "$OUT/in_$eng" "$OUT/out_$eng"
    if [ "$rc" != 0 ]; then
        echo "WX-FAIL --$eng: guest rc=$rc"
        head -3 "$OUT/wx_$eng.err" || true
        FAIL=1
    elif [ "$bad" = 0 ]; then
        echo "ok W^X --$eng: no PROT_EXEC in guest window"
    fi
}

if [ "$FAIL" = 0 ]; then
    write_wx
    wx_probe interp
    if [ "$FAIL" = 0 ]; then wx_probe dbt; fi
fi

if [ "$FAIL" = 0 ]; then
    echo "== make check + line limits"
    make check >"$OUT/check.log" 2>&1 || {
        echo "CHECK-FAIL:"; tail -5 "$OUT/check.log"; FAIL=1
    }
    make check-line-limits >"$OUT/lines.log" 2>&1 || {
        echo "LINES-FAIL:"; tail -3 "$OUT/lines.log"; FAIL=1
    }
fi

if [ "$FAIL" = 0 ]; then
    echo "P7-SMC-OK"
    exit 0
else
    echo "P7-SMC-FAIL"
    exit 1
fi
