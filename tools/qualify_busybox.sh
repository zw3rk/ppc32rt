#!/bin/sh
#
# tools/qualify_busybox.sh — build BusyBox for PPC32 and qualify it under
# the oracle and both translator engines (lane L5b).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Runs INSIDE the Phase 5 lane container (Debian --platform linux/arm64
# with gcc-powerpc-linux-gnu, qemu-user, file, make, curl, xz-utils,
# bzip2, ca-certificates): builds
# BusyBox from source with powerpc-linux-gnu- (static), then runs
#   sh -c 'ls / && echo ok | wc -c'
# under the oracle (qemu-ppc -cpu 750 and -cpu e500v2, -L sysroot) and
# under ppc32rt --interp / --dbt, and byte-diffs all outputs against the
# oracle. Exit 0 on identical output, 1 otherwise. Every step is bounded
# (timeout --kill-after=30s); remove the lane container on exit (the
# caller owns `docker rm`).
#
# Environment overrides:
#   BUSYBOX_VERSION  source release (default 1.37.0)
#   WORKDIR          scratch dir for sources/build/logs (default
#                    _build/qualify-busybox under the repo root)
#   PPC32RT          translator binary (default _build/ppc32rt)
#   SYSROOT          Debian powerpc sysroot (default /usr/powerpc-linux-gnu)
#   PPC32RT_SYSROOT  exported to the translator when set (default SYSROOT
#                    once the translator honors it; harmless otherwise)
#
# Usage: sh tools/qualify_busybox.sh

set -eu

BB_VER=${BUSYBOX_VERSION:-1.37.0}
PPC32RT=${PPC32RT:-_build/ppc32rt}
SYSROOT=${SYSROOT:-/usr/powerpc-linux-gnu}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKDIR=${WORKDIR:-"$root/_build/qualify-busybox"}

GUEST_CMD='ls / && echo ok | wc -c'
STEP_TIMEOUT="timeout --kill-after=30s"

log() {
    printf 'qualify-busybox: %s\n' "$*"
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
if command -v curl >/dev/null 2>&1; then
    fetch="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
    fetch="wget -qO-"
else
    log "need curl or wget to fetch BusyBox sources"
    exit 2
fi

if [ ! -x "$PPC32RT" ]; then
    case $PPC32RT in
        /*) ;;
        *) PPC32RT="$root/$PPC32RT" ;;
    esac
fi
if [ ! -x "$PPC32RT" ]; then
    log "translator not executable: $PPC32RT"
    exit 2
fi
if [ ! -d "$SYSROOT" ]; then
    log "sysroot missing: $SYSROOT"
    exit 2
fi

mkdir -p "$WORKDIR"
cd "$WORKDIR"

fetch_tarball() {
    # shellcheck disable=SC2086
    log "fetching BusyBox ${BB_VER}"
    $STEP_TIMEOUT 120s $fetch \
        "https://busybox.net/downloads/busybox-${BB_VER}.tar.bz2" \
        > "busybox-${BB_VER}.tar.bz2"
}

if [ ! -f "busybox" ]; then
    if [ ! -f "busybox-${BB_VER}.tar.bz2" ]; then
        fetch_tarball
    fi
    rm -rf "busybox-${BB_VER}"
    if ! tar -xf "busybox-${BB_VER}.tar.bz2"; then
        log "archive corrupt, re-fetching once"
        rm -f "busybox-${BB_VER}.tar.bz2"
        rm -rf "busybox-${BB_VER}"
        fetch_tarball
        tar -xf "busybox-${BB_VER}.tar.bz2"
    fi
    cd "busybox-${BB_VER}"
    $STEP_TIMEOUT 120s make defconfig ARCH=powerpc \
        CROSS_COMPILE=powerpc-linux-gnu- >/dev/null
    # Static build: BusyBox links no shared libc when CONFIG_STATIC=y.
    sed -i 's/^# CONFIG_STATIC is not set$/CONFIG_STATIC=y/' .config
    # Cross fix: the x86-only SHA-NI hwaccel objects do not compile with
    # powerpc-linux-gnu-gcc (undeclared sha1_process_block64_shaNI).
    sed -i 's/^CONFIG_SHA1_HWACCEL=y$/# CONFIG_SHA1_HWACCEL is not set/' \
        .config
    sed -i 's/^CONFIG_SHA256_HWACCEL=y$/# CONFIG_SHA256_HWACCEL is not set/' \
        .config
    # Cross fix: networking/tc.c needs CBQ qdisc structs that current
    # kernel headers no longer provide; tc is not needed for the
    # qualification workload (sh + ls + echo + wc).
    sed -i 's/^CONFIG_TC=y$/# CONFIG_TC is not set/' .config
    $STEP_TIMEOUT 600s make -j2 busybox ARCH=powerpc \
        CROSS_COMPILE=powerpc-linux-gnu- >build.log 2>&1
    cp busybox ../busybox
    cd "$WORKDIR"
fi

file busybox
if [ -n "${PPC32RT_SYSROOT:-}" ]; then
    export PPC32RT_SYSROOT
else
    PPC32RT_SYSROOT=$SYSROOT
    export PPC32RT_SYSROOT
fi

log "oracle -cpu 750"
$STEP_TIMEOUT 60s qemu-ppc -cpu 750 -L "$SYSROOT" \
    "$WORKDIR/busybox" sh -c "$GUEST_CMD" >oracle750.out 2>oracle750.err
log "oracle -cpu e500v2"
$STEP_TIMEOUT 60s qemu-ppc -cpu e500v2 -L "$SYSROOT" \
    "$WORKDIR/busybox" sh -c "$GUEST_CMD" >oraclee500v2.out 2>oraclee500v2.err
log "translator --interp"
$STEP_TIMEOUT 60s "$PPC32RT" --interp -- "$WORKDIR/busybox" sh -c \
    "$GUEST_CMD" >interp.out 2>interp.err
log "translator --dbt"
$STEP_TIMEOUT 60s "$PPC32RT" --dbt -- "$WORKDIR/busybox" sh -c \
    "$GUEST_CMD" >dbt.out 2>dbt.err

fail=0
for f in oraclee500v2.out interp.out dbt.out; do
    if cmp -s oracle750.out "$f"; then
        log "identical: oracle750.out == $f"
    else
        log "MISMATCH: oracle750.out != $f"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi
log "all outputs identical"
exit 0
