#!/bin/sh
#
# tools/build_fixture.sh — build the freestanding PPC32 Phase 1 ISA fixture
#
# Usage: tools/build_fixture.sh [src] [out]
#   src defaults to tests/test_p1_isa.c, out to _build/test_p1_isa.
#
# Tries, in order: $PPC_CC, powerpc-linux-gnu-gcc,
# powerpc-unknown-linux-gnu-gcc, powerpc-linux-musl-gcc, then nix
# pkgsCross powerpc variants. Verifies the output with file(1) is a
# 32-bit MSB PowerPC static ELF. Exit 3 when no powerpc toolchain
# exists on this host (the coordinator runs the oracle build in a
# debian+qemu container at RC1 instead).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

src=${1:-tests/test_p1_isa.c}
out=${2:-_build/test_p1_isa}

case $src in /*) ;; *) src=$PWD/$src ;; esac
case $out in /*) ;; *) out=$PWD/$out ;; esac

if [ ! -f "$src" ]; then
    echo "build_fixture.sh: no such source: $src" >&2
    exit 2
fi

# Both paths must live under the repository root so a single docker
# volume mount covers the source and the output.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case $src in
    "$root"/*) src=${src#"$root"/} ;;
    *) echo "build_fixture.sh: source must live under $root" >&2; exit 2 ;;
esac
case $out in
    "$root"/*) out=${out#"$root"/} ;;
    *) echo "build_fixture.sh: output must live under $root" >&2; exit 2 ;;
esac

mkdir -p "$root/$(dirname -- "$out")"

# compile_with <cc...> — returns 0 when $src built and verified.
compile_with() {
    echo "build_fixture.sh: trying: $*" >&2
    # shellcheck disable=SC2068
    if "$@" -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
        -fno-pie -no-pie -fno-stack-protector \
        -o "$root/$out" "$root/$src" 2>/dev/null; then
        if command -v file >/dev/null 2>&1; then
            desc=$(file -b "$root/$out")
            case $desc in
                *"ELF 32-bit MSB"*PowerPC*)
                    echo "build_fixture.sh: $out: $desc"
                    return 0
                    ;;
                *)
                    echo "build_fixture.sh: $out is not a PPC32 static ELF: $desc" >&2
                    rm -f "$root/$out"
                    return 1
                    ;;
            esac
        else
            echo "build_fixture.sh: $out built (no file(1) to verify)"
            return 0
        fi
    fi
    return 1
}

# 1. Explicit override, then native cross compilers.
if [ -n "${PPC_CC:-}" ]; then
    # shellcheck disable=SC2086
    compile_with $PPC_CC && exit 0
fi
for cc in powerpc-linux-gnu-gcc powerpc-unknown-linux-gnu-gcc \
    powerpc-linux-musl-gcc powerpc-unknown-linux-gnueabi-gcc; do
    if command -v "$cc" >/dev/null 2>&1; then
        compile_with "$cc" && exit 0
    fi
done

# 2. nix pkgsCross powerpc variants (best effort; needs network/store).
# Each attempt is wall-clock bounded so a dead daemon/network still
# reaches the exit-3 report below instead of hanging.
nix_try() { # $1 = nix attr, $2 = gcc tuple prefix
    echo "build_fixture.sh: trying nix shell $1 ($2)" >&2
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=10s 90s nix shell "$1" -c "$2" \
            -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
            -fno-pie -no-pie -fno-stack-protector \
            -o "$root/$out" "$root/$src" 2>/dev/null
    else
        nix shell "$1" -c "$2" \
            -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
            -fno-pie -no-pie -fno-stack-protector \
            -o "$root/$out" "$root/$src" 2>/dev/null
    fi
}
if command -v nix >/dev/null 2>&1; then
    for spec in \
        "nixpkgs#pkgsCross.ppc-embedded.stdenv.cc:powerpc-unknown-linux-gnueabi-gcc" \
        "nixpkgs#pkgsCross.musl-powerpc.stdenv.cc:powerpc-unknown-linux-musl-gcc"; do
        attr=${spec%%:*}
        tuple=${spec##*:}
        if nix_try "$attr" "$tuple"; then
            if command -v file >/dev/null 2>&1; then
                desc=$(file -b "$root/$out")
                case $desc in
                    *"ELF 32-bit MSB"*PowerPC*)
                        echo "build_fixture.sh: $out: $desc"
                        exit 0
                        ;;
                    *)
                        echo "build_fixture.sh: $out is not a PPC32 static ELF: $desc" >&2
                        rm -f "$root/$out"
                        exit 1
                        ;;
                esac
            else
                echo "build_fixture.sh: $out built (no file(1) to verify)"
                exit 0
            fi
        fi
    done
fi

echo "build_fixture.sh: no powerpc toolchain on this host (tried" >&2
echo "build_fixture.sh: \$PPC_CC, powerpc-linux-gnu-gcc," >&2
echo "build_fixture.sh: powerpc-unknown-linux-gnu-gcc," >&2
echo "build_fixture.sh: powerpc-linux-musl-gcc and nix pkgsCross" >&2
echo "build_fixture.sh: ppc-embedded/musl-powerpc variants)." >&2
echo "build_fixture.sh: build in the RC1 debian+qemu container instead:" >&2
echo "build_fixture.sh:   apt install -y gcc-powerpc-linux-gnu qemu-user" >&2
echo "build_fixture.sh:   sh tools/build_fixture.sh" >&2
exit 3
