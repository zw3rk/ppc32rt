#!/bin/sh
#
# tools/run_difftest.sh — interp-vs-dbt differential wrapper (Phase 2, L2d)
#
# Usage: tools/run_difftest.sh <fixture> [guest-args...]
#
# When the ppc32rt runner wires --difftest (coordinator, RC2), this runs
#   ppc32rt --difftest -- <fixture> [guest-args...]
# and reports DIFFTEST: EQUAL (exit 0) or DIVERGENCE (exit 1).
#
# Until main.c wires --difftest (current master rejects the flag), the
# wrapper works standalone: it builds the small C selftest driver baked
# into src/dbt/difftest.c (PPC32RT_DIFFTEST_SELFTEST) with the host cc
# and runs it, proving the comparator detects injected gpr/nip/cr
# divergences and stays clean on identical states.
#
# The runner is located via, in order: $PPC32RT_BIN, _build/ppc32rt next
# to the repo root, ./_build/ppc32rt, then $PATH. Plain POSIX sh.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: run_difftest.sh <fixture> [guest-args...]" >&2
    exit 2
fi

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$self_dir/.." && pwd)

if [ -n "${PPC32RT_BIN:-}" ]; then
    runner=$PPC32RT_BIN
elif [ -x "$root/_build/ppc32rt" ]; then
    runner=$root/_build/ppc32rt
elif [ -x ./_build/ppc32rt ]; then
    runner=./_build/ppc32rt
elif command -v ppc32rt >/dev/null 2>&1; then
    runner=$(command -v ppc32rt)
else
    runner=""
fi

if [ -n "$runner" ] && [ -x "$runner" ] && \
        "$runner" --help 2>&1 | grep -q -- "--difftest"; then
    echo "run_difftest: runner=$runner fixture=$1 (engine --difftest)" >&2
    # shellcheck disable=SC2068
    if "$runner" --difftest -- "$@"; then
        echo "DIFFTEST: EQUAL"
        exit 0
    else
        echo "DIFFTEST: DIVERGENCE"
        exit 1
    fi
fi

echo "run_difftest: engine --difftest not wired yet (RC2 coordinator work);" >&2
echo "run_difftest: running standalone comparator selftest" >&2
tmp=$(mktemp -d "${TMPDIR:-/tmp}/run_difftest.XXXXXX")
# shellcheck disable=SC2064
trap "rm -rf \"$tmp\"" EXIT INT TERM
cc=${CC:-cc}
"$cc" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -Iinclude -Isrc -DPPC32RT_DIFFTEST_SELFTEST \
    "$root/src/dbt/difftest.c" -o "$tmp/difftest_selftest"
if "$tmp/difftest_selftest"; then
    echo "DIFFTEST: EQUAL (comparator selftest)"
    exit 0
else
    echo "DIFFTEST: DIVERGENCE (comparator selftest failed)"
    exit 1
fi
