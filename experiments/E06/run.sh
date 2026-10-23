#!/bin/sh
# E06 acceptance: qemu-ppc oracle run (needs PPC cross-CC + qemu-ppc).
# Host fallback: native cc build runs the machine-independent self-checks.
set -eu
CC_PPC="${CC_PPC:-powerpc-linux-gnu-gcc}"
if command -v "$CC_PPC" >/dev/null 2>&1 && command -v qemu-ppc >/dev/null 2>&1; then
    "$CC_PPC" -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -o _build/e06-probe-ppc experiments/E06/probe.c
    timeout --kill-after=30s 60s qemu-ppc -cpu 750 ./_build/e06-probe-ppc
    timeout --kill-after=30s 60s qemu-ppc -cpu e500v2 ./_build/e06-probe-ppc
else
    cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -o /tmp/e06probe-host experiments/E06/probe.c
    /tmp/e06probe-host
fi
test -s experiments/E06/FINDINGS.md
