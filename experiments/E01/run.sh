#!/bin/sh
# Phase E lane E01 acceptance helper. Host check runs everywhere; the
# cross-compile + qemu-ppc oracle runs need a PowerPC toolchain.
set -eu
cd "$(dirname "$0")"
cc -fsyntax-only -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror probe.c
cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
  -o /tmp/e01probe probe.c
/tmp/e01probe
if command -v powerpc-linux-gnu-gcc >/dev/null 2>&1; then
  powerpc-linux-gnu-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -static -o /tmp/e01probe-ppc probe.c
  timeout --kill-after=30s 60s qemu-ppc -cpu 750    /tmp/e01probe-ppc
  timeout --kill-after=30s 60s qemu-ppc -cpu e500v2 /tmp/e01probe-ppc
else
  echo "e01: no powerpc cross-CC; qemu-ppc oracle runs pending" >&2
fi
test -s FINDINGS.md
