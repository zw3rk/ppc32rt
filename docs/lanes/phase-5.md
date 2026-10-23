# Phase 5 Task Cards — Dynamic Linking & Target libc Matrix (`RC5`)

Run after `RC4` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 4 output,
this file.

Common lane rules: as Phase 2.

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L5a | `lane/p5-l5a` `../ppc32rt-l5a` | `src/rt32/dynlink.c`, `src/rt32/dynlink.h`, `src/os/auxv.c` | cross-compile via `nix shell` cross-CC |
| L5b | `lane/p5-l5b` `../ppc32rt-l5b` | `tests/test_p5_dyn.c`, `tools/qualify_busybox.sh` | host self-check prints `PASS` |

## Card L5a — `PT_INTERP` dynamic loader

Scope: `PT_INTERP` `ld.so` mapping, complete auxiliary vector (`AT_PHDR`,
`AT_ENTRY`, `AT_BASE`, `AT_HWCAP`, `AT_HWCAP2`, `AT_RANDOM`, `AT_EXECFN`,
plus `AT_PAGESZ`/`AT_UID`/etc.), and `/proc/self/{exe,maps,cmdline,stat,
auxv}` interception returning guest-consistent contents.
Check: cross-compile `src/rt32/dynlink.c` + `src/os/auxv.c`, zero warnings.

## Card L5b — Dynamic tests + BusyBox qualification

Scope: `tests/test_p5_dyn.c` (`dlopen`/`dlsym`, TLS `__thread`, shared
library calls; prints `PASS`); `tools/qualify_busybox.sh` running target
BusyBox `sh -c 'ls / && echo ok | wc -c'` under both engines and diffing
against the `qemu-ppc` oracle log.
Check: host self-check of the test logic prints `PASS`; script passes
`sh -n`.

## `RC5` (coordinator, after both merge)

Dynamic `test_p5_dyn` and BusyBox match `qemu-ppc` (both CPUs) on both
engines in a bounded Docker container.
