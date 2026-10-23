# Phase 4 Task Cards — Signals, Threads & Process Lifecycle (`RC4`)

Run after `RC3` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 3 output
plus `src/os/sigframe_ppc32.h` (L0b, E04-verified 992 B `mcontext`),
`src/os/syscall_nr.h`, this file.

Common lane rules: as Phase 2. Signal/thread lanes additionally: reservation
invalidation on signal delivery, helper call, and thread switch (SPEC
§2.2); `CLONE_VM` page-table mutex locking per rt32 `D19`.

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L4a | `lane/p4-l4a` `../ppc32rt-l4a` | `src/os/signals.c`, `src/os/signals.h` | cross-compile via `nix shell` cross-CC |
| L4b | `lane/p4-l4b` `../ppc32rt-l4b` | `src/os/threads.c`, `src/os/threads.h` | cross-compile via `nix shell` cross-CC |
| L4c | `lane/p4-l4c` `../ppc32rt-l4c` | `src/os/proc.c`, `src/os/proc.h`, `tests/test_p4_threads_signals.c` | host self-check prints `PASS` |

## Card L4a — Exact `rt_sigframe` construction & restoration

Scope: PPC32 `rt_sigframe` + `mcontext_t` build/restore per SPEC §2.3 and
E04 (`mc_gregs[48]`@0x0, `mc_fregs[33]`@0xc0, pad@0x1c8, `mc_vregs[528]`@
0x1d0 with SPE `evr[32]`+`acc`+`spefscr` overlay); `rt_sigaction`,
`rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`; synchronous `SIGSEGV`/
`SIGILL`/`SIGFPE`/`SIGBUS`/`SIGTRAP` delivery with guest PC in `nip` and
reservation cleared on delivery.
Check: cross-compile `src/os/signals.c` with the aarch64-musl cross-CC,
zero warnings.

## Card L4b — Multithreading

Scope: `clone` with `CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID`
(`r2` TLS pointer per E06), `futex` wait/wake, TLS register plumbing,
`set_tid_address`, LL/SC reservation invalidation across helpers, signals,
and thread switches; `D19` table locking on `CLONE_VM` mapping changes.
Check: cross-compile `src/os/threads.c`, zero warnings.

## Card L4c — Process lifecycle + test suite

Scope: `fork`, `vfork`, `execve` (re-enter ELF admission incl. profile
re-detect), `wait4`, `waitid`, `pipe2`, `dup2`; `tests/
test_p4_threads_signals.c` fixture (signal frame inspect/modify/restore,
`SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`);
prints `PASS`, exits 0.
Check: host-native self-check prints `PASS` (oracle comparison at `RC4`).

## `RC4` (coordinator, after all three merge)

`test_p4_threads_signals` matches `qemu-ppc` (both CPUs) on both engines in
a bounded Docker container.
