# Phase 2 Task Cards — Static Libc Syscalls & Base Integer AArch64 DBT (`RC2`)

Run after `RC1` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): everything from
Phase 1 (`src/ppc32rt.h`, `src/interp/**`, `src/os/syscalls_min.c`,
`src/os/syscall_nr.h`, `src/rt32/**`, `src/main.c`, `Makefile`,
`flake.nix`, `SPEC.md`, `AGENTS.md`, this file). Reference: `../i686rt`
Phase 2/3 DBT (read-only).

Common lane rules: as Phase 1. DBT lanes additionally: enforce W^X (emit
into RW staging, flip to `PROT_READ | PROT_EXEC` + `__builtin___clear_cache`
before execution), never map guest data pages `PROT_EXEC`, never touch
`x18`, guest addresses wrap in 32-bit `W` regs before adding `xG` (`x20`).

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L2a | `lane/p2-l2a` `../ppc32rt-l2a` | `src/os/syscalls.c`, `src/os/convert.c`, `src/os/convert.h` | cross-compile both via `nix shell` cross-CC |
| L2b | `lane/p2-l2b` `../ppc32rt-l2b` | `src/dbt/dbt.h`, `src/dbt/dbt.c`, `src/dbt/trampoline_a64.S`, `src/dbt/cache.c` | cross-compile `dbt.c`+`cache.c`, `as` check of trampoline |
| L2c | `lane/p2-l2c` `../ppc32rt-l2c` | `src/dbt/emit_int.c`, `src/dbt/emit_int.h` | host unit test of emitted encodings |
| L2d | `lane/p2-l2d` `../ppc32rt-l2d` | `src/dbt/difftest.c`, `tests/test_p2_libc.c`, `tools/run_difftest.sh` | host unit test of difftest comparator |

## Card L2a — Complete static-libc syscall & struct conversion layer

Scope: full static-libc dispatch replacing `syscalls_min.c` callers:
`stat`/`stat64`/`statx`, `iovec` (`readv`/`writev`), `openat`, `fcntl`,
`clock_gettime`, `getrandom`, `futex`, `rt_sigprocmask` (stub → Phase 4),
`ioctl` (passthrough allowlist), plus converted `stat` layouts and
big-endian-safe copying. Keeps the E01 return convention (`CR0.SO`,
`r3=+errno`). Unimplemented → `-ENOSYS`.
Check: cross-compile `src/os/syscalls.c` + `src/os/convert.c` with the
aarch64-musl cross-CC, zero warnings.

## Card L2b — AArch64 DBT core

Scope: block translator driver: guest basic blocks up to 64 insns,
terminating at control transfers or page boundaries; direct block chaining;
4096-entry per-thread IBTC; return address stack (RAS); block cache keyed
by guest PC with SMC page-version invalidation hooks; `PPC32_EXIT_UNDEF` /
`PPC32_EXIT_SINGLE_STEP` → single-instruction `interp_step` fallback then
resume; `trampoline_a64.S` (guest↔host context switch, `x20`=guest base,
no `x18` use). Uses `rt32_a64_emit` for code emission.
Check: cross-compile `dbt.c`/`cache.c`; assemble `trampoline_a64.S` with
the cross assembler; grep trampoline for `x18` must be empty.

## Card L2c — AArch64 integer instruction emitter

Scope: `emit_int` lowering every Phase 1 integer instruction to AArch64 via
`rt32_a64_emit`: ALU with NZCV→`CR0`/`XER` materialization, rotates/masks
(`ubfm`/`bfm` families), loads/stores with `REV16`/`REV` byte-swap and
`[x20, wAddr, uxtw]` addressing, branches with chaining exits, `lwarx`/
`stwcx.` via `ldaxr`/`stlxr` (AArch64 reservation mirrors guest
reservation while `res_valid` is set at block entry).
Check: host unit test asserting selected emission sequences (e.g. `addi`
→ `add`, `lwz` → `ldr`+`rev`) prints `L2C OK`.

## Card L2d — Differential harness + static libc test suite

Scope: `--difftest` comparator (`difftest.c`): after each guest insn/block,
compare `gpr[32]`, `nip`, `lr`, `ctr`, `cr`, `xer` between `interp` and
`dbt`, reporting first divergence with PC/register dump; `tools/
run_difftest.sh` wrapper; `tests/test_p2_libc.c` (static libc: `hello`,
`printf`, `malloc`, `qsort`, file I/O) as PPC32 fixture source.
Check: host unit test of the comparator (injected divergence detected,
identical states clean) prints `L2D OK`.

## `RC2` (coordinator, after all four merge)

`--difftest` reports `0` register/PC mismatches on `test_p1_isa`; static
`hello`/`printf`/`qsort`/`malloc`/file-I/O match `qemu-ppc` (both CPUs) on
both engines in a bounded Docker container.
