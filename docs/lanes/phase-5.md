# Phase 5 Task Cards — Dynamic Linking (`PT_INTERP`), Target `libc` Matrix & `BusyBox` (`RC5`)

Run after `RC4` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 4 output,
the RC5 entry-point fix (`ctx->elf_entry` start nip in `main.c` guest load,
difftest ref setup, and `proc.c` execve reparking), `src/ppc32rt.h`,
`src/os/syscall_nr.h`, `Makefile`, this file.

Common lane rules: as Phase 2. Curated C11, every file <= 900 lines, never
read/write `x18`, guest memory only via the `G`-window helpers
(`ppc32_guest_ptr` / `ppc32_range_ok` / BE converters).

Toolchain & sysroot (both lanes): Debian `powerpc-linux-gnu` cross set
inside a `--platform linux/arm64` container (`gcc-powerpc-linux-gnu`,
`libc6-dev-powerpc-cross`, `libc6-powerpc-cross`, `qemu-user`):
guest sysroot is `/usr/powerpc-linux-gnu` (`lib/ld.so.1`, `libc.so.6`
present); oracle runs as `qemu-ppc -cpu {750,e500v2} -L
/usr/powerpc-linux-gnu`; translator runs with the sysroot exported
(`PPC32RT_SYSROOT=/usr/powerpc-linux-gnu`, honoured by
`ppc32_open_guest_ro`). Wall-clock bound every container step
(`timeout --kill-after=30s`), remove lane containers on exit.

HWCAP note: `ppc32rt` advertises classic `0x8000000AU` /
SPE `0x80E00002U` (no VMX); Debian glibc IFUNCs select accordingly.

## Escalation rule

A lane stops and reports to the Coordinator when its acceptance fails
twice, when it needs an edit outside its exclusive files + hook hunks
(new syscalls needed by `ld.so`/`libc` startup surface this way — do
NOT widen `syscalls.c` from a lane), or when oracle behavior
contradicts a frozen contract above.

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L5a | `lane/p5-l5a` `../ppc32rt-l5a` | `src/rt32/stack32.c` (auxv hunk), `src/os/procfs.c` + `src/os/procfs.h` (new), `tests/test_p5_auxv.c` (new) | `make check` + host self-check prints `PASS` |
| L5b | `lane/p5-l5b` `../ppc32rt-l5b` | `tests/test_p5_dyn.c` + `tests/test_p5_dynlib.c` (new), `tools/qualify_busybox.sh` (new), `docs/lanes/phase-5-sysroot.md` (new) | `make check` + `sh -n tools/qualify_busybox.sh` |

`src/os/syscalls.c` hook hunks (L5a only, narrow): route
`/proc/self/*` path opens through `procfs.c` inside the existing
`sys_openat` path, and implement `readlink(85)` (plus `readlinkat` only
if the lane proves glibc needs it — the number lives in the frozen
header, the lane escalates for it).

## Card L5a — `AT_BASE`/`AT_SECURE`, `/proc/self/*`, auxv self-test

Scope:
1. `src/rt32/stack32.c` auxv: add `AT_BASE` (7, interpreter base, 0
   when static) and `AT_SECURE` (23, 0); keep 16-alignment +
   `AT_NULL`, do not disturb existing slots (`AT_PHDR/ENTRY/HWCAP/
   RANDOM/EXECFN/...`).
2. `src/os/procfs.{c,h}` (new): content builders for
   `/proc/self/{exe,maps,cmdline,stat,auxv}` from translator state
   (guest path, region table, guest argv, minimal stat, the exact
   auxv bytes handed to the guest). `exe` keeps symlink semantics
   (serves `readlink` too).
3. `tests/test_p5_auxv.c` (freestanding, like `test_p1_isa.c`):
   dump own auxv (`AT_PHDR/ENTRY/BASE/HWCAP`), read own
   `/proc/self/{cmdline,maps,auxv}`, compare against loader-known
   values; prints `PASS`, exits 0.
Check: `make check` clean; host self-check of the test logic prints
`PASS` (full oracle comparison at `RC5`).

## Card L5b — dynamic `libc` test, shared lib, `BusyBox`

Scope:
1. `tests/test_p5_dyn.c` (dynamic, Debian sysroot): `dlopen`/`dlsym`
   of `tests/test_p5_dynlib.c` (built as `.so` alongside),
   `__thread` TLS, shared-library calls (`printf`/`qsort`),
   `argv`/`envp`/`auxv` self-check (`getauxval(AT_ENTRY)` is the app
   entry, `AT_BASE` nonzero); prints `PASS`, exits 0.
2. `tools/qualify_busybox.sh`: build BusyBox from source with
   `powerpc-linux-gnu-` (static), run
   `sh -c 'ls / && echo ok | wc -c'` under the oracle and both
   engines, byte-diff; exit 0 on identical output.
3. `docs/lanes/phase-5-sysroot.md`: exact toolchain provenance
   (package versions, sysroot path, loader path), every missing
   syscall met during `ld.so`/`libc` startup (lane does NOT
   implement them — escalate the list), residual gaps.
Check: `make check` clean; `sh -n tools/qualify_busybox.sh`;
dynamic pair builds in the container.

## `RC5` (coordinator, after both merge)

`test_p5_auxv` and dynamic `test_p5_dyn` (+ BusyBox) match
`qemu-ppc (with -cpu 750 and -cpu e500v2, -L sysroot)` on both `interp`
and `dbt` with `--difftest` EQUAL (0 divergences), in a bounded Docker
container; `make check`, `make check-line-limits`,
`check_abi_invariants` green; Phases 0–4 suites unchanged.
