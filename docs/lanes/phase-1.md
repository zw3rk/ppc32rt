# Phase 1 Task Cards — Base Integer Decoder, Reference Interpreter & Minimal Syscalls (`RC1`)

Run after `RC0` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): `src/ppc32rt.h`
(`ppc32_ctx_t`, SPEC §2.1 offsets), `src/os/syscall_nr.h`, `src/main.c`,
`src/rt32/**` (Phase 0 output), `include/a32host.h`, `Makefile`,
`flake.nix`, `SPEC.md`, `AGENTS.md`, this file.
Reference: `../i686rt` Phase 1 (read-only).

Common lane rules: work only in your worktree on your branch; never touch
`master`, other lanes' files, or sibling repos; never push; Curated C11
(`-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror`, no VLA, no
`sprintf`/`strcpy`/`strcat`, no `<threads.h>`); every `.c`/`.h` file
`<= 900` lines; never read or write `x18`; commit once when your check
passes with a plain message (no AI mentions); escalate per protocol (2
failed check attempts, needed file outside ownership, ambiguity).

Big-endian rule (all lanes): every guest memory access byte-swaps (`REV16` /
`REV` semantics); guest is `ELFDATA2MSB`.

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L1a | `lane/p1-l1a` `../ppc32rt-l1a` | `src/interp/decode.h`, `src/interp/decode.c` | host `cc` syntax + unit decode test (see card) |
| L1b | `lane/p1-l1b` `../ppc32rt-l1b` | `src/interp/interp.h`, `src/interp/interp.c` | host unit test of ALU/branch handlers |
| L1c | `lane/p1-l1c` `../ppc32rt-l1c` | `src/os/syscalls_min.c` (exit, exit_group, write, read, brk, mmap, munmap, mprotect, uname, set_tid_address) | cross-compile `syscalls_min.c` via `nix shell` cross-CC |
| L1d | `lane/p1-l1d` `../ppc32rt-l1d` | `tests/test_p1_isa.c`, `tools/build_fixture.sh` (ppc part) | host-native self-check prints `PASS` |

## Card L1a — Instruction decoder

Scope: `ppc32_insn_t` (`uint32_t raw`, primary opcode `op`, extended `xo`,
fields `rt/ra/rb/rs`, immediates `d/ds/si/ui/bo/bi/bd/li`, flags `oe/rc`);
`ppc_decode(uint32_t raw, ppc32_insn_t *out)` covering primary opcodes 14–31
(arithmetic/logical/immediate), 16 (`bc`), 18 (`b`), 19 (extended branch/
condition/spr), 20 (`rlwimi`), 21 (`rlwinm`), 23 (`rlwnm`), 24–27 (load/
store D-forms), 30–31 (X-forms incl. `lwarx`/`stwcx.`/`lmw`/`stmw`),
46 (`lmw`), 47 (`stmw`), 48–55 (float D-forms), 58–63 (float/SPE X-forms,
major opcode 4 SPE). Unknown → `PPC32_OP_UNDEF`. `OE`/`Rc` bits preserved.
Check: `cc -std=c11 ... -Iinclude -Isrc -c src/interp/decode.c` plus a
host unit asserting encodings of `addi`, `rlwinm`, `b`, `bc`, `sc`
(`0x44000002`), `lwarx`, `evaddw` decode to expected fields.

## Card L1b — Base integer reference interpreter

Scope: `interp_step(ppc32_ctx_t *ctx)` + `interp_run()` implementing SPEC
§2.2 Book I integer ISA: arithmetic/logical with `XER.CA`/`OV`/`CR0`, rotate/
mask (incl. `MB > ME` wrap per E02), shifts, CR logical ops, `mfcr`/`mtcrf`,
`mfspr`/`mtspr` (LR=8, CTR=9, XER=1, TB=268, TBU=269), branches (`b`/`bc`/
`blr`/`bctr`, `BO`/`BI` semantics, `LK`), `sc` → `PPC32_EXIT_SYSCALL`,
`lmw`/`stmw`, `lswi`/`stswi`, `*brx`, load/store with update, `lwarx`/
`stwcx.` with `res_valid` reservation (invalidated on helper/sycall entry),
unaligned access handling, unknown → `PPC32_EXIT_UNDEF`. Chunked
`interp_run` stops at syscalls, errors, and page boundaries.
Check: host unit test exercising add/sub carry, `rlwinm` wrap mask, `bc`
taken/not-taken, `lwarx`/`stwcx.` success/failure prints `L1B OK`.

## Card L1c — Minimal Linux syscall layer

Scope: `src/os/syscalls_min.c` dispatching on `r0`: `exit`, `exit_group`,
`write`, `read`, `brk`, `mmap`, `munmap`, `mprotect`, `uname` (ppc 6×65
layout, machine `"ppc"`), `set_tid_address`. Return convention per E01:
success `CR0.SO=0`, `r3=(uint32_t)ret`; error `CR0.SO=1`,
`r3=(uint32_t)(-ret)`. Unimplemented → `-ENOSYS` via the same path.
Arguments from `r3..r8`; 64-bit args in aligned pairs high-word-first.
Check: cross-compile with
`nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c
aarch64-unknown-linux-musl-gcc -std=c11 ... -c src/os/syscalls_min.c`.

## Card L1d — Freestanding ISA test suite

Scope: `tests/test_p1_isa.c` — freestanding PPC32 test (compiled with the
powerpc cross toolchain) covering ALU, shifts, branches, a branch in the
last word before a `PROT_NONE` page (`page_end - 4`), atomics
(`lwarx`/`stwcx.`), and unaligned loads/stores; prints `PASS` and exits 0
on success. `tools/build_fixture.sh` gains a `ppc` build function.
Check: host-native self-check of the test's expected-output logic prints
`PASS` (oracle comparison against `qemu-ppc -cpu 750`/`-cpu e500v2` runs
at `RC1` by the coordinator).

## `RC1` (coordinator, after all four merge)

`test_p1_isa` under `PPC32RT_ENGINE=interp` matches `qemu-ppc` (both CPUs)
exit code and stdout bit-for-bit in a bounded Docker container.
