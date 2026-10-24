# GOAL: Build, Verify, and Harden `ppc32rt` (PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE) -> AArch64 Binary Translator)

## Objective

Implement, verify, and harden **`ppc32rt`** — a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (`hyper-linux`) — from **Phase E** through **Phase 7 (`H1..H4`)** in full compliance with [`SPEC.md`](SPEC.md), [`AGENTS.md`](AGENTS.md), and [`../rt-series/SPEC.md`](../rt-series/SPEC.md).

## Autonomous Coordinator & Concurrent Subagent Execution Rules

1. **Operate with Full Autonomy Through All 9 Phases (`Phase E -> Phase 0 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6 -> Phase 7`)**:
   - Do **not** stop after completing a single phase. Advance continuously from one phase to the next until every checkbox in this `GOAL.md` is `[x]` with committed code and verified test outputs on `master`.
2. **Use Workflows & Multiple Concurrent Subagents (`subagent`) in Isolated Git Worktrees**:
   - Act as the **Coordinator** on `master`.
   - Before each phase, freeze the phase's shared headers (`src/ppc32rt.h`, `src/os/syscall_nr.h`, etc.) and write/update `docs/lanes/phase-<N>.md`.
   - Spawn **multiple concurrent `subagent` worker lanes in parallel** in isolated git worktrees (`git worktree add -b lane/<phase>-<lane> ../ppc32rt-<lane> master`). Use `list_workflows` / `run_workflow` where helpful.
   - Merge completed worker branches back to `master` (`git merge --no-ff`), remove the temporary worktrees (`git worktree remove ../ppc32rt-<lane>`), and run the phase Review Checkpoint (`RC`) gate before starting the next phase.
3. **Host Toolchain & Container Discipline**:
   - Compile `ppc32rt` with `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c aarch64-unknown-linux-musl-gcc -static-pie -fPIE ...` (or `nix build .#ppc32rt`).
   - Run AArch64 Linux and `qemu-ppc (with -cpu 750 and -cpu e500v2)` verification inside bounded Docker containers (`timeout --kill-after=30s 120s docker run --rm --name ppc32rt-<id> --memory 2g --cpus 2 --platform linux/arm64 -v "$PWD:/w" -w /w ...`) and verify container cleanup.

---

## Phase Checklist & Verification Gates

### Phase E — Pre-Implementation Empirical Experiments (`RC-E`)
Read [`docs/lanes/phase-e.md`](docs/lanes/phase-e.md) and run concurrent experiment lanes `E01..E06`:
- [x] **E01 (PPC32 `sc` Syscall `CR0.SO` Error Flag & 64-Bit Pair Alignment)**: Verify `sc` return convention (`CR0.SO=0/1`, `r3=+errno`) and 64-bit register pair alignment under `qemu-ppc`. (`experiments/E01/FINDINGS.md`)
- [x] **E02 (Rotate-and-Mask (`rlwinm`/`rlwimi`) Wrap-Around (`MB > ME`) & `XER.CA`)**: Verify all edge cases of `rlwinm[.]`, `rlwimi[.]`, `srawi[.]`, and `addze`/`subfze` carry propagation against `qemu-ppc`. (`experiments/E02/FINDINGS.md`)
- [x] **E03 (`.gnu.attributes` Parsing & Classic FPU vs `e500v2` SPE Dispatch)**: Verify ELF `.gnu.attributes` (`Tag_GNU_Power_ABI_FP`) and SPE `ev*`/`efs*`/`efd*` upper-word `gpr_hi[32]` behavior under `qemu-ppc -cpu e500v2`. (`experiments/E03/FINDINGS.md`)
- [x] **E04 (PPC32 `ucontext_t` / `mcontext_t` (992 B) & SPE `evr[32]` Overlay)**: Compile a target C probe dumping `sizeof`/`offsetof` for `ucontext_t`, `mcontext_t` (`0x1d0` `mc_vregs`), and `stat64`. (`experiments/E04/FINDINGS.md`)
- [x] **E05 (Big-Endian String/Multiple Loads (`lmw`/`stmw`, `lswi`/`stswi`, `*brx`))**: Verify `lmw`/`stmw`, `lswi`/`stswi`, and byte-reversed load/store instructions against `qemu-ppc`. (`experiments/E05/FINDINGS.md`)
- [x] **E06 (TLS (`r2` Thread Pointer) & `lwarx`/`stwcx.` Reservation Semantics)**: Verify `CLONE_SETTLS` (`r2`), `set_tid_address`, and `lwarx`/`stwcx.` atomic sequences under `qemu-ppc`. (`experiments/E06/FINDINGS.md`)
- [x] **Gate `RC-E`**: All `experiments/E01..E06/FINDINGS.md` committed on `master` with target cross-compiler `sizeof`/`offsetof` and `qemu-ppc (with -cpu 750 and -cpu e500v2)` ground-truth verification.

### Phase 0 — Repository Scaffold, Frozen Headers & Substrate Copy (`RC0`)
Read [`docs/lanes/phase-0.md`](docs/lanes/phase-0.md) and run lanes `L0a..L0b`:
- [x] **Lane `L0a`**: Copy and adapt `src/rt32/ from ../i686rt`, create `flake.nix`, `Makefile`, `src/ppc32rt.h`, and CLI entry (`--version`, `--help`, `--interp`, `--dbt`, `--difftest`, `--trace`).
- [x] **Lane `L0b`**: Create `tests/check_abi_invariants.c` verifying all `ppc32_ctx_t`, `sigframe`, `ucontext`, and `stat` `sizeof`/`offsetof` invariants with `_Static_assert` and runtime checks.
- [x] **Gate `RC0`**: `_build/ppc32rt` builds cleanly as a static-PIE `aarch64-unknown-linux-musl` binary; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass.

### Phase 1 — Base Integer Decoder, Reference Interpreter (`src/interp/`) & Minimal Syscalls (`RC1`)
Write `docs/lanes/phase-1.md` and run concurrent lanes `L1a..L1d`:
- [x] **Lane `L1a`**: Instruction decoder (`src/interp/decode.c`, `src/interp/decode.h`).
- [x] **Lane `L1b`**: Base integer reference interpreter (`src/interp/interp.c`) including all control-flow, delay-slot/annul, register-window/prefix, unaligned, and atomic instructions in `SPEC.md` §2.
- [x] **Lane `L1c`**: Minimal Linux syscall layer (`exit`, `exit_group`, `write`, `read`, `brk`, `mmap`, `munmap`, `mprotect`, `uname`, `set_tid_address`).
- [x] **Lane `L1d`**: Freestanding ISA test suite (`tests/test_p1_isa.c`) covering ALU, shifts, branches, page-final branches before `PROT_NONE` pages, atomics, and unaligned loads/stores.
- [x] **Gate `RC1`**: `test_p1_isa` under `PPC32RT_ENGINE=interp` matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` exit code and stdout bit-for-bit.

### Phase 2 — Static Libc Syscalls & Base Integer AArch64 DBT (`src/dbt/`) (`RC2`)
Write `docs/lanes/phase-2.md` and run concurrent lanes `L2a..L2d`:
- [ ] **Lane `L2a`**: Complete static-libc Linux syscall & struct conversion layer (`src/os/syscalls.c`, `stat`/`stat64`/`statx`, `iovec`, `openat`, `fcntl`, `clock_gettime`, `getrandom`, `futex`, `rt_sigprocmask`, `ioctl`).
- [ ] **Lane `L2b`**: AArch64 DBT core (`src/dbt/dbt.c`, `src/dbt/trampoline_a64.S`, direct block chaining, 4096-entry IBTC, RAS, D2 `EXIT_UNDEF`/`EXIT_SINGLE_STEP` interpreter fallback).
- [ ] **Lane `L2c`**: AArch64 integer instruction emitter (`src/dbt/emit_int.c`).
- [ ] **Lane `L2d`**: Differential harness (`--difftest`) + static libc test suite (`hello`, `printf`, `malloc`, `qsort`, file I/O).
- [ ] **Gate `RC2`**: `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa` and static libc binaries; outputs match `qemu-ppc (with -cpu 750 and -cpu e500v2)`.

### Phase 3 — Floating-Point & SIMD (`src/interp/fp.c`, `src/dbt/emit_fp.c`) (`RC3`)
Write `docs/lanes/phase-3.md` and run concurrent lanes `L3a..L3c`:
- [ ] **Lane `L3a`**: Complete FPU & SIMD reference interpreter (`src/interp/fp.c`) implementing all `SPEC.md` §2 FP/SIMD instructions, NaN rules, condition codes, and status registers.
- [ ] **Lane `L3b`**: AArch64 FP & NEON emitter (`src/dbt/emit_fp.c`) + phase-gated `AT_HWCAP` activation.
- [ ] **Lane `L3c`**: `tests/test_p3_fp_simd.c` covering scalar FP, SIMD lanes, NaN propagation, rounding modes, and conversions.
- [ ] **Gate `RC3`**: `test_p3_fp_simd` matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` golden output bit-for-bit on both `interp` and `dbt` with `0` `--difftest` divergences.

### Phase 4 — Signals (`rt_sigframe`), Threads (`clone`/`futex`/TLS), & Process Lifecycle (`fork`/`execve`) (`RC4`)
Write `docs/lanes/phase-4.md` and run concurrent lanes `L4a..L4c`:
- [ ] **Lane `L4a`**: Exact target Linux UAPI `rt_sigframe` construction & restoration (`rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, synchronous `SIGSEGV`/`SIGILL`/`SIGFPE`/`SIGBUS`/`SIGTRAP` delivery).
- [ ] **Lane `L4b`**: Multithreading (`clone` with `CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID`, `futex`, TLS register, LL/SC reservation invalidation across helpers/signals/threads).
- [ ] **Lane `L4c`**: Process lifecycle (`fork`, `vfork`, `execve`, `wait4`, `waitid`, `pipe2`, `dup2`) and `tests/test_p4_threads_signals.c`.
- [ ] **Gate `RC4`**: `test_p4_threads_signals` (signal frame inspection/modification/restoration, pthreads + futex, `fork`+`execve`+`wait4`) matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` on both `interp` and `dbt`.

### Phase 5 — Dynamic Linking (`PT_INTERP`), `BusyBox`, & Target `libc` Matrix (`RC5`)
Write `docs/lanes/phase-5.md` and run concurrent lanes `L5a..L5b`:
- [ ] **Lane `L5a`**: `PT_INTERP` dynamic loader (`ld.so`) mapping, complete auxiliary vector (`AT_PHDR`, `AT_ENTRY`, `AT_BASE`, `AT_HWCAP`, `AT_HWCAP2`, `AT_RANDOM`, `AT_EXECFN`), and `/proc/self/{exe,maps,cmdline,stat,auxv}` interception.
- [ ] **Lane `L5b`**: Dynamic `test_p5_dyn` (`dlopen`/`dlsym`, TLS `__thread`, shared library calls) and target `BusyBox` qualification (`sh -c 'ls / && echo ok | wc -c'`).
- [ ] **Gate `RC5`**: Dynamic `test_p5_dyn` and `BusyBox` match `qemu-ppc (with -cpu 750 and -cpu e500v2)` on both `interp` and `dbt`.

### Phase 6 — `hyper-linux` (`hl`) Host Contract & Dual-Host Parity (`RC6`)
Write `docs/lanes/phase-6.md` and run lanes `L6a..L6b`:
- [ ] **Lane `L6a`**: Verify full compliance with `../rt-series/docs/HOST-CONTRACT.md` (`/dev/a32host A32H_ABI 1.0/1.1 negotiation and G = 0x1_0000_0000`).
- [ ] **Lane `L6b`**: Run full parity suite (`test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, adjacent 4 KiB page permissions).
- [ ] **Gate `RC6`**: All Phase 1–5 suites pass cleanly under the AArch64 Linux runtime environment and host-contract harness.

### Phase 7 — Hardening (`SMC`, `libc-test`, LTP Syscall Subset, Instrumented CoreMark, C++17) (`RC-H`)
Write `docs/lanes/phase-7.md` and run concurrent hardening lanes `H1..H4`:
- [ ] **Lane `H1` (`tests/test_h1_smc.c`)**: Self-modifying code & W^X verification (rewrite guest instructions on stack/heap/anon mmap, flush cache, re-execute in `dbt`).
- [ ] **Lane `H2` (`docs/h2-report.md`)**: Run target `libc-test` (math, string, pthread, sig, functional) and LTP syscall subset; commit `docs/h2-report.md` with machine-enforced pass/skip/fail assertions (`0` unexpected failures).
- [ ] **Lane `H3` (`docs/h3-coremark.md`)**: Follow the mandatory 6-step performance loop (`AGENTS.md`: Instrument -> Measure -> Hypothesise -> Fix -> Measure again -> Validate) on CoreMark and commit `docs/h3-coremark.md` demonstrating verified `dbt > interp` throughput.
- [ ] **Lane `H4` (`tests/test_h4_cxx17.cc`)**: Compile and verify a C++17 binary exercising `try`/`catch` stack unwinding across signal/call frames, `dynamic_cast` RTTI, `std::thread`, and `thread_local` destructors.
- [ ] **Gate `RC-H`**: All `H1..H4` artifacts and tests pass on `master`; `make check` and `make check-line-limits` pass with a clean git tree.
