# Phase 7 Task Cards — Hardening (`SMC`, `libc-test` + LTP, CoreMark, C++17) (`ppc32rt`)

Run after `RC6` (`e663356`) is committed on `master`. Frozen contracts:
`src/ppc32rt.h`, `include/a32host.h` (byte-identical), `src/os/syscall_nr.h`,
`Makefile`, `SPEC.md` 1.1 (window) + `../rt-series/docs/HOST-CONTRACT.md`.
`--engine`/`--sysroot`/`--window`/`--execfn`/`--image-fd`/`--no-host`,
`--interp`/`--dbt`/`--difftest`, the full P1–P6 parity suite, and
`src/os/hostfault.c` protection-fault translation exist; Phase 7 hardens
the translator. SMC translation-cache invalidation on guest writes is
NOT yet real (`vm.c` D11 note); the loader maps what `PT_LOAD`/`PT_DYNAMIC`
need today.

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept
(guest data pages never `PROT_EXEC` on the host), dual-engine parity,
`timeout --kill-after=30s` on every build/Docker/`qemu-ppc` step, no
AI/agent names, never `git push`. Coordinator owns `docs/lanes/phase-7.md`,
merges `--no-ff`, removes lane worktrees + containers. A lane stops and
reports back when its acceptance command fails twice, needs a frozen-header
or non-exclusive-file edit, or a spec detail is ambiguous.

---

## Lane `H1` — Self-Modifying Code & W^X (`tests/test_h1_smc.c`)

- **Worktree**: `../ppc32rt-h1` on branch `lane/p7-h1`
- **Exclusive files**: `tests/test_h1_smc.c` (new), `tools/p7_smc.sh` (new),
  `src/dbt/cache.c`, `src/dbt/dbt.c`
- **Task**:
  1. `tests/test_h1_smc.c` (freestanding): rewrite guest instructions on
     stack, heap, and anon `mmap`; flush with the PPC cache-control
     instruction the oracle honors; re-execute under `--dbt` and confirm
     the NEW bytes run (not stale translations). Cover `mprotect` and
     `munmap` page invalidation. Print `PASS`, exit 0, matching
     `qemu-ppc -cpu 750` + `-cpu e500v2` goldens on `--interp`/`--dbt`
     with `--difftest` EQUAL.
  2. W^X probe in the same fixture or script: guest data pages stay
     non-`PROT_EXEC` on the host throughout.
  3. `tools/p7_smc.sh`: build the fixture (`powerpc-linux-gnu-gcc`,
     freestanding like `build_fixture.sh`), run the oracle/engines/
     difftest matrix, exit 0 only on full match.
- **Acceptance command**: `sh tools/p7_smc.sh` exit 0 in the lane worktree
  (inside the lane container where Docker applies).

## Lane `H2` — `libc-test` + LTP Syscall Subset (`docs/h2-report.md`)

- **Worktree**: `../ppc32rt-h2` on branch `lane/p7-h2`
- **Exclusive files**: `docs/h2-report.md` (new), `tools/p7_libc.sh` (new)
- **Task**:
  1. Fetch, build (powerpc), and run target `libc-test` (math, string,
     pthread, sig, functional) plus the LTP syscall subset under
     `qemu-ppc -cpu 750`, `--interp`, and `--dbt`.
  2. Commit `docs/h2-report.md` with machine-enforced pass/skip/fail
     assertions: `0` unexpected failures (unexpected = fails on the
     translator while passing on the oracle; oracle-fails are
     documented skips with the oracle log line quoted).
  3. `tools/p7_libc.sh`: one bounded command reproducing the report
     (fetch/build/run/diff), exit 0 when the report's assertions hold.
- **Acceptance command**: `sh tools/p7_libc.sh` exit 0 in the lane
  worktree with `docs/h2-report.md` committed (inside the lane
  container where Docker applies).

## Lane `H3` — Instrumented CoreMark 6-Step Loop (`docs/h3-coremark.md`)

- **Worktree**: `../ppc32rt-h3` on branch `lane/p7-h3`
- **Exclusive files**: `docs/h3-coremark.md` (new), `tools/p7_coremark.sh` (new)
- **Task**:
  1. Fetch, build (powerpc, static), and run CoreMark under
     `qemu-ppc -cpu 750`, `--interp`, and `--dbt` (bounded iterations,
     wall-clock timeouts).
  2. Follow the mandatory 6-step loop (Instrument → Measure →
     Hypothesise → Fix → Measure again → Validate); commit
     `docs/h3-coremark.md` with measured numbers demonstrating verified
     `dbt > interp` throughput plus the one bottleneck fixed.
  3. `tools/p7_coremark.sh`: reproduce the measurement, exit 0.
- **Acceptance command**: `sh tools/p7_coremark.sh` exit 0 in the lane
  worktree with `docs/h3-coremark.md` committed (inside the lane
  container where Docker applies).

## Lane `H4` — C++17 Exceptions/RTTI/TLS (`tests/test_h4_cxx17.cc`)

- **Worktree**: `../ppc32rt-h4` on branch `lane/p7-h4`
- **Exclusive files**: `tests/test_h4_cxx17.cc` (new), `tools/p7_cxx.sh` (new),
  `src/rt32/ppc32_elf32.c`
- **Task**:
  1. `tests/test_h4_cxx17.cc`: `try`/`catch` stack unwinding across
     call frames (and across a guest signal frame), `dynamic_cast`
     RTTI, `std::thread` create/join, `thread_local` destructors.
     Print `PASS`, exit 0, matching `qemu-ppc -cpu 750` (+ e500v2
     best-effort) on `--interp`/`--dbt` with `--difftest` EQUAL.
  2. Build with the powerpc C++ driver (static; lane installs the
     toolchain it needs). Loader gaps (`PT_GNU_EH_FRAME`, unwind
     tables) may be closed in `src/rt32/ppc32_elf32.c` only.
  3. `tools/p7_cxx.sh`: build + matrix, exit 0 on full match.
- **Acceptance command**: `sh tools/p7_cxx.sh` exit 0 in the lane
  worktree (inside the lane container where Docker applies).

---

## `RC-H` (coordinator, after all lanes merge)

1. Merge `H1..H4` (`--no-ff`), wire dispatch, host + cross build.
2. Re-run `tools/p6_host_check.sh`, `tools/p6_parity.sh`, plus
   `H1`/`H4` gates on both engines × both CPUs with `0` divergences;
   `h2-report.md` shows `0` unexpected failures, `h3-coremark.md`
   shows measured `dbt > interp`.
3. Tick every remaining `GOAL.md` box, `make check`,
   `make check-line-limits`, `check-abi-invariants` green, clean tree.
4. Commit `RC-H` on `master` (`GOAL.md` all `[x]`).
