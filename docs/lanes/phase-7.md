# Phase 7 Task Cards — Hardening (`RC-H`)

Run after `RC6` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 6 output,
this file.

Common lane rules: as Phase 2. Report lanes (H2/H3) additionally: every
pass/skip/fail count in the committed report must be machine-produced by
the lane's own check (no hand-written numbers).

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| H1 | `lane/p7-h1` `../ppc32rt-h1` | `tests/test_h1_smc.c` | host self-check prints `PASS` |
| H2 | `lane/p7-h2` `../ppc32rt-h2` | `tools/run_libc_ltp.sh`, `docs/h2-report.md` | report contains machine-verified counts, `0` unexpected failures |
| H3 | `lane/p7-h3` `../ppc32rt-h3` | `tools/run_coremark.sh`, `docs/h3-coremark.md` | report shows measured `dbt > interp` speedup |
| H4 | `lane/p7-h4` `../ppc32rt-h4` | `tests/test_h4_cxx17.cc` | host self-check prints `PASS` |

## Card H1 — Self-modifying code & W^X

Scope: `tests/test_h1_smc.c` fixture rewriting guest instructions on stack/
heap/anon-`mmap`, flushing cache, re-executing under `dbt` (page-version
invalidation path), verifying updated behavior; asserts no guest data page
is ever `PROT_EXEC` on the host.
Check: host self-check prints `PASS` (full run at `RC-H`).

## Card H2 — libc-test + LTP syscall subset

Scope: run target `libc-test` (math, string, pthread, sig, functional) and
the LTP syscall subset under both engines, diff against `qemu-ppc`;
commit `docs/h2-report.md` with machine-enforced pass/skip/fail assertions
and `0` unexpected failures.
Check: `test -s docs/h2-report.md` with counts produced by the run.

## Card H3 — 6-step instrumented CoreMark

Scope: mandatory 6-step loop (Instrument → Measure → Hypothesise → Fix →
Measure again → Validate) on CoreMark comparing `interp` vs `dbt`; commit
`docs/h3-coremark.md` demonstrating verified `dbt > interp` throughput with
before/after numbers from actual runs.
Check: `test -s docs/h3-coremark.md` containing both measurement tables.

## Card H4 — C++17 exceptions/RTTI/TLS smoke

Scope: `tests/test_h4_cxx17.cc` exercising `try`/`catch` unwinding across
signal/call frames, `dynamic_cast` RTTI, `std::thread`, and `thread_local`
destructors; prints `PASS`, exits 0.
Check: host self-check (`g++ -std=c++17` syntax + native run) prints `PASS`.

## `RC-H` (coordinator, after all four merge)

All `H1..H4` artifacts and tests pass on `master`; `make check` and
`make check-line-limits` pass with a clean git tree.
