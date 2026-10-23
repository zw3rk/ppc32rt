# Phase 6 Task Cards — `hyper-linux` Host Contract & Dual-Host Parity (`RC6`)

Run after `RC5` is merged to `master`.

Frozen on `master` before fan-out (read-only to lanes): all Phase 5 output,
`include/a32host.h`, this file. Reference: `../rt-series/docs/HOST-
CONTRACT.md` (read-only).

Common lane rules: as Phase 2.

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L6a | `lane/p6-l6a` `../ppc32rt-l6a` | `src/rt32/host_ppc32.c`, `src/rt32/host_ppc32.h` | cross-compile via `nix shell` cross-CC |
| L6b | `lane/p6-l6b` `../ppc32rt-l6b` | `tools/parity_suite.sh` | `sh -n` + host dry-run listing |

## Card L6a — Host contract compliance

Scope: `/dev/a32host` `A32H_ABI 1.0/1.1` negotiation (`A32H_GET_INFO`,
`sizeof(a32h_info_t)==256` frozen check, per-capability-bit tests),
`G = 0x100000000ULL` fixed-offset window when `A32H_CAP_FIXED_OFFSET_4G`
(or series-equivalent cap) is advertised, graceful fallback to dynamic `G`
otherwise; `PPC32RT_HOST` env override honored.
Check: cross-compile `src/rt32/host_ppc32.c`, zero warnings.

## Card L6b — Both-host parity suite

Scope: `tools/parity_suite.sh` running `test_p1_isa`, `test_p3_fp_spe`,
`test_p4_threads_signals`, `test_p5_dyn`, BusyBox, plus adjacent-4 KiB-page
permission checks, on both the AArch64 Linux container path and the `hl`
(`hyper-linux`) host-contract harness path, diffing each against oracle
logs.
Check: `sh -n tools/parity_suite.sh` clean; host dry-run lists all five
suites.

## `RC6` (coordinator, after both merge)

All Phase 1–5 suites pass under the AArch64 Linux runtime environment and
the host-contract harness.
