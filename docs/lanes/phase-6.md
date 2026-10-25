# Phase 6 Task Cards — `hyper-linux` Host Contract & Dual-Host Parity (`ppc32rt`)

Run after `RC5` (`f2a792d`) is committed on `master`. Frozen contracts:
`src/ppc32rt.h`, `include/a32host.h` (byte-identical to `a32rt`/`i686rt`),
`src/os/syscall_nr.h`, `Makefile`, `SPEC.md` 1.1 (window) +
`../rt-series/docs/HOST-CONTRACT.md` (A32H_ABI 1.0/1.1, Wave 1 CLI).
Current state: `/dev/a32host` probe (`src/rt32/ppc32_host.c`),
`PPC32RT_WINDOW`/`PPC32RT_HOST` env handling, `--engine`/`--sysroot`/
`--trace`/`--profile` flags exist; `guest_load` passes literal `0` to
`ppc32_vm_init`, so the env/window_hint order is dead; `--window`/
`--execfn`/`--image-fd`/`AT_EXECFD`/`--no-host` do not exist yet.

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept,
dual-engine parity, `timeout --kill-after=30s` on every build/Docker/
`qemu-ppc` step, no AI/agent names, never `git push`. Coordinator owns
`docs/lanes/phase-6.md`, merges `--no-ff`, removes lane worktrees +
containers. A lane stops and reports back when its acceptance command
fails twice, needs a frozen-header edit, or a spec detail is ambiguous.

---

## Lane `L6a` — CLI/Window/`a32host` Contract + Host Check

- **Worktree**: `../ppc32rt-l6a` on branch `lane/p6-l6a`
- **Exclusive files**: `src/main.c` (CLI parsing + `guest_load` call
  only), `src/rt32/ppc32_host.c` (probe only), `src/rt32/ppc32_vm.c`
  (`G` resolution only), `tools/p6_host_check.sh` (new)
- **Task**:
  1. `src/main.c`: add `--window <hex>` (fail-hard on bad value /
     reservation failure), `--execfn PATH` (sets `exec_path`, remaining
     args become guest `argv` verbatim incl. custom `argv[0]`),
     `--image-fd FD` (load ELF from the open descriptor, `close()` after
     mapping; never touch fds `0,1,2` or caller fds otherwise), and
     `--no-host` (skip the `/dev/a32host` probe like
     `PPC32RT_HOST=none`). Without `--execfn`, `argv[i]` stays both
     path and `argv[0]`.
  2. `src/main.c`: `AT_EXECFD` detection via `errno`-checked
     `getauxval(AT_EXECFD)` (or raw auxv scan); a value of `0` with
     `errno == 0` is a valid fd. Prefer `--image-fd` over auxv; close
     the loader-private fd after mapping.
  3. `src/main.c` + `src/rt32/ppc32_vm.c`: implement the contract `G`
     order — `--window` (fail-hard) → `PPC32RT_WINDOW` (fail-hard) →
     `window_hint` (when `has_host_info`) → `G = 0` with the existing
     4 GiB-aligned scan fallback (`guest_load` must pass `UINT64_MAX`
     when no explicit window is given, not literal `0`).
  4. `tools/p6_host_check.sh`: exercise no-device fallback,
     `PPC32RT_HOST=none`, `--no-host`, `--window` (good + bad),
     `--execfn` custom `argv[0]`, `--image-fd` load, and `AT_EXECFN`
     presence; all PASS in the lane container
     (`--platform linux/arm64` Debian + `gcc-powerpc-linux-gnu`,
     `qemu-user`).
- **Acceptance command**: `sh tools/p6_host_check.sh` exit 0 in the
  lane worktree (run inside the lane container where Docker applies).

## Lane `L6b` — Full Parity Suite + Adjacent 4 KiB Page Permissions

- **Worktree**: `../ppc32rt-l6b` on branch `lane/p6-l6b`
- **Exclusive files**: `tools/p6_parity.sh` (new),
  `tests/test_p6_perms.c` (new)
- **Task**:
  1. `tests/test_p6_perms.c` (freestanding): adjacent 4 KiB pages with
     distinct permissions (`PROT_READ|PROT_EXEC` next to
     `PROT_READ|PROT_WRITE`, `PT_GNU_RELRO`-style RX-then-RW split);
     guest faults land exactly on the guarded page on `--interp` and
     `--dbt`, matching the `qemu-ppc -cpu 750` + `-cpu e500v2` oracles
     (print `PASS`, exit 0).
  2. `tools/p6_parity.sh`: re-run `test_p1_isa`, `test_p2_libc`,
     `test_p3_fp_spe`, `test_p4_threads_signals`, `test_p5_auxv`,
     `test_p5_dyn` (+ `test_p6_perms`, + `qualify_busybox.sh`) under
     `--interp` and `--dbt` on both CPUs vs `qemu-ppc` goldens with `0`
     divergences; invoke L6a's `tools/p6_host_check.sh`.
- **Acceptance command**: `sh tools/p6_parity.sh` exit 0 in the lane
  worktree (run inside the lane container where Docker applies).

---

## `RC6` (coordinator, after both merge)

1. Merge `L6a`/`L6b` (`--no-ff`), wire dispatch, host + cross build.
2. Re-run `tools/p6_host_check.sh`, `tools/p6_parity.sh`, plus the
   P1–P5 gates on both engines × both CPUs with `0` divergences;
   `make check`, `make check-line-limits`, `check-abi-invariants`.
3. Tick `GOAL.md` Phase 6 / `RC6`, commit on `master`.
