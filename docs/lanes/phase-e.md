# Phase E Task Cards — Empirical Pre-Implementation Experiments (`ppc32rt`)

Spawn **concurrent `subagent` worker lanes** for `E01..E06` in isolated worktrees (`../ppc32rt-e01` .. `../ppc32rt-e06`), merge each into `master`, and verify `RC-E`.

---

### Lane `E01` — PPC32 `sc` Syscall `CR0.SO` Error Flag & 64-Bit Pair Alignment
- **Worktree**: `../ppc32rt-e01` on branch `lane/pe-e01`
- **Exclusive Files**: `experiments/E01/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E01/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E01/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E01/FINDINGS.md
  ```

### Lane `E02` — Rotate-and-Mask (`rlwinm`/`rlwimi`) Wrap-Around (`MB > ME`) & `XER.CA`
- **Worktree**: `../ppc32rt-e02` on branch `lane/pe-e02`
- **Exclusive Files**: `experiments/E02/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E02/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E02/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E02/FINDINGS.md
  ```

### Lane `E03` — `.gnu.attributes` Parsing & Classic FPU vs `e500v2` SPE Dispatch
- **Worktree**: `../ppc32rt-e03` on branch `lane/pe-e03`
- **Exclusive Files**: `experiments/E03/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E03/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E03/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E03/FINDINGS.md
  ```

### Lane `E04` — PPC32 `ucontext_t` / `mcontext_t` (992 B) & SPE `evr[32]` Overlay
- **Worktree**: `../ppc32rt-e04` on branch `lane/pe-e04`
- **Exclusive Files**: `experiments/E04/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E04/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E04/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E04/FINDINGS.md
  ```

### Lane `E05` — Big-Endian String/Multiple Loads (`lmw`/`stmw`, `lswi`/`stswi`, `*brx`)
- **Worktree**: `../ppc32rt-e05` on branch `lane/pe-e05`
- **Exclusive Files**: `experiments/E05/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E05/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E05/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E05/FINDINGS.md
  ```

### Lane `E06` — TLS (`r2` Thread Pointer) & `lwarx`/`stwcx.` Reservation Semantics
- **Worktree**: `../ppc32rt-e06` on branch `lane/pe-e06`
- **Exclusive Files**: `experiments/E06/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E06/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)` and run under `qemu-ppc (with -cpu 750 and -cpu e500v2)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E06/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E06/FINDINGS.md
  ```

