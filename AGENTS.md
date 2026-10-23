# AGENTS.md — `ppc32rt`

Follow `~/.config/ai/AGENTS.md`, `~/.config/ai/C_GUIDELINES.md`, and `../rt-series/AGENTS.md`. Keep `CLAUDE.md` symlinked to `AGENTS.md`.

---

## 1. Authoritative Specifications

- **Read [`SPEC.md`](SPEC.md) and [`GOAL.md`](GOAL.md) first.**
- Cross-check series-wide invariants in [`../rt-series/SPEC.md`](../rt-series/SPEC.md), [`../rt-series/docs/HOST-CONTRACT.md`](../rt-series/docs/HOST-CONTRACT.md), and [`../rt-series/lode/ISA-TRAP-AND-ABI-MATRIX.md`](../rt-series/lode/ISA-TRAP-AND-ABI-MATRIX.md).
- Phase task cards live in [`docs/lanes/`](docs/lanes/).

---

## 2. Non-Negotiable Technical Invariants

- **Class-A 32-Bit 4 GiB Window (`[G, G + 4 GiB)`)**:
  - Reuses the proven `src/rt32/` substrate copied from `../i686rt` / `../a32rt` (with `D18` `safe_syscall_a64.S` signal window and `D19` `CLONE_VM` table locking applied). Never extract a shared cross-repo library; `ppc32rt` is a standalone zero-dependency repository.
  - Parametric 64-bit guest base `G` held in `x20` (`xG`); all 32-bit guest effective addresses wrap in 32-bit `W` registers before adding `xG` (`[x20, wAddr, uxtw]`).
  - Negotiates host capabilities via `/dev/a32host` (`include/a32host.h`, `A32H_ABI 1.0/1.1`).
- **Curated C11**: `-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror`. No VLAs, no Annex K (`*_s`), no `<threads.h>`, no `_Generic`, no `sprintf`/`strcpy`/`strcat`.
- **File Size Discipline**: Every `.c`, `.h`, and `.S` source file must stay **<= 900 lines** (`make check-line-limits`).
- **AArch64 Platform Register `x18`**: **Never read or write `x18`** in any assembly trampoline or JIT emitter (`src/dbt/`, `src/rt32/`, or `src/rt64/`).
- **W^X & I-Cache Coherence**: Never map guest data pages `PROT_EXEC` on the host; emit A64 code into RW staging/pages, flip to `PROT_READ | PROT_EXEC`, and flush I-cache properly.
- **Dual-Engine (`interp` + `dbt`) Parity**: Every ISA phase verifies `src/interp/` against the independent `qemu-ppc (with -cpu 750 and -cpu e500v2)` ground-truth oracle first, and then verifies `src/dbt/` (`--difftest`) with `0` register/PC divergences against `src/interp/`.

---

## 3. Muse Spark Workflow & Concurrent Worker-Lane Protocol

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` main agent on `master`) owns frozen headers (`src/ppc32rt.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Use Workflows & Multiple Concurrent Subagents**:
     - Use `list_workflows` / `run_workflow` where applicable and spawn **multiple concurrent `subagent` worker lanes in parallel** for independent tasks within a phase (`E01..E06`, `L0a..L0b`, `L1a..L1d`, `L2a..L2d`, `L3a..L3c`, `L4a..L4c`, `L5a..L5b`, `H1..H4`).
     - Each parallel writer lane runs in its own isolated git worktree (`../ppc32rt-<lane>` on branch `lane/<phase>-<lane>`), owns an exclusive set of files, codes against frozen headers, and runs its single bounded acceptance command once.
2. **Escalation Rule**:
   - A worker lane stops and reports back to the Coordinator if its acceptance command fails twice, if it needs an edit to a frozen header, or if a spec detail is ambiguous.

---

## 4. Verified Host Environment & Toolchain Notes (macOS Apple Silicon Host)

1. **Cross-Compiling the Translator (`aarch64-unknown-linux-musl-gcc`)**:
   - On this macOS host, `nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl` can fail with an empty daemon log; use **`nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c aarch64-unknown-linux-musl-gcc -static-pie -fPIE ...`** or `nix build .#ppc32rt` (which uses the configured `aarch64-linux` builder).
2. **Running AArch64 Linux Binaries & `qemu-ppc (with -cpu 750 and -cpu e500v2)` Oracle**:
   - `limactl` is not in `PATH` on this host; use **Docker (`--platform linux/arm64`)** with a unique container name and wall-clock timeout:
     ```sh
     timeout --kill-after=30s 120s docker run --rm --name ppc32rt-<lane>-$$ --memory 2g --cpus 2 --platform linux/arm64 -v "$PWD:/w" -w /w alpine /w/_build/ppc32rt /w/_build/tests/...
     ```
   - Always verify container cleanup (`docker ps`) on exit or error.
3. **Git & Attribution Hygiene**:
   - Default branch is `master`. Never `git push` without explicit user permission.
   - License: `Apache-2.0`, `Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.` Never include AI agent or model names in commit messages, trailers, or code comments.
