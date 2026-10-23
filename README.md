# `ppc32rt` — PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE) User-Mode Binary Translator for AArch64

`ppc32rt` is a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (via [`hyper-linux`](../hyper-linux)).

- **Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)
- **Target CPUs**: PowerPC 750 (G3) / BAE RAD750 / 7400 (`ppc32-classic`) and NXP QorIQ / PowerQUICC III e500v2 (`P1021` / `MPC8548`, `ppc32-spe`)
- **ELF Admission**: `ELFCLASS32`, `ELFDATA2MSB` (big-endian), `e_machine == EM_PPC (20)`. Profile auto-detected from `.gnu.attributes` (`Tag_GNU_Power_ABI_FP` / `Tag_GNU_Power_ABI_Vector`), SPE opcode presence, or `--profile=classic|spe` (`PPC32RT_PROFILE`)
- **Guest `TASK_SIZE`**: `0xc0000000 (stack top 0xbfff0000, vDSO/sigtramp 0xbfffe000)`
- **Dual Execution Engines**:
  1. `src/interp/` — Portable Curated C11 reference interpreter and differential oracle (`PPC32RT_ENGINE=interp`)
  2. `src/dbt/` — Direct-mapped + IBTC AArch64 dynamic binary translator (`PPC32RT_ENGINE=dbt`, default) with single-instruction interpreter fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP`)

---

## Key Documents

| Document | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Repository ground rules, Curated C11 & AArch64 ABI invariants, Muse Spark Coordinator + Parallel Worker-Lane worktree protocol, and host environment notes. |
| [`SPEC.md`](SPEC.md) | Complete technical specification for `ppc32rt` (CPU context, ISA semantics, syscall/signal/thread ABI, host contract, and 9-phase verification pipeline). |
| [`GOAL.md`](GOAL.md) | Executable `/goal` specification for autonomous Muse Spark implementation (`Phase E` -> `Phase 0..Phase 7`). |
| [`docs/lanes/`](docs/lanes/) | Phase task cards (`phase-e.md`, `phase-0.md`, and subsequent phase lane cards). |
| [`../rt-series/`](../rt-series/) | Series-wide architecture (`../rt-series/SPEC.md`), master plan (`../rt-series/PLAN.md`), and host contract (`../rt-series/docs/HOST-CONTRACT.md`). |
