# `ppc32rt` — Technical Specification & Execution Plan

**Target Architecture**: PowerPC 32-Bit (`750`/RAD750 Classic FPU & NXP `e500v2` SPE)
**Target Host**: AArch64 Linux (`aarch64-unknown-linux-musl` static-PIE) & macOS on Apple Silicon via `hyper-linux` (`hl`)
**Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)

---

## 0. Execution Protocol (Muse Spark Coordinator + Parallel Worker-Lane DAG)

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` on `master`) owns frozen headers (`src/ppc32rt.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Concurrent Subagents & Workflows**:
     - For every phase (`Phase E`, `Phase 0` .. `Phase 7`), spawn **multiple concurrent `subagent` worker lanes in parallel** using isolated git worktrees (`../ppc32rt-<lane>` on branch `lane/<phase>-<lane>`) and use `run_workflow` / `list_workflows` where helpful.
     - Each worker lane has **exclusive file ownership**, codes against **frozen headers**, and runs **one bounded acceptance check** (`timeout --kill-after=30s ...`).
2. **Dual-Oracle Verification**:
   - Every phase validates `src/interp/` against the independent **`qemu-ppc (with -cpu 750 and -cpu e500v2)` ground-truth oracle** first, and then validates `src/dbt/` against `src/interp/` via `--difftest` (`0` register/PC mismatches).

---

## 1. Target Profile, ELF Admission & Substrate Architecture

### 1.1 Target CPUs & ELF Admission
- **Target CPUs**: PowerPC 750 (G3) / BAE RAD750 / 7400 (`ppc32-classic`) and NXP QorIQ / PowerQUICC III e500v2 (`P1021` / `MPC8548`, `ppc32-spe`)
- **ELF Admission**: `ELFCLASS32`, `ELFDATA2MSB` (big-endian), `e_machine == EM_PPC (20)`. Profile auto-detected from `.gnu.attributes` (`Tag_GNU_Power_ABI_FP` / `Tag_GNU_Power_ABI_Vector`), SPE opcode presence, or `--profile=classic|spe` (`PPC32RT_PROFILE`)
- **Guest `TASK_SIZE`**: `0xc0000000 (stack top 0xbfff0000, vDSO/sigtramp 0xbfffe000)`
- **Ground-Truth Oracle**: `qemu-ppc (with -cpu 750 and -cpu e500v2)`
- **Cross Toolchains**: `pkgsCross.ppc-embedded / powerpc-unknown-linux-gnu and musl powerpc toolchains`

### 1.2 Class-A 4 GiB Window (`[G, G + 4 GiB)`) & `src/rt32/` Copy-First Substrate
- `ppc32rt` allocates a contiguous 4 GiB + 64 KiB guard region `[G, G + 4 GiB + 64 KiB)` (`PROT_NONE` reservation via `src/rt32/vm.c`).
- Under standalone AArch64 Linux, `G` is chosen dynamically by the host kernel (`mmap(NULL, 0x100010000ULL, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)`).
- Under `hyper-linux` (`hl`), `/dev/a32host` (`include/a32host.h`, `A32H_ABI 1.0/1.1`) provides `G = 0x100000000ULL` (`A32H_CAP_FIXED_OFFSET_4G`).
- **Phase 0 Lane `L0a`** copies the proven `rt32` substrate from `../i686rt/src/` (or `../a32rt/src/`) into `src/rt32/`:
  - `src/rt32/vm.c`, `src/rt32/elf32.c`, `src/rt32/stack32.c`, `src/rt32/host.c`, `src/rt32/a64_emit.[ch]`, `src/rt32/safe_syscall_a64.S` (with `D18` signal-window race-free commit point and `D19` `CLONE_VM` page-table mutex locking).
  - Parameterize `elf32.c` on `ppc32rt`'s `e_machine`, endianness, and `e_flags` admission rules.

---

## 2. CPU Context, ISA Semantics & Linux ABI

### 2.1 `ppc32_ctx_t` Unified Context & Dual-FPU/SPE Register Architecture (`src/ppc32rt.h`)
- **Unified Context Layout (`_Static_assert` verified in `tests/check_abi_invariants.c`)**:
  - `0x000`: `uint32_t gpr[32]` (low 32 bits of `r0..r31`; `r1 = sp`, `r2 = tp` TLS pointer, `r3..r10` args/return, `r13` small data)
  - `0x080`: `uint32_t gpr_hi[32]` (upper 32 bits of `r0..r31` for e500v2 SPE 64-bit `ev*`/`efd*` operations; untouched by classic 32-bit instructions)
  - `0x100`: `uint32_t nip` (`pc`), `uint32_t lr`, `uint32_t ctr`, `uint32_t cr` (8 × 4-bit fields `CR0..CR7`, each `[LT, GT, EQ, SO]`), `uint32_t xer`, `uint32_t fpscr`, `uint32_t spefscr`
  - `0x120`: `uint64_t acc` (64-bit SPE accumulator), `uint64_t fpr[32]` (classic `f0..f31` 64-bit IEEE-754 registers)
  - `0x228`: `uint64_t guest_base` (`G`), `uint32_t res_addr`, `uint32_t res_val`, `uint8_t res_valid`, `uint8_t is_spe`.
- **Big-Endian Memory Access**:
  - Every 16/32/64-bit guest memory load/store in `interp` and `dbt` byte-swaps (`REV16`, `REV`, `REV64`) because guest memory is big-endian (`ELFDATA2MSB`).

### 2.2 PowerPC Book I, Classic FPU (`750`), & NXP `e500v2` SPE Semantics
- **PowerPC Book I Integer ISA**:
  - Full arithmetic, logical, rotate/mask (`rlwinm[.]`, `rlwnm[.]`, `rlwimi[.]` with wrap-around `MB > ME` masks), condition register logical ops (`crand`, `cror`, `crxor`, `crnand`, `crnor`, `creqv`, `crandc`, `crorc`, `mcrf`), `mfcr`/`mtcrf`, `mfspr`/`mtspr` (`LR=8`, `CTR=9`, `XER=1`, `TB=268`, `TBU=269`), byte-reversed loads/stores (`lhbrx`, `lwbrx`, `sthbrx`, `stwbrx`), load/store with update (`lbzu`, `lhzu`, `lwzu`, `stbu`, `sthu`, `stwu`), multiple word (`lmw`, `stmw`), string word (`lswi`, `stswi`), and `lwarx`/`stwcx.` (with reservation invalidation on helper/syscall/signal/thread-switch).
- **Classic 64-Bit FPU (`ppc32-classic`)**:
  - 32 × 64-bit `fpr[0..31]`, `lfs`/`lfd`/`stfs`/`stfd` (+ update/indexed), `fadd[s]`, `fsub[s]`, `fmul[s]`, `fdiv[s]`, `fsqrt[s]`, `fmadd[s]`, `fmsub[s]`, `fnmadd[s]`, `fnmsub[s]`, `fcmpu`/`fcmpo`, `fctiw[z]`, `frsp`, `fabs`, `fnabs`, `fneg`, `fmr`, `fsel`, `mffs`/`mtfsf`.
- **NXP `e500v2` SPE APU (`ppc32-spe`, Major Opcode 4)**:
  - 64-bit GPRs formed as `((uint64_t)gpr_hi[r] << 32) | gpr[r]` plus 64-bit `acc` and `spefscr`.
  - Vector integer/logical/merge/ldst (`evaddw`, `evsubfw`, `evand`, `evor`, `evxor`, `evmr`, `evmergehi`, `evmergelo`, `evmergelohi`, `evmergehilo`, `evldd[x]`, `evldw[x]`, `evstdd[x]`, `evstdw[x]`, `evlwhe[x]`, `evlwhos[x]`, `evlwhou[x]`, `evstwwe[x]`, `evstwwo[x]`, `evcmpeq`, `evcmpgts`, `evcmpgtu`, `evsel`, `evmra`, MAC ops).
  - Scalar single-precision `efs*` (`efsadd`, `efssub`, `efsmul`, `efsdiv`, `efsabs`, `efsnabs`, `efsneg`, `efscmpgt`, `efscmplt`, `efscmpeq`, `efscfd`, `efsctsi`, `efsctuf`, etc.), scalar double-precision `efd*` (`efdadd`, `efdsub`, `efdmul`, `efddiv`, `efdabs`, `efdneg`, `efdcmp*`, `efdcfs`, `efdctsi[z]`, `efdcfsi`, etc.), and vector float `evfs*`.

### 2.3 PPC32 Linux Syscall, vDSO & Signal Frame ABI (`src/os/`)
- **PPC32 Syscall Convention (`sc` instruction `0x44000002`)**:
  - Syscall number in `r0`; arguments 1..6 in `r3, r4, r5, r6, r7, r8` (64-bit args in aligned register pairs, high word first).
  - Success: **`CR0.SO = 0`** (`ctx->cr &= ~0x10000000U`), `r3 = (uint32_t)ret`.
  - Error: **`CR0.SO = 1`** (`ctx->cr |= 0x10000000U`), **`r3 = (uint32_t)(-ret)`** (positive errno).
- **PPC32 `rt_sigframe` & `mcontext_t` (`src/os/sigframe_ppc32.h`, Linux `arch/powerpc/include/uapi/asm/ucontext.h`, Verified in `tests/check_abi_invariants.c`)**:
  - `struct mcontext` (`mcontext_t`, **992 bytes**, 16-byte aligned):
    - `0x000..0x0bf`: `uint32_t mc_gregs[48]` (192 B: `r0..r31`, `nip`, `msr`, `orig_r3`, `ctr`, `link`, `xer`, `ccr`, `mq`, `trap`, `dar`, `dsisr`, `result`)
    - `0x0c0..0x1c7`: `uint64_t mc_fregs[33]` (264 B: `f0..f31` + `fpscr`)
    - `0x1c8..0x1cf`: `uint32_t mc_pad[2]` (8 B padding to align `mc_vregs` to 16 bytes at `0x1d0`)
    - `0x1d0..0x3df`: `uint8_t mc_vregs[528] __attribute__((aligned(16)))` (inline `elf_vrregset_t` = `33 * 16 = 528` B; on e500v2 SPE, Linux overlays `uint32_t evr[32]` (`128 B`, holding `gpr_hi[0..31]`), `uint64_t acc` (`8 B`), and `uint32_t spefscr` (`4 B`) at the start of `mc_vregs`!).

---

## 3. Dual-Engine Design (`src/interp/` + `src/dbt/`)

1. **Reference Interpreter (`src/interp/`)**:
   - Pure Curated C11 step-by-step and chunked interpreter (`interp_step(ppc32_ctx_t *ctx)` and `interp_run(ppc32_ctx_t *ctx)`).
   - Serves as:
     - Ground-truth reference engine (`PPC32RT_ENGINE=interp` or `--interp`),
     - Instruction-by-instruction differential oracle (`--difftest`),
     - Single-instruction fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP` -> `interp_step(ctx)` -> resume DBT) for rare system/unaligned/cross-page delay-slot instructions so valid instructions never abort execution.
2. **AArch64 Dynamic Binary Translator (`src/dbt/`)**:
   - Translates guest basic blocks (up to 64 guest instructions, terminating at control transfers or page boundaries) into AArch64 machine code using `a64_emit.[ch]`.
   - Direct block chaining + 4096-entry per-thread Indirect Branch Target Cache (`IBTC`) + Return Address Stack (`RAS`).
   - Enforces W^X (`PROT_READ | PROT_WRITE` during emission -> `PROT_READ | PROT_EXEC` before execution + `__builtin___clear_cache` / `A32H_CAP_ICACHE_TRAP_IALLU`) and self-modifying code (`SMC`) page-version invalidation on `mprotect` / `munmap` / `clear_cache` / guest writes to translated pages.
   - **Never touches `x18`**.

---

## 4. Nine-Phase Implementation Pipeline & Review Checkpoints (`RC`)

| Phase / Gate | Lanes (Run in Parallel Worktrees) | Required Independent Oracle & Acceptance Gate |
|---|---|---|
| **Phase E (`RC-E`)** | `E01` .. `E06` (`experiments/E01..E06/FINDINGS.md`) | All 6 empirical probes compiled with target cross-CC, executed under `qemu-ppc (with -cpu 750 and -cpu e500v2)`, and committed with `FINDINGS.md` (`sizeof`/`offsetof` verified). |
| **Phase 0 (`RC0`)** | `L0a` (Substrate copy + build), `L0b` (`tests/check_abi_invariants.c` + CLI smoke) | `aarch64-unknown-linux-musl-gcc -static-pie` builds `_build/ppc32rt`; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass; `--version` / `--help` pass in AArch64 Docker container. |
| **Phase 1 (`RC1`)** | `L1a` (Decoder), `L1b` (Integer `src/interp/`), `L1c` (Minimal syscalls `exit`, `write`, `brk`, `mmap`), `L1d` (`test_p1_isa`) | `test_p1_isa` (covering ALU, shifts, branches, delay slots/annul at `page_end - 4` before `PROT_NONE` page, atomics, unaligned accesses) matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` exit code and stdout bit-for-bit under `PPC32RT_ENGINE=interp`. |
| **Phase 2 (`RC2`)** | `L2a` (`src/os/` static libc syscalls + struct translation), `L2b` (`src/dbt/` dispatcher + block cache + IBTC), `L2c` (`src/dbt/emit_int.c`), `L2d` (`difftest` + static libc tests) | `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa`; static `hello`, `printf`, `qsort`, `malloc`, and file I/O match `qemu-ppc (with -cpu 750 and -cpu e500v2)` on both `interp` and `dbt`. |
| **Phase 3 (`RC3`)** | `L3a` (`src/interp/fp.c` FPU/SIMD), `L3b` (`src/dbt/emit_fp.c` NEON/FP lowering), `L3c` (`test_p3_fp_simd`) | `test_p3_fp_simd` (NaN modes, rounding, FPU/SIMD corner cases) matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` bit-for-bit on both `interp` and `dbt` with `0` difftest divergences. |
| **Phase 4 (`RC4`)** | `L4a` (`rt_sigframe` + `rt_sigaction`/`rt_sigreturn`/altstack), `L4b` (`clone`/TLS/`futex`/reservation invalidation), `L4c` (`fork`/`vfork`/`execve`/`wait4` + `test_p4_threads_signals`) | `test_p4_threads_signals` (signal frame inspection/modification/restoration, `SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`) matches `qemu-ppc (with -cpu 750 and -cpu e500v2)` on both `interp` and `dbt`. |
| **Phase 5 (`RC5`)** | `L5a` (`PT_INTERP` dynamic linker loading + auxv + `/proc/self/*`), `L5b` (Dynamic `glibc`/`musl` + `BusyBox` suite) | Dynamic `test_p5_dyn` and `BusyBox` (`sh -c 'ls / && echo ok | wc -c'`) match `qemu-ppc (with -cpu 750 and -cpu e500v2)` on both `interp` and `dbt`. |
| **Phase 6 (`RC6`)** | `L6a` (`hyper-linux` host contract & packaging), `L6b` (Both-host parity test suite) | `test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, and `BusyBox` pass on both AArch64 Linux container and `hl` (`hyper-linux`). |
| **Phase 7 (`RC-H`)** | `H1` (`test_h1_smc`), `H2` (`libc-test` + LTP syscall subset -> `docs/h2-report.md`), `H3` (6-step instrumented CoreMark -> `docs/h3-coremark.md`), `H4` (C++17 exceptions/RTTI/TLS smoke) | All 4 hardening gates committed with machine-verified pass counts (`0` unexpected failures) and measured `dbt > interp` speedup in `docs/h3-coremark.md`. |
