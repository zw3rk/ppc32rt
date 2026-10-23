# Phase 0 Task Cards — Repository Scaffold, Frozen Headers & Substrate Copy (`ppc32rt`)

Run after `RC-E` is merged to `master`.

---

### Lane `L0a` — Substrate Copy, Frozen Headers (`src/ppc32rt.h`), Build System (`Makefile`, `flake.nix`) & CLI Entry
- **Worktree**: `../ppc32rt-l0a` on branch `lane/p0-l0a`
- **Exclusive Files**: `Makefile`, `flake.nix`, `src/ppc32rt.h`, `src/main.c`, `src/os/syscall_nr.h`, `src/rt32/**`
- **Task**:
  1. Copy and adapt the `src/rt32/ substrate from ../i686rt/src/ (vm.c, elf32.c, stack32.c, host.c, a64_emit.[ch], safe_syscall_a64.S)`.
  2. Define `ppc32_ctx_t` in `src/ppc32rt.h` matching `SPEC.md` §2.1 exact offsets.
  3. Implement `src/main.c` supporting `--version`, `--help`, `--interp`, `--dbt`, `--difftest`, `--trace`, and `PPC32RT_ENGINE=interp|dbt`.
  4. Create `Makefile` (with `build`, `check`, `check-line-limits`, `check-abi-invariants`, `clean`, `help`) and `flake.nix`.
- **Acceptance Command**:
  ```sh
  nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c make build check-line-limits
  ```

---

### Lane `L0b` — ABI Invariant Verification Suite (`tests/check_abi_invariants.c`)
- **Worktree**: `../ppc32rt-l0b` on branch `lane/p0-l0b`
- **Exclusive Files**: `tests/check_abi_invariants.c`, `src/os/sigframe_ppc32rt.h`
- **Task**:
  1. Define the frozen target UAPI signal frame (`sigframe_ppc32rt.h`), `ucontext`, `sigcontext`/`mcontext`, and `stat` structs matching `SPEC.md` §2 and `experiments/E04/FINDINGS.md`.
  2. Write `tests/check_abi_invariants.c` with `_Static_assert` and runtime offset checks verifying every field offset and struct size in `ppc32_ctx_t` and `sigframe_ppc32rt.h`.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/check_abi_invariants.c -o _build/check_abi_invariants && ./_build/check_abi_invariants
  ```
