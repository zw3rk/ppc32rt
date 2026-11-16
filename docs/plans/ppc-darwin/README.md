# `ppc32rt` Slice of PowerPC Darwin (`docs/plans/ppc-darwin/`)

**Architectural Boundary (`rt-series` + `hyper-linux`):**
`ppc32rt` remains **small**: it owns only 32-bit PowerPC ISA execution (`interp` + AArch64 `dbt`), CPU/AltiVec/exception state, the 4 GiB guest memory window / Soft-TLB, persistent AOT cache isolation, Linux ELF userspace, and the **narrow versioned cross-repo execution & trap callback contract (`G02`)** shared with `a32rt`.

All Darwin/XNU guest OS personality and UI code — Mach-O/FAT admission, `dyld` & binding, `0xFFFF8000` commpage policy, BSD/Mach traps, Wine-style stub libraries, native Tiger/Leopard framework bundles, and X11/WindowServer/Carbon/Cocoa/CoreAudio (`ppc-darwin-ui`) — lives in **`../hyper-linux`** (`../hyper-linux/docs/plans/ppc-darwin/` and `../hyper-linux/docs/plans/ppc-darwin-ui/`).

## Goal Cards Touching `ppc32rt`

| Goal | File | `ppc32rt` Scope |
|---|---|---|
| `G01` | [`01-baseline-and-target-matrix.goal`](01-baseline-and-target-matrix.goal) | Inventory existing `ppc32rt` classic G3/G4 + AltiVec coverage vs. Mac OS X 10.4/10.5 PPC32 CPU requirements. |
| `G02` | [`02-cross-repo-execution-contract.goal`](02-cross-repo-execution-contract.goal) | Narrow versioned guest execution, memory, trap (`sc` `r0 < 0` Mach / `r0 >= 0` BSD), fault, callback, and cancellation ABI shared with `a32rt` and `hl`. |
| `G04` | [`04-ppc-darwin-cpu-profile.goal`](04-ppc-darwin-cpu-profile.goal) | PowerPC 7400/7450 (G4) Darwin user-mode SPRs (`VRSAVE` SPR 256), AltiVec stream no-ops (`dss`/`dst`), cache ops (`dcba`/`dcbz` 32B line), FP/vector state, and trap syndrome reporting. |
| `G06` | [`06-darwin-vm-and-fault-bridge.goal`](06-darwin-vm-and-fault-bridge.goal) | Precise guest fault address/access-kind reporting (`DAR`/`DSISR` equivalents) across `interp` and `dbt` Soft-TLB into `hl`'s Mach exception / `SIGBUS` / `SIGSEGV` bridge. |
| `G12` | [`12-threads-tls-and-pthreads.goal`](12-threads-tls-and-pthreads.goal) | Per-thread `ppc32rt` CPU context creation/teardown and fast-trap/SPR thread-ID hook (`0x7FF0` ultra-fast trap or commpage read) without embedding `pthread` policy in `ppc32rt`. |
| `G13` | [`13-signals-mach-exceptions-unwind.goal`](13-signals-mach-exceptions-unwind.goal) | Architectural register/FPR/VR/CR/XER/LR/CTR/VRSAVE snapshot & restore hooks for `hl`'s Darwin `mcontext` / `_sigtramp` / Mach exception delivery. |
| `G16` | [`16-dbt-parity-and-aot-isolation.goal`](16-dbt-parity-and-aot-isolation.goal) | Lockstep `--difftest` parity on PPC Darwin CPU instructions and AOT cache-key isolation between Linux ELF and `hl`-hosted Darwin Mach-O profiles. |
| `G19` | [`19-security-and-differential-qualification.goal`](19-security-and-differential-qualification.goal) | Untrusted guest pointer/trap boundary hardening and convergence audit across the `ppc32rt` <-> `hl` contract. |
| `G20` | [`20-release-matrix-and-documentation.goal`](20-release-matrix-and-documentation.goal) | Reproducible qualification matrix and performance baselines. |
