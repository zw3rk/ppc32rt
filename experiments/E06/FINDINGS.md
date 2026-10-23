# E06 Findings — TLS (`r2`) & `lwarx`/`stwcx.` reservation

Status legend: **VERIFIED** = executed in this environment (host `cc`,
native run of `probe.c`); **ANALYTICAL** = grounded in the cited sources,
pending `qemu-ppc -cpu 750 / -cpu e500v2` confirmation (no qemu or PPC
cross-CC on this host).

## 1. Instruction encodings (VERIFIED arithmetic, ANALYTICAL execution)

X-form, primary opcode 31. `lwarx`: XO=20, Rc=0.
`stwcx.`: XO=150, Rc=1. EA = `(RA == 0 ? 0 : rA) + rB`.

| Instruction | Encoding | Word for `r4,r3,r5` |
|---|---|---|
| `lwarx RT,RA,RB` | `(31<<26)\|(RT<<21)\|(RA<<16)\|(RB<<11)\|(20<<1)\|0` | `0x7c832828` |
| `stwcx. RS,RA,RB` | `(31<<26)\|(RS<<21)\|(RA<<16)\|(RB<<11)\|(150<<1)\|1` | `0x7c83292d` |
| `sc` (syscall trap) | fixed | `0x44000002` |

Source: PowerPC Book I, Ch. on Storage Synchronization (`lwarx`/`stwcx.`
XO values). The two example words above are VERIFIED by `probe.c`
(`E06-SELFCHECK PASS`); guest execution under qemu is ANALYTICAL.

`stwcx.` Record semantics (Book I): CR0 = `[0, 0, EQ, XER(SO)]` —
LT/GT cleared, **EQ=1 iff the store was performed** (reservation held for
the addressed granule), EQ=0 otherwise. `lwarx` sets no CR bits.

## 2. TLS: `r2` is the thread pointer (ANALYTICAL, kernel/glibc source-grounded)

- On PPC32 Linux the TLS thread pointer lives in **`r2`**
  (`ctx->gpr[2]`); the PPC64 TP (`r13`) does **not** apply.
- PPC has **no `set_thread_area`/`get_thread_area` syscall and no
  `arch_prctl`**: the only kernel path that sets `r2` is
  `clone` with **`CLONE_SETTLS = 0x00080000`** (`linux/sched.h`), whose
  `tls` argument becomes the child's `r2`
  (`arch/powerpc/kernel/process.c`, `copy_thread`).
- `set_tid_address` is PPC syscall **nr 232**
  (`arch/powerpc/include/uapi/asm/unistd_32.h`); `clone` is **nr 120**.
  NPTL uses `set_tid_address` for `tid` futex clearing, orthogonal to `r2`.
- Toolchain note (ELF for the PowerPC Architecture supplement):
  thread-local accesses compile to `r2 + tprel(...)` sequences
  (`R_PPC_TPREL16*` relocs); the translator must therefore treat `r2` as
  an ordinary GPR that `clone(CLONE_SETTLS)` writes once at thread birth.

## 3. Reservation grant/clear semantics (ANALYTICAL model, VERIFIED state machine)

Model for `src/interp` + `src/dbt`: one global slot
`{res_addr (word-aligned EA), res_val (informational), res_valid}` —
exactly the SPEC 2.1 tail at offsets `0x230/0x234/0x238`
(VERIFIED via `_Static_assert` + runtime `offsetof` in `probe.c`;
`sizeof(ctx-shape) = 576`).

- **Grant**: `lwarx` sets `res_addr = EA & ~3`, `res_valid = 1`.
  Success is by **reservation presence, never by value compare**:
  `res_val` is debug-only; `stwcx.` must NOT compare memory against it.
- **Consume**: any executed `stwcx.` clears `res_valid`, whether it
  succeeded or failed. A second `stwcx.` without a new `lwarx` fails.
- **Overwrite**: a second `lwarx` replaces the grant; the old address fails.
- **Conservative invalidation** (superset of HW clearing, always correct
  because spurious `stwcx.` failure is architecturally legal and libc
  retry-loops on `EQ=0`): clear `res_valid` on `sc` entry/exit, signal
  delivery/return, thread switch, `clone`/`fork`, and around any helper
  call. Real HW additionally loses the reservation on context switch,
  external interrupts, and a foreign store to the granule.
- **Granule**: implementation-defined, >= 4 bytes. Emulator uses exact
  word (`EA & ~3`) comparisons plus the conservative clears above; this
  can only cause legal spurious failures.
- **Alignment edge case**: `EA & 3 != 0` on `lwarx`/`stwcx.` raises a
  guest Alignment exception (`0x600`) → deliver guest SIGBUS; never
  emulate the access. Same CPU encoding/semantics on 750 and e500v2
  (Book E retains both instructions) — one code path covers both profiles.

All five state-machine rules above are VERIFIED in `probe.c`
(`E06-SELFCHECK PASS`: consume-once, invalidate-then-fail, overwrite,
same-word alias `0x4002 → 0x4000` succeeds).

## 4. Implications for `src/interp` and `src/dbt`

1. `interp_step`/`dbt` emit: `lwarx` = byte-swapped (big-endian) word
   load + grant; `stwcx.` = `if (valid && alig
...[truncated 911 chars]