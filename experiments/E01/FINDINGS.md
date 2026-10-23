# Phase E lane E01 findings — PPC32 `sc`, CR0.SO error flag, 64-bit pairs

## 1. Verdict ledger (claim → status → source)

| # | Claim | Status | Grounding |
|---|---|---|---|
| 1 | `sc` encoding is `0x44000002`, primary opcode 17 | VERIFIED (decode) / ANALYTICAL (ISA text) | Host-executed decode: `po=17 suffix=2 LEV=0` (`/tmp/e01probe` output + independent python3 re-decode agree); semantic name per Power ISA opcode map and SPEC 2.3 |
| 2 | Syscall nr in `r0`, args in `r3..r8` | VERIFIED | Linux `arch/powerpc/include/uapi/asm/ptrace.h`: `PT_R0..PT_R8`, `struct pt_regs{gpr[32],...}` (fetched upstream master) |
| 3 | Success: `CR0.SO=0`, `r3=ret` | VERIFIED | Linux `arch/powerpc/kernel/interrupt.c`, `syscall_exit_prepare` (fetched upstream master, quoted below) |
| 4 | Error: `CR0.SO=1`, `r3=+errno` | VERIFIED | Same function: `r3 = -r3; regs->ccr \|= 0x10000000; /* Set SO bit in CR */`; linuxppc-dev: "When cr0.SO is set, the syscall failed and r3 is the error value … strace relies on this ABI" |
| 5 | `CR0.SO` mask `0x10000000` (word bit 3) | VERIFIED | Same kernel line (`ccr` holds the CR image, CR0 in top nibble); host `_Static_assert` + runtime print `cr0_so=0x10000000` |
| 6 | 64-bit args high word first | VERIFIED | Linux `arch/powerpc/kernel/syscalls.c`: `SYSCALL_DEFINE6(ppc_fadvise64_64, fd, advice, offset_high, offset_low, len_high, len_low)` + `merge_64(high, low)` (fetched upstream master) |
| 7 | 64-bit args require even-aligned (padded) register pairs | OPEN — kernel evidence leans NO padding for `sc` | Same wrapper places `offset_high` in `r5` (odd start); see §5. Decisive qemu test specified but NOT yet run (no powerpc toolchain / qemu-ppc on this host) |
| 8 | Raw-`sc` register values under `qemu-ppc -cpu 750 / -cpu e500v2` | PENDING | `probe.c` target path written (`#ifdef __powerpc__`); no machine run in this environment |
| 9 | `ctx` offsets: `gpr[3]` at `0x00c`, `cr` at `0x10c` | VERIFIED (arithmetic) | `offsetof` `_Static_assert`s + runtime print; layout per SPEC 2.1 |

## 2. Instruction encoding

`sc` = `0x44000002` = `010001 00000 00000 0000000000000 1 0`:

- bits 0:5 = 17, the primary opcode shared with the trap/syscall class;
- bits 6:29 = 0 (`LEV` field 0, the Linux `sc 0` form);
- bits 30:31 = `10b` (the fixed `sc` suffix; the sibling `scv` form differs here).

Machine-checked on host: C `_Static_assert((0x44000002u >> 26) == 17)` and
`(0x44000002u & 3u) == 2`, plus runtime print `sc=0x44000002 po=17 suffix=2`
and an independent python3 bit-decode (`po=17 suffix=2 lev=0x0`). The probe
issues the trap with `.long 0x44000002` so the target run pins the opcode
rather than trusting the cross-assembler mnemonic.

## 3. Register and flag behaviour

Kernel return path (`arch/powerpc/kernel/interrupt.c`, upstream master):

```c
if (unlikely(r3 >= (unsigned long)-MAX_ERRNO) && is_not_scv) {
        if (likely(!(ti_flags & (_TIF_NOERROR | _TIF_RESTOREALL)))) {
                r3 = -r3;
                regs->ccr |= 0x10000000; /* Set SO bit in CR */
        }
}
...
regs->gpr[3] = r3;
```

Consequences:

- Success: `CR0.SO=0`, `r3` = return value (any `uint32_t`, including values
  1..4095 — e.g. `read` returning 38 is data, error `ENOSYS` is also 38;
  only the SO bit disambiguates; probe vectors `success-nread` vs
  `err-enosys` pin this).
- Error: kernel-internal `r3` in `[-4095, -1]` → user `r3 = -r3` in
  `[1, 4095]` = `+errno`, `CR0.SO=1`.
- Boundary: `-4096` (`0xfffff000`) is outside `[-MAX_ERRNO, -1]` and is
  returned as-is with `SO=0` (probe vector `neg-beyond`). The emulator must
  key on the CR bit (equivalently the pre-negation range test), never on
  the magnitude of user `r3` alone.
- `scv` (`is_not_scv` gate) uses a different (non-negating) convention;
  ppc32 guests use `sc`, so `interp`/`dbt` implement the `sc` rule above.
- The kernel ORs SO into the saved `ccr`; the emulator owns `ctx->cr`, so
  per SPEC 2.3 it must explicitly clear (`ctx->cr &= ~0x10000000U`) on
  success and set-or (`ctx->cr |= 0x10000000U`) plus `r3 = (uint32_t)(-ret)`
  on error.

Reference implementation for `src/interp` (and the `dbt` syscall stub):

```c
if (kret < 0 && kret >= -4095) {
    ctx->gpr[3] = (uint32_t)(-kret);
    ctx->cr |= 0x10000000u;   /* CR0.SO = 1 */
} else {
    ctx->gpr[3] = (uint32_t)kret;
    ctx->cr &= ~0x10000000u;  /* CR0.SO = 0 */
}
```

## 4. Byte offsets

- `ppc32_ctx_t` (SPEC 2.1, machine-checked mirror in `probe.c`):
  `gpr[3]` at `0x00c`, `gpr_hi` base `0x080`, `nip` `0x100`, `lr` `0x104`,
  `ctr` `0x108`, `cr` `0x10c`.
- Kernel `struct pt_regs` UAPI (`ptrace.h`): `gpr[0..31]` indices `PT_R0..31`
  = 0..31, `PT_NIP=32`, `PT_CCR=38`, `PT_RESULT=43`. Note `ccr` is a full
  `unsigned long` whose low 32 bits carry CR0 in the top nibble on ppc32.

## 5. 64-bit pair placement — order settled, padding OPEN

Settled (VERIFIED from kernel source): consecutive registers, high word
first — `ppc_fadvise64_64(fd, advice, offset_high, offset_low, len_high,
len_low)` calls `merge_64(offset_high, offset_low)`. The probe's
`e01_merge_64(1, 2) == 0x100000002` vector pins the shift direction.

Open: the SPEC phrase "aligned register pairs" could imply even-alignment
with padding when a 64-bit arg would start on an odd register. The fetched
kernel wrapper contradicts strict padding: its six C args map to `r3..r8`
in order, so `offset_high` lands in `r5` (odd start). That suggests the
`sc` convention is consecutive-pair, high-first, with NO padding — unlike
the SVR4 stack-parameter ABI. Do NOT implement padding on this evidence
alone.

Decisive qemu experiments (written into `probe.c`, pending toolchain):

1. Order: raw `sc` `_llseek` (nr 140) on a small temp file with
   `(hi=0, lo=8)` must return 8 with `SO=0`; swapped `(hi=8, lo=0)`
   must fail (`SO=1`) — distinguishes word order functionally.
2. Odd-start: raw `sc` `fallocate`-family or `fadvise64_64`-family call
   with the 64-bit value at an odd-start pair, checking the kernel reads
   the consecutive (unpadded) registers; cross-check with
   `qemu-ppc -strace` / gdbstub register capture.
3. Error flag: raw `sc` with bogus nr must yield `r3=38` (`ENOSYS`) with
   `SO=1`; raw `sc` getpid (nr 20) must yield `r3=pid` with `SO=0`
   (both coded in `e01_target_probes()`).

Run on both `-cpu 750` and `-cpu e500v2`; the convention is OS-level so no
CPU difference is expected, but RC-E requires both.

## 6. Edge cases for `src/interp` / `src/dbt`

- Never infer error from `r3` magnitude; always test `ctx->cr & 0x10000000`.
- `r0` (nr) and the arg registers `r3..r8` are inputs; only `r3` (+`cr`)
  are defined outputs — `dbt` stubs must not assume other regs preserved.
- `_TIF_NOERROR`/`_TIF_RESTOREALL` threads skip negation in the kernel;
  normal guest paths always see the §3 rule; tracer-faithful paths note it.
- Syscall restart uses saved `orig_gpr3`/`ccr`, not the clobbered `r3` —
  relevant to Phase 4 signal work, not to the return-value path itself.

## 7. Analytical vs verified note

VERIFIED in this environment: items 1–6 and 9 of the ledger (upstream
kernel/UAPI sources fetched and quoted; opcode/offset/return-model checks
compiled under `-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror` and
executed on host with `RESULT: PASS`; bit-decode corroborated by an
independent python3 computation). ANALYTICAL (pending `qemu-ppc` with a
PowerPC cross-toolchain, unavailable on this macOS host): item 8, the
even-alignment padding question in item 7, and any behavioural difference
between `-cpu 750` and `-cpu e500v2`. The probe's `__powerpc__` path is
written so the coordinator (or a follow-up lane with the toolchain) can
promote these to VERIFIED by running `sh experiments/E01/run.sh`.
