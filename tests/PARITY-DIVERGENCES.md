# Parity divergences blocking `tests/parity_suite.sh` (Wave C1, lane C1-3)

Status: the Tier S gate is implemented at `tests/parity_suite.sh` but
held uncommitted: it fails closed on the divergence below (21 PASS,
2 FAIL, 0 GAP, stable across runs). This record is the escalation to
the DBT-owning lane; the fix lives in `src/dbt/` (outside lane C1-3
file ownership), not in `tests/`.

## D1 — DBT `evsubfw` computes the wrong word (SPE profile)

- Guest: `tests/test_p3_fp_spe.c`, sites 42-43 (`evsubfw 16,14,15`
  with `vecA={10,3}`, `vecB={4,1}` loaded by `evldd`).
- ISA + oracle ground truth: `evsubfw` is subtract-from, `d = B - A`,
  so the high word must be `4 - 10 = -6 = 0xFFFFFFFA`.
- Observed under `--profile spe --dbt` (host and Linux backends):
  `FAIL id=0000002a got=000000fa want=fffffffa` (exit 1).
  `0xFA` is the low byte of the correct word, zero-extended: the
  upper 24 bits are dropped.
- Control legs, all PASS: `qemu-ppc -cpu e500v2` oracle,
  `--profile spe --interp`, every `--profile classic` leg
  (`--interp`, `--dbt`, `--difftest`), and `--profile classic`
  `--difftest` (`DIFFTEST: EQUAL`). The SPE `--difftest` leg fails
  because it locksteps the same broken DBT path against interp.
- Root cause (decoded from the failing values, not fixed here):
  `src/dbt/emit_fp.c`, `sv_base[]` integer entries `0x0E208400`
  (ADD) / `0x2E208400` (SUB) carry `size = 00` (bits 23:22) with Q = 0,
  i.e. an 8-byte arrangement, not `.2S`. The SUB operand order is
  right (`SUB v0,v1,v0` = B − A) but the width is wrong: per-byte
  `0x04 − 0x0A = 0xFA` in lane 0 reproduces the observed
  `got=0x000000fa` exactly. Fix is to set `size = 10` (OR `2U << 22`)
  on the ADD/SUB entries. `evaddw` is masked, not healthy: small
  lane values make 8B ADD numerically equal to word ADD, so it passes
  by luck. AND/OR/XOR survive legitimately (bitwise, size-agnostic);
  TRN1/TRN2 entries (`0x0EA01C00`/`0x0E802800`) share the 8B
  arrangement and are suspect for word transpose; both EXT entries
  emit no index immediate and are untested (guest aborts at site 42).
  All of this is `src/dbt/` work for the DBT-owning lane.

Reproduction (from the repo root):

```sh
powerpc-linux-gnu-gcc -std=c11 -Wall -Wextra -ffreestanding -static \
    -nostdlib -O2 -fno-pie -no-pie -fno-stack-protector \
    tests/test_p3_fp_spe.c -o _build/parity/p3_both
qemu-ppc -cpu e500v2 _build/parity/p3_both          # PASS, exit 0
./_build/ppc32rt-darwin --profile spe --interp -- _build/parity/p3_both  # PASS
./_build/ppc32rt-darwin --profile spe --dbt -- _build/parity/p3_both     # FAIL site 42
```

No `tests/`-side resolution exists: the guest asserts ISA semantics
that qemu and the interpreter both satisfy, and no flag, profile, or
build knob changes emitter arithmetic. Landing condition for
`tests/parity_suite.sh`: the two `ppc32-spe` `--dbt`/`--difftest`
rows go green with no other row changing.
