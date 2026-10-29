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
- Suspect path (not verified by edit): `src/dbt/emit_fp.c`,
  `spe_scalar()`, `prec == 3U`, `SV_SUB` branch — the only op that
  clears bit 16 and sets `(1U << 5) | 0U` instead of the common
  `(1U << 16) | 0U` encoding. Site 42 is the first SPE vector-integer
  op in the guest, so every vector `evsubfw` under `--dbt` is suspect.

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
