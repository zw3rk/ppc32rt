# Lane E05 Findings — String/Multiple/Byte-Reverse Loads (`lmw`/`stmw`, `lswi`/`stswi`, `*brx`)

Status convention: **VERIFIED** = executed in this environment (native run of
`experiments/E05/probe.c`, output below). **ANALYTICAL** = derived from
PowerPC Book I / PEM / Linux UAPI text, pending `qemu-ppc -cpu 750` /
`-cpu e500v2` confirmation (no qemu/powerpc CC in this environment).

## 1. Instruction encodings (VERIFIED: probe prints and asserts each word)

D-form `op(6)|RT(5)|RA(5)|D(16)`:

| Insn | op | Example | Encoding |
|---|---|---|---|
| `lmw` | 46 (`0x2E`) | `lmw r5,8(r6)` | `0xB8A60008` |
| `stmw` | 47 (`0x2F`) | `stmw r5,8(r6)` | `0xBCA60008` |

X-form op 31, `Rc=0`, `word = 0x7C000000|(RT<<21)|(RA<<16)|(RB<<11)|(XO<<1)`:

| Insn | XO | Example | Encoding |
|---|---|---|---|
| `lswi` | 597 | `lswi r4,r5,3` | `0x7C851CAA` |
| `stswi` | 725 | `stswi r4,r5,3` | `0x7C851DAA` |
| `lswi` NB=0 | 597 | `lswi r4,r5,0` | `0x7C8504AA` |
| `lwbrx` | 534 | `lwbrx r3,0,r4` | `0x7C60242C` |
| `lhbrx` | 790 | `lhbrx r4,r5,r6` | `0x7C85362C` |
| `sthbrx` | 918 | `sthbrx r4,r5,r6` | `0x7C85372C` |
| `stwbrx` | 662 | `stwbrx r4,r5,r6` | `0x7C85352C` |

Cross-check: `lwbrx r3,0,r4 = 0x7C60242C` matches the canonical binutils
disassembly bytes `7c 60 24 2c`. No record (`Rc=1`) forms exist for any of
these; bit 31 must be 0 (ANALYTICAL: reserved-form trap behavior is
implementation-defined, treat `Rc=1` as `EXIT_UNDEF`).

## 2. Semantics

- `lmw rD,D(rA)` / `stmw rS,D(rA)` (ANALYTICAL per Book I, model VERIFIED):
  EA is a plain D-form address (`RA==0` → `EXTS(D)`). `lmw` loads
  `rD..r31` (so `rD=0` loads all 32), each word big-endian; `stmw` stores
  `rS..r31`. Neither touches CR/XER/LR/CTR.
- `lswi rT,rA,NB` / `stswi rS,rA,NB` (ANALYTICAL, model VERIFIED):
  EA uses `rA` only (`RA==0` → 0; the RB field carries NB, not an index).
  `n = NB==0 ? 32 : NB`. Bytes run `EA..EA+n-1`, filling each register
  MSB-first (byte 0 → bits 24–31). Register index advances every 4 bytes.
  Probe confirms: `n=5` gives `r4=0x00112233`, top byte of `r5=0x44`;
  `NB=0` loads 32 bytes (`r4=0x00010203 … r11=0x1C1D1E1F` for input
  `0..31`). Neither touches CR/XER.
- `*brx` (model VERIFIED): `lwbrx` = `REV32(lwz)` (`0x00112233 → 0x33221100`);
  `lhbrx` = byte-swapped halfword in low 16 bits, high bits zeroed
  (`[00 11] → 0x00001100`); `sthbrx` stores low 16 bits reversed;
  `stwbrx` stores the full register reversed. EA = `(RA==0?0:rA)+rB`.
- Big-endian REV rule for the translator (VERIFIED as arithmetic):
  normal guest `lwz` on LE host = LE `LDR` + `REV32`; `lwbrx` = plain LE
  `LDR` with **no** swap. `*brx` must therefore bypass the standard REV
  path in both engines — the single most likely bypass bug.

## 3. Edge cases (ANALYTICAL — qemu probes named for RC-E follow-up)

1. `lmw`/`stmw` with `RA in rD..r31`, `RA!=0` → Book I *invalid form*
   (boundedly undefined); interp must pick one deterministic behavior
   (recommend: compute EA first, then execute the loop) and dbt must match
   it bit-for-bit. qemu probe: `stmw r5,0(r6)` must not corrupt `r6`.
2. `lmw`/`stmw` with `EA mod 4 != 0` → Alignment interrupt (they are not
   in the unaligned-tolerant set). qemu probe: `lmw r30,1(rX)` → expect
   SIGBUS/Alignment, not silent success.
3. `lswi`/`stswi` register wrap: Book I advances `(RT+i) mod 32`
   (model implements wrap); confirm `lswi r31,rX,5` lands byte 4 in `r0`.
4. Partial last register on `lswi` load: Book I leaves non-loaded bytes
   *undefined*; probe model preserves them. qemu probe: preset
   `r5=0xFFFFFFFF`, `lswi r4,rX,5` → record whether low 3 bytes read
   `FFFFFF` (preserve) or `000000` (zero).
5. `lswi`/`stswi` with `RA` inside the written range → invalid form, same
   handling as (1).
6. `*brx` allow unaligned EA (like `lhzx`/`lwzx`); no update/record forms.
7. `e500v2` note: SPE `evld*`/`evst*` are separate (Phase 3); classic
   `*brx`/`lmw`/`stmw`/`lswi`/`stswi` exist unchanged on `e500v2` —
   confirm identical results under both `-cpu` flags.

## 4. `sizeof`/`offsetof` (VERIFIED by probe on host C11 LP64)

SPEC §2.1 prefix mirror: `sizeof = 0x228`, `gpr_hi @ 0x80`, `nip @ 0x100`,
`acc @ 0x120`, `fpr @ 0x128`. String/multiple ops touch `gpr` only and must
never write `gpr_hi` (SPE upper halves); `*brx` likewise write only the
low word. The `evr[32]` overlay (`mc_vregs` start) corresponds to `gpr_hi`.

## 5. Implications for `src/interp` and `src/dbt`

- interp: one implementation each — word loop (`lmw`/`stmw`, BE word
  semantics), byte loop (`lswi`/`stswi`, MSB-first, NB=0→32, wrap),
  REV-of-normal (`*brx`). Multi-word/string ops spanning a page boundary
  must use the `EXIT_SINGLE_STEP` → `interp_step` fallback per SPEC §3,
  never abort. Partial-fault ordering: lowest address first.
- dbt: `lmw`/`stmw` → unrolled `LDR+REV`/`STR+REV` sequences (consider
  `LDP` pairs); `lwbrx`/`lhbrx`/`stwbrx`/`sthbrx` → plain `LDR`/`STR`
  with **no** `REV`; `lswi`/`stswi` → unrolled byte ops. Never read/write
  `x18`. `--difftest` vectors: the exact register/byte values in §2–§3
  (including the `n=0 → 32 bytes` and wrap cases) with `0` divergences.

## Sources

PowerPC Book I (integer load/store/string/byte-reverse chapters), PowerPC
PEM (`lswi`/`stswi` NB=0→32, XO table: 533 `lswx`, 534 `lwbrx`, 597 `lswi`,
661 `stswx`, 662 `stwbrx`, 725 `stswi`, 790 `lhbrx`, 918 `sthbrx`), ELF for
the PowerPC Architecture (big-endian `ELFDATA2MSB`), Linux
`arch/powerpc/include/uapi/asm/ucontext.h` (992 B `mcontext_t` context).

## Probe output (VERIFIED, native `cc`, all assertions passed)

All 10 encoding vectors `ok`; `lwz=0x00112233`, `lwbrx=0x33221100`,
`lhbrx=0x00001100`; `lmw r30..r31 = 0x00112233 0x44556677`;
`stmw` bytes `AA BB CC DD 11 22 33 44`; `lswi n=5: r4=0x00112233`;
`lswi n=0: r4=0x00010203 r11=0x1C1D1E1F`; `E05 probe: ALL OK`.
