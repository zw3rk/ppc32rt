# E03 Findings — `.gnu.attributes` Parsing & Classic-FPU vs `e500v2` SPE Dispatch

Status labels: **VERIFIED** = executed in this environment (host `cc`
syntax check + native run of `probe.c` on synthetic vectors; binutils
sources fetched and grepped). **ANALYTICAL** = grounded in the cited
sources but pending `qemu-ppc -cpu 750 / -cpu e500v2` confirmation
(no qemu or powerpc cross-toolchain on this macOS host).

## 1. ELF admission (VERIFIED against binutils `include/elf/common.h`)

- `EM_PPC = 20` (`EM_PPC_OLD = 17` deprecated, `EM_PPC64 = 21`).
  `ppc32rt` admits only `e_machine == 20`.
- `ELFCLASS32 = 1`, `ELFDATA2MSB = 2` (big-endian). Every
  16/32/64-bit guest load/store in `interp`/`dbt` must byte-swap
  (`REV16`/`REV`/`REV64`); the `.gnu.attributes` subsection length
  word and all instruction words are read big-endian.
- Attribute section type `SHT_GNU_ATTRIBUTES = 0x6ffffff5`, name
  `.gnu.attributes`, vendor string `gnu`, file-scope subsection tag
  `Tag_File = 1`, attributes as ULEB128 `(tag, value)` pairs.

## 2. Tag numbers and values (VERIFIED against `include/elf/ppc.h`,
## `binutils/readelf.c`, assembler docs)

- `Tag_GNU_Power_ABI_FP = 4`: low 2 bits `0` = unspecified,
  `1` = double-precision hard float (**classic 750**), `2` = soft
  float, `3` = single-precision hard float (**e500v2 SPE**).
  Bits 3:2 encode the long-double flavor (`0/4/8/12` =
  unspecified / 128-bit IBM / 64-bit / 128-bit IEEE) — mask with
  `val & 3` for the FP decision, as `readelf` does.
- `Tag_GNU_Power_ABI_Vector = 8`: `0` = unspecified, `1` = generic
  (GPRs), `2` = AltiVec, `3` = SPE registers (**e500v2**).
- `Tag_GNU_Power_ABI_Struct_Return = 12`: `1` = r3/r4 small-struct
  return, `2` = memory; parse-and-ignore for dispatch (record for
  future ABI work).

Profile decision table (`--profile classic|speak`, `PPC32RT_PROFILE`):

| FP tag | Vector tag | resolved profile |
|---|---|---|
| 1 (hard) | 0/1/2 | `classic` |
| 3 (single-hard) | 3 (SPE) | `spe` |
| 2 (soft) | any | `classic` (soft-float library calls; no FPU/SPE state) |
| missing section | — | `classic`, unless an SPE word is decoded (fallback) or CLI overrides |

Precedence: CLI `--profile` > attribute pair > SPE-opcode presence
> default `classic`. Conflicting signals (e.g. FP=1 with SPE
opcodes present) resolve to `spe` with a warning: real e500v2
binaries can carry FP=1 objects linked in; the opcode stream is
authoritative at run time. (ANALYTICAL: pending qemu check of what
GCC `-mcpu=8548 -mspe` actually emits — expected FP=3/Vector=3.)

## 3. Dispatch encodings (VERIFIED: probe decodes these exact words)

Primary opcode = `w >> 26`. Bit layout macros from
`opcodes/ppc-opc.c`: `OP(op) = op<<26`,
`VX(op,xop) = OP(op)|(xop&0x7ff)` (11-bit XO = PPC bits 21–31; the
low bit is the Rc slot for arithmetic forms),
`A(op,xop,rc)` classic A-form (5-bit XO at value bits 1–5).

| mnemonic | word (rD/rA/rB = 0/0/0 shape) | primary | XO (`w&0x7ff`) | class |
|---|---|---|---|---|
| `evaddw` | `0x10000200` | 4 | 512 | SPE vector int |
| `evand` | `0x10000211` | 4 | 529 | SPE vector logical |
| `evmergehi/lo` | `0x1000022c/0x22d` | 4 | 556/557 | SPE merge |
| `evfsadd` | `0x10000280` | 4 | 640 | SPE vector float |
| `efsadd/sub` | `0x100002c0` | 4 | 704/705 | SPE scalar single |
| `efsabs` | `0x100002c4` | 4 | 708 | SPE scalar single |
| `efdadd/sub` | `0x100002e0` | 4 | 736/737 | SPE scalar double |
| `efdabs` | `0x100002e4` | 4 | 740 | SPE scalar double |
| `evldd` | `0x10000301` | 4 | 769 (Rc-slot=1) | SPE 64-bit load |
| `evstdd` | `0x10000321` | 4 | 801 (Rc-slot=1) | SPE 64-bit store |
| `fadd` | `0xfc22182a` (r1,r2,r3) | 63 | A-form | classic double |
| `fadds` | primary 59 | 59 | A-form | classic single |
| `lfs/lfd/stfs/stfd` | primaries 48/50/52/54 | — | D-form | classic FP ld/st |
| `sc` | `0x44000002` | 17 | — | syscall, not FP/SPE |

Probe run (native, synthetic vectors — VERIFIED):

```text
word evaddw: 0x10000200 primary=4 sub=512 -> SPE:evaddw
word efsadd: 0x100002c0 primary=4 sub=704 -> SPE:efsadd
word efdadd: 0x100002e0 primary=4 sub=736 -> SPE:efdadd
word evldd: 0x10000301 primary=4 sub=769 -> SPE:evldd
word fadd: 0xfc22182a primary=63 sub=42 -> CLASSIC-FPU-arith
word sc: 0x44000002 primary=17 sub=2 -> sc
```

Structural rule: primary opcode `4` is **never** a classic-750
instruction (reserved/illegal on 750) and **never** overlaps classic
FPU primaries `59/63` or FP load/store primaries `48/50/52/54`, so
the first-level demux is a single 6-bit compare. Second level masks
`w & 0x7ff` (full 11-bit XO incl. Rc slot); load/store XO values
`769/801` have the low bit set and must be matched exactly, not
masked to 10 bits. (ANALYTICAL: `qemu-ppc -cpu 750` must SIGILL
primary-4 words and `-cpu e500v2` must execute them; `qemu-ppc -cpu
750` must SIGILL `efs*`/`efd*` while e500v2 executes — pending.)

## 4. `gpr_hi[32]` upper-word discipline (VERIFIED in probe model)

- `S
...[truncated 2085 chars]