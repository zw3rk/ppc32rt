# Phase E lane E02 — Rotate-and-mask wrap-around (`MB > ME`) & `XER.CA`

## 0. Evidence legend

- `VERIFIED (host-run)`: executed on this host (`cc`, Apple clang) — model
  self-check, `sizeof`/`offsetof`, encoding-formula outputs.
- `VERIFIED (source)`: read in the named upstream source at the stated path.
- `ANALYTICAL`: derived from Book I / PEM semantics or hand computation;
  **pending `qemu-ppc -cpu 750 / -cpu e500v2` confirmation** (no qemu or
  powerpc cross-toolchain exists on this macOS host).

Probe: `experiments/E02/probe.c` — 68/68 `PASS`, exit 0, strict flags clean:

```sh
cc -fsyntax-only -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
  experiments/E02/probe.c
```

## 1. Instruction encodings

M-form `w = (PO<<26)|(S<<21)|(A<<16)|(SH<<11)|(MB<<6)|(ME<<1)|Rc`;
XO-form `w = (31<<26)|(RT<<21)|(RA<<16)|(RB/SH<<11)|(OE<<10)|(XO<<1)|Rc`.

| Instruction (example operands) | PO/XO | Encoding (`VERIFIED (host-run)`, formula output) |
|---|---|---|
| `rlwinm r3,r4,0,0,31` | PO 21 | `0x5483003E` |
| `rlwinm r3,r4,24,24,31` | PO 21 | `0x5483C63E` |
| `rlwimi r3,r4,0,24,31` | PO 20 | `0x5083063E` |
| `rlwnm r3,r4,r5,0,31` | PO 23 | `0x5C83283E` |
| `sraw r3,r4,r5` | XO 792 | `0x7C832E30` |
| `srawi r3,r4,1` | XO 824 | `0x7C830E70` |
| `addc r3,r4,r5` | XO 10 | `0x7C642814` |
| `addze r3,r4` | XO 202 | `0x7C640194` |
| `subfc r3,r4,r5` | XO 8 | `0x7C642810` |
| `subfze r3,r4` | XO 200 | `0x7C640190` |

`ANALYTICAL` (pending `powerpc-*-objdump -d` cross-check): PO 21/20/23 and
XO 792/824/10/202/8/200 values are the standard Book I assignments; the
probe prints them from the formulae so the qemu-phase run can diff them
against the assembler byte-for-byte.

## 2. Mask generation, including `MB > ME` wrap

Rule (`VERIFIED (host-run)` on 6 spot masks, `ANALYTICAL` vs hardware):
with IBM MSB-0 bit numbers, `ml = [MB,31]`, `mh = [ME+1,31]`
(`mh = 0` when `ME = 31`, avoiding a 32-shift):

```c
x = ml ^ mh;  mask = (MB <= ME) ? x : ~x;
```

I.e. `MB<=ME` selects `[MB,ME]`; `MB>ME` selects `[MB,31]+[0,ME]` (the
complement). Verified values: `mask(0,31)=0xFFFFFFFF`,
`mask(8,31)=0x00FFFFFF`, `mask(0,0)=0x80000000`,
`mask(31,31)=0x00000001`, `mask(24,7)=0xFF0000FF` (wrap),
`mask(16,15)=0xFFFFFFFF` (wrap-full). QEMU's `trans_RLWINM`/`trans_RLWIMI`
(`VERIFIED (source)`, `target/ppc/translate/fixedpoint-impl.c.inc`) use the
same rotate-then-`MASK(mb,me)` structure, confirming the model shape.

Result semantics (`VERIFIED (host-run)`, pending qemu):

- `rlwinm`: `ROTL(rs,SH) & mask` — R1 `0x12345678->0x12345678` (identity),
  R3 `0x80000001 SH=1 ->0x00000003`, R4 byte-extract `SH=24,MB=24,ME=31`
  `->0x56`, R6 wrap-partial `MB=24,ME=7 ->0x12000078`,
  R5 wrap-full `MB=16,ME=15` identity, R8 `MB=8 ->0x00FFFFFF`.
- `rlwimi`: `(ROTL(rs,SH)&mask)|(ra&~mask)` — I1 low-byte insert
  `0xFFFFFF00+0xAB ->0xFFFFFFAB`, I2 wrap insert `->0xFF0000FF`,
  I3 zero-source clear `->0`.
- `rlwnm`: shift amount is `RB & 0x1F` — N3 `RB=0x20` behaves as shift 0
  (`0xDEADBEEF` unchanged).

## 3. `sraw` / `srawi` and `XER.CA`

Oracle rules (`VERIFIED (source)` in QEMU, the SPEC ground-truth oracle —
`helper_SRAW` in `target/ppc/int_helper.c`, `trans_SRAWI` in
`target/ppc/translate/fixedpoint-impl.c.inc`):

- `CA = 1` iff `RS` is negative **and** any dropped low bit is 1
  (`RS & ((1<<n)-1) != 0`). A negative `RS` alone is **not** enough:
  `srawi 0x80000000,1 -> 0xC0000000, CA=0` (S1), while
  `srawi 0x80000001,1 -> 0xC0000000, CA=1` (S1b). This probe initially
  hand-expected `CA=1` for S1/W1; the host run failed, the model was
  corrected to the dropped-bit rule, and all vectors now pass — recorded
  here so `interp`/`dbt` do not repeat the mistake.
- Shift count 0 **clears** CA (it is not preserved): `trans_SRAWI` emits
  `cpu_ca = 0` for `SH=0`; `helper_SRAW` sets `ca = 0` for `n=0`.
  Vectors S5/S6/W3 pin this (`CA=0` even for negative `RS`).
- `sraw` uses `n = RB & 0x3F`; `n >= 32` saturates to sign extension with
  `CA = (result != 0)`, i.e. `CA=1` iff `RS<0` (W2: `0x80000000,32 ->
  0xFFFFFFFF, CA=1`).

All sraw/srawi vectors `VERIFIED (host-run)`; hardware behavior
`ANALYTICAL` pending the qemu run in section 7.

## 4. `addc` / `addze` / `subfc` / `subfze` carry propagation

(`VERIFIED (host-run)`; `ANALYTICAL` pending qemu.)

- `addc`: 64-bit sum, `CA = sum>>32`. A1 `0xFFFFFFFF+1 -> 0, CA=1`;
  A2 `0x7FFFFFFF+1 -> 0x80000000, CA=0`.
- `addze`: `rd = RA + CA`. A3 `5+1 -> 6, CA=0`;
  A4 `0xFFFFFFFF+1 -> 0, CA=1`. (QEMU: `do_add_const_XO(0,...)` —
  `VERIFIED (source)` — confirms the `+CA` shape.)
- `subfc rD,rA,rB`: `rd = RB-RA`, `CA = (RB>=RA)` (1 = no borrow).
  A5 `5-3 -> 2, CA=1`; A6 `3-5 -> 0xFFFFFFFE, CA=0`;
  A7 `0-0 -> 0, CA=1`.
- `subfze rD,rA`: `rd = ~RA + CA`. A8 `~0+1 -> 0, CA=1`;
  A9 `~5+1 -> 0xFFFFFFFB, CA=0`; A10 `~0+0 -> 0xFFFFFFFF, CA=0`.

`OE=0` in all probe encodings, so `XER.OV/SO` are untouched by these forms.

## 5. `Rc=1` CR0 update

`CR0 = [LT,GT,EQ,SO<-XER.SO]` with `LT=0x80000000, GT=0x40000000,`
`EQ=0x20000000, SO=0x10000000` (`VERIFIED (host-run)`):
C1 `rd=0 -> 0x20000000`, C2 `rd=0x80000000 -> 0x80000000`,
C3 `rd=1 -> 0x40000000`, C4 `rd=0,XER.SO=1 -> 0x30000000`.
QEMU applies `gen_set_Rc0` after each `Rc` form (`VERIFIED (source)`),
so `interp`/`dbt` must update CR0 for every `Rc=1` rotate/shift/add/subf
variant, copying the pre-instruction `XER.SO`.

## 6. `XER` / `CR` / SPR bit positions (cross-corroborated)

| Item | Value | Source |
|---|---|---|
| `XER.SO / OV / CA` | `0x80000000 / 0x40000000 / 0x20000000` | `VERIFIED (source)`: QEMU `target/ppc/cpu.h` (`XER_SO=31, XER_OV=30, XER_CA=29`, LSB-0 shifts); Linux `arch/powerpc/include/asm/reg.h` (`SPRN_XER 0x001`) |
| `CR0.SO` | `0x10000000` | SPEC section 2.3 (matches CR0 bit-3 placement) |
| SPR numbers LR/CTR/XER | `8 / 9 / 1` | SPEC section 2.2; Linux `SPRN_XER 0x001` corroborates XER |

## 7. `sizeof` / `offsetof` (`VERIFIED (host-run)`)

Probe carrier `struct e02_xer_state { uint32_t xer, cr, nip; }`:
`sizeof = 12`, offsets `xer=0, cr=4, nip=8`. All-`uint32_t` layout, so the
values are ABI-stable for the powerpc target (`ANALYTICAL` for target
equality, zero-risk: no pointers, no `long`).

## 8. Implications for `src/interp` and `src/dbt`

1. Share one `ppc_mask32(mb, me)` helper (`~x` on wrap) between decoder,
   `interp` rotate/mask executors, and the A64 emitter; unit-test it with
   the section 2 spot masks.
2. Thread a single-bit `CA` through `addc/addze/subfc/subfze` (`adde` later);
   never derive it from the 32-bit result alone.
3. `sraw[i]` CA needs the dropped-bits test, not the sign bit; explicit
   `n==0 -> CA=0` and `n>=32` saturation paths (no shared "shift" helper
   that forgets them).
4. Every `Rc=1` form updates CR0 from result sign/zero plus live `XER.SO`.
5. `dbt` lowering hint (from QEMU's translators): `rlwinm` with `ME=31`
   and `rsh+len<=32` is an extract; `SH=(31-ME), MB<=ME` is a deposit —
   same fast paths apply to the A64 emitter. Emitter must never use `x18`.

## 9. Pending qemu-ppc confirmation (Phase E gate)

```sh
powerpc-linux-gnu-gcc -static -o /w/_build/e02probe \
  /w/experiments/E02/probe.c
timeout --kill-after=30s 60s docker run --rm --platform linux/arm64 \
  -v "$PWD:/w" -w /w alpine \
  sh -c 'qemu-ppc -cpu 750 /w/_build/e02probe && qemu-ppc -cpu e500v2 /w/_build/e02probe'
powerpc-linux-gnu-objdump -d /w/_build/e02probe | grep -E 'rlwinm|sraw|addc|subfc'
```

Expected: exit 0 on both CPUs (all 68 vectors incl. S5/S6/W3 zero-shift
CA clearing), and objdump bytes matching the section 1 encodings.
