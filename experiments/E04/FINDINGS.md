# Lane E04 Findings — PPC32 `ucontext`/`mcontext` (992 B) & SPE `evr` Overlay

## Sources (VERIFIED: fetched kernel UAPI text this session)

- `arch/powerpc/include/uapi/asm/ucontext.h` — `struct mcontext`
  (`mc_gregs`, `mc_fregs`, `mc_pad[2]`, `mc_vregs` aligned(16)) and
  `struct ucontext` (`uc_flags`, `uc_link`, `uc_stack`, `uc_pad[7]`,
  `uc_regs`, `uc_sigmask`, `uc_maskext[30]`, `uc_pad2[3]`, `uc_mcontext`).
- `arch/powerpc/include/uapi/asm/elf.h` — `ELF_NGREG 48`, `ELF_NFPREG 33`,
  `ELF_NVRREG 33`, `ELF_NEVRREG 34 /* includes acc (as 2) */`,
  `elf_gregset_t = unsigned int[48]`, `elf_fpregset_t = double[33]`,
  `elf_vrregset_t = 16-byte unit[33]`, `ELF_ARCH EM_PPC`,
  `ELF_CLASS ELFCLASS32`.
- `arch/powerpc/include/uapi/asm/ptrace.h` — `PT_R0..PT_R31`,
  `PT_NIP 32`, `PT_MSR 33`, `PT_ORIG_R3 34`, `PT_CTR 35`, `PT_LNK 36`,
  `PT_XER 37`, `PT_CCR 38`, `PT_MQ 39`, `PT_TRAP 40`, `PT_DAR 41`,
  `PT_DSISR 42`, `PT_RESULT 43`, `PT_DSCR 44`.
- `arch/powerpc/include/uapi/asm/stat.h` — `struct stat64` member list
  (ppc32, "matches struct stat64 in glibc2.1").

## Findings

### 1. `mcontext_t` is exactly 992 bytes (VERIFIED: UAPI text + native probe run)

| Field | Offset | Size | Type |
|---|---|---|---|
| `mc_gregs[48]` | `0x0` | 192 B | `unsigned int[48]` |
| `mc_fregs[33]` | `0xc0` | 264 B | `double[33]` (`f0..f31` + `fpscr`) |
| `mc_pad[2]` | `0x1c8` | 8 B | padding aligning `mc_vregs` to 16 B |
| `mc_vregs[528]` | `0x1d0` | 528 B | `16 B x 33`, `aligned(16)` |

Arithmetic: `192 + 264 + 8 + 528 = 992 = 0x3e0`. `0x1c8 + 8 = 0x1d0`,
and `0x1d0 mod 16 = 0`, so the pad is exactly what the 16-byte
alignment needs — no hidden tail padding. The probe's replica struct
(`_Alignas(16)` on `mc_vregs`, `_Static_assert`-style runtime checks)
prints `sizeof = 0x3E0` and all four offsets exactly; native run reports
`E04 probe: ALL OK` (VERIFIED: executed on host; the arithmetic is
target-independent, but the claim that a powerpc cross-compiler lays the
replica out identically is ANALYTICAL pending `powerpc-unknown-linux-gnu`
execution under `qemu-ppc -cpu 750 / -cpu e500v2`).

### 2. `mc_gregs` index map (VERIFIED: `ptrace.h` `PT_*` values)

`r0..r31` = words `0..31`; `nip 32`, `msr 33`, `orig_r3 34`, `ctr 35`,
`link 36`, `xer 37`, `ccr (= CR) 38`, `mq 39`, `trap 40`, `dar 41`,
`dsisr 42`, `result 43`, `dscr 44`; words `45..47` reserved (covered by
`ELF_NGREG 48` but unnamed on 32-bit). `orig_r3` restarts syscalls;
`result` carries the syscall return. `PT_FPR0 48` confirms FP state lives
outside `mc_gregs` (in `mc_fregs`).

### 3. SPE overlay at `mc_vregs` start (ANALYTICAL, consistent with VERIFIED `ELF_NEVRREG`)

On e500v2 (`CONFIG_SPE`), Linux reuses the 528 B `mc_vregs` area:

| Overlay field | `mc_vregs` offset | Size | 32-bit word index |
|---|---|---|---|
| `evr[32]` (= `gpr_hi[0..31]`) | `+0` | 128 B | words `0..31` |
| `acc` (64-bit) | `+128` | 8 B | words `32..33` ("acc as 2") |
| `spefscr` | `+136` | 4 B | word `34` |

`128 + 8 + 4 = 140` payload (`sizeof` = 144 with the `acc`-imposed
8-alignment tail pad; probe asserts 144), `<= 528`; `32 + 2 = 34 =
ELF_NEVRREG`, i.e. the overlay occupies exactly the 34-word SPE regset
plus `spefscr`. Edge cases (ANALYTICAL, need qemu): the kernel only
fills/restores the overlay when the task used SPE (`used_spe`); classic
750 kernels leave `mc_vregs` zero unless Altivec state is present, so a
translator must not assume nonzero `mc_vregs` on 750, and must not let a
stale overlay leak across `sigreturn` on profile switch. `acc` is
little-word-order-sensitive under the big-endian guest: word 32 is the
high half (ANALYTICAL).

### 4. `struct stat64` is 104 bytes (VERIFIED source text; offsets ANALYTICAL-derived, probe-checked)

`st_dev@0x0`, `st_ino@0x8` (both u64); `st_mode@0x10`, `st_nlink@0x14`,
`st_uid@0x18`, `st_gid@0x1c`; `st_rdev@0x20` (u64); `__pad2@0x28`
(implies 8-byte alignment of following 64-bit members); `st_size@0x30`;
`st_blksize@0x38`; `st_blocks@0x40`; `st_atime@0x48`,
`st_mtime@0x50`, `st_ctime@0x58` each followed by a `_nsec` u32;
`__unused4@0x60`, `__unused5@0x64`; `sizeof = 104 = 0x68`. Probe prints
every offset and `sizeof = 0x68`: ALL OK natively. The 8-byte alignment
assumption for `long long`/`double` on PPC32 SysV (which the `__pad2`
field corroborates) still needs a powerpc-target compile to confirm.

### 5. `struct ucontext` wrapper (ANALYTICAL, derived from VERIFIED header)

`uc_flags(4) + uc_link(4) + uc_stack(12: sp/flags/size) + uc_pad[7](28)
+ uc_regs ptr(4) = 52`; `uc_sigmask` is 8 B (64-bit kernel mask, not the
glibc 1024-bit one); `uc_maskext[30](120) + uc_pad2[3](12)`; `52 + 8 +
120 + 12 = 192 = 0x
...[truncated 1587 chars]