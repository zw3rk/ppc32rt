# Phase 5 Sysroot Record — Dynamic `libc`, Loader & `BusyBox` (Lane L5b)

Scope: exact toolchain provenance for the Phase 5 dynamic lane, every
syscall met during `ld.so`/`libc` startup that `ppc32rt` does not
implement (lane L5b does NOT implement them — escalated below with
numbers and observed behavior), and residual gaps for RC5/the
Coordinator. All container observations below were made in fresh
`--platform linux/arm64` `debian:stable-slim` containers (lane
containers named `ppc32rt-l5b-<pid>`, removed on exit; every step
bounded with `timeout --kill-after=30s`).

## 1. Toolchain provenance

| Component | Version / path |
|---|---|
| Base image | `debian:stable-slim` (`--platform linux/arm64`) |
| `gcc-powerpc-linux-gnu` | `4:14.2.0-1` (gcc `14.2.0-19cross1`, binutils `2.44-3`) |
| `libc6-powerpc-cross` / `libc6-dev-powerpc-cross` | `2.41-11cross1` (glibc `2.41`) |
| `qemu-user` | `1:10.0.13+ds-0+deb13u1` (`qemu-ppc` `10.0.13`) |
| Guest sysroot | `/usr/powerpc-linux-gnu` |
| Loader | `/lib/ld.so.1` (guest-absolute; sysroot file `lib/ld.so.1`, 264968 B, regular file, not a symlink) |
| `libc.so.6` | sysroot `lib/libc.so.6`, 2302588 B |
| Fixture interp | `test_p5_dyn`: `ELF 32-bit MSB executable, PowerPC, dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 3.2.0` |
| Companion | `test_p5_dynlib.so`: `ELF 32-bit MSB shared object, PowerPC` |

Loader default search dirs baked into this `ld.so.1` (via `strings`):
`/lib/`, `/lib/powerpc-linux-gnu/`, `/usr`, `/usr/lib/`,
`/usr/lib/powerpc-linux-gnu/`. No `etc/ld.so.cache` is shipped inside
the sysroot; with `-L /usr/powerpc-linux-gnu` the oracle falls back to
the container host root for sysroot-missing paths (observed: guest
`/etc/ld.so.cache` resolves to the host arm64 cache, and guest
`/lib/powerpc-linux-gnu/` resolves when the host root has it — the
oracle is therefore not a pure sysroot view).

Oracle form: `qemu-ppc -cpu {750,e500v2} -L /usr/powerpc-linux-gnu`.
Translator form (once plumbed): `PPC32RT_SYSROOT=/usr/powerpc-linux-gnu
ppc32rt --{interp,dbt} -- ./test_p5_dyn`.

## 2. Dynamic fixture — oracle results

Build (Debian container, from the worktree root):

```sh
powerpc-linux-gnu-gcc -O2 -fPIC -shared tests/test_p5_dynlib.c \
    -o _build/test_p5_dynlib.so
powerpc-linux-gnu-gcc -O2 -no-pie tests/test_p5_dyn.c \
    -o _build/test_p5_dyn -ldl
```

(`-no-pie` keeps the app entry at its link address so the
`getauxval(AT_ENTRY) == &_start` self-check is exact.)

- `-cpu 750`: exit `0`, stdout byte-identical on repeat runs:

  ```text
  p5 dyn printf: 42 ok ff
  p5 dyn qsort ok
  p5 dyn dlopen ok
  p5 dyn tls ok
  p5 dyn auxv ok
  PASS
  ```

- `-cpu e500v2` (and `-cpu e500`): the GUEST takes `SIGILL`
  (`exit=132`, `qemu: uncaught target signal 4 (Illegal instruction)`).
  The fault is a classic double-precision store in `ld.so`
  (`stfd f14,0x58(r3)` at `NIP 0x40835f2c`), illegal on Book-E cores.
  The STATIC `test_p2_libc` build SIGILLs identically, so no Debian
  powerpc userspace runs under qemu's `e500`/`e500v2` models at all.
  Classic cores `750/7400/7450/G3/G4/603/604` all print `PASS`.
  This is ESCALATION E1 (oracle contradicts the lane doc, §6).

Full `ld.so`/`libc` startup inventory (oracle `-cpu 750 -strace`,
syscall numbers are PPC `asm/unistd_32.h` from this sysroot):

`brk(45)`, `mmap2(192)`, `access(33)`, `openat(286)`, `statx(383)`,
`read(3)`, `close(6)`, `munmap(91)`, `mprotect(125)`,
`set_tid_address(232)`, `set_robust_list(300)` → `ENOSYS` (tolerated),
`rseq(387)` → `ENOSYS` (tolerated), `ugetrlimit(190)`, `getrandom(359)`,
`getcwd(182)` (for the relative-path `dlopen`), `write(4)`,
`exit_group(234)`.

## 3. Dynamic fixture — translator results

- Pristine (`PPC32RT_SYSROOT=/usr/powerpc-linux-gnu` exported):

  ```text
  ppc32rt: cannot open interpreter '/lib/ld.so.1': No such file or directory
  ```

  `ctx->sysroot` is never populated (`main.c` reads no such variable
  and offers no `--sysroot` flag), so `ppc32_open_guest_ro` falls back
  to the host root. This is ESCALATION E2 (frozen plumbing, §6).

- With container-local compat hacks ONLY (symlink
  `/lib/ld.so.1 -> /usr/powerpc-linux-gnu/lib/ld.so.1`,
  `LD_LIBRARY_PATH=/usr/powerpc-linux-gnu/lib`, no repo changes),
  `--interp` and `--dbt` both fail identically with:

  ```text
  ./test_p5_dyn: error while loading shared libraries: libc.so.6: cannot stat shared object: Error 38
  ```

  (`Error 38` is `ENOSYS`: `statx` is the first fatal gap.)
  `--difftest` reports `DIFFTEST: EQUAL exit=127` — both engines agree,
  but vacuously (the guest never starts). First-fault isolation past
  `statx` is impossible from outside: `--trace` is parsed but no guest
  syscall tracer exists (residual gap G3).

## 4. Missing-syscall escalation list (do NOT implement in-lane)

Numbers are PPC (`asm/unistd_32.h`, verified in this sysroot);
“impl?” is the state of `src/os/syscalls.c` on branch `lane/p5-l5b`.

| nr | name | met by | observed behavior | impl? |
|---|---|---|---|---|
| 383 | `statx` | `ld.so`+`libc` startup, every shared-object load | FATAL: `cannot stat shared object: Error 38` | no |
| 33 | `access` | preload check | tolerated (`ENOENT`-equivalent path) | defined, undispatched |
| 190 | `ugetrlimit` | startup (stack-guard sizing) | unreached (blocked behind `statx`) | no |
| 76 | `getrlimit` | — (not called here; `ugetrlimit` used) | unreached | defined, undispatched |
| 182 | `getcwd` | `dlopen("./test_p5_dynlib.so")` | fatal for slash-relative `dlopen` (test also tries a bare-soname `dlopen`, which needs only `LD_LIBRARY_PATH`) | no |
| 300 | `set_robust_list` | startup | `ENOSYS`, tolerated by glibc (single-threaded) | no |
| 387 | `rseq` | startup | `ENOSYS`, tolerated by glibc | no |
| 202 | `getdents64` | BusyBox `ls` applet (direct form) | fatal for `ls` (translator: `ls: Function not implemented`) | no |
| 317 | `pipe2` | BusyBox `sh` pipeline (`echo ok \| wc -c`) | unreached under translator (blocked behind `execve`-path gaps) | no |
| 24 | `getuid` | BusyBox `ls` startup | unreached/unknown tolerance | defined, undispatched |
| 64 | `getppid` | BusyBox `sh` job control | unreached/unknown tolerance | defined, undispatched |

Not met by either workload, hence no evidence claimed: `readlink(85)`
/ `readlinkat(296)` (L5a's lane), `stat64`/`fstat64`/`faccessat`,
`mremap`, `madvise`. `set_tid_address(232)` is already implemented.

“Defined, undispatched” = present in frozen `src/os/syscall_nr.h` but
with no `case` in the dispatch switch (returns `-ENOSYS`).

## 5. BusyBox qualification

- Source: `https://busybox.net/downloads/busybox-1.37.0.tar.bz2`
  (2565764 B). Container needs `ca-certificates` (TLS fetch) and
  `bzip2` (extract) beyond the lane card's package list.
- Lane-local build fixes in `tools/qualify_busybox.sh` (`.config`
  seds, no repo-source changes): disable `CONFIG_SHA1_HWACCEL` /
  `CONFIG_SHA256_HWACCEL` (x86-only SHA-NI asm does not compile with
  `powerpc-linux-gnu-gcc`) and `CONFIG_TC` (`networking/tc.c` needs
  CBQ qdisc structs absent from the 6.12 cross kernel headers). The
  workload (`sh`, `ls`, `echo`, `wc`) does not need them.
- Binary: `ELF 32-bit MSB executable, PowerPC, statically linked`,
  2561356 B.
- Oracle `-cpu 750`: exit `0`, 93 bytes
  (`bin boot dev etc home … var w` + `3`).
  Oracle `-cpu e500v2`: guest `SIGILL` (same E1 root cause; the
  strict script gate exits `132` here, which is the intended signal).
- Translator (`--interp` and `--dbt`): exit `0` process-wise but empty
  stdout and `sh: ls: Function not implemented` on stderr — no output
  is identical to the oracle.
- Workload analysis (from oracle `-strace`): defconfig sets
  `CONFIG_FEATURE_SH_STANDALONE=n`, so `sh -c` does NOT run internal
  applets — it `statx`-searches `PATH` and `execve`s EXTERNAL
  `/usr/bin/ls` and `/usr/bin/wc`. On the oracle these are the
  container's arm64 binaries executed natively by the host kernel
  (qemu `execve` passthrough), so the mandated command line is
  inherently host-dependent; the direct-applet form
  `./busybox ls /` stays purely in-guest PPC (oracle: `openat` +
  `getdents64` ×2 + `statx` + `write`, exit `0`).

## 6. Escalations to the Coordinator

- E1 — oracle contradicts lane doc: `qemu-ppc -cpu e500v2` (and
  `e500`) SIGILLs ALL Debian powerpc userspace (static, dynamic, and
  BusyBox; classic `stfd` in `ld.so`). The card/RC5 “`-cpu 750 and
  -cpu e500v2`” oracle expectation is unachievable with this
  toolchain+qemu pair; needs a doc amendment or a different CPU pick.
- E2 — `PPC32RT_SYSROOT` is not honored: nothing populates
  `ctx->sysroot` (`main.c` has no env/flag for it; frozen). Absolute
  guest opens in `syscalls.c` `openat` likewise bypass the sysroot.
  Dynamic loading cannot work without coordinator-owned plumbing
  changes (plus L5a's `AT_BASE`, still on its branch).
- E3 — missing syscalls in frozen `src/os/syscalls.c`: first-fatal
  `statx(383)`; then `getcwd(182)`, `ugetrlimit(190)`,
  `getdents64(202)`, `pipe2(317)`, `getuid(24)`, `getppid(64)`;
  tolerated-missing `set_robust_list(300)`, `rseq(387)`. Lane makes
  no frozen-file edits per the escalation rule.

## 7. Residual gaps (not escalations)

- G1: `ls /` output depends on the container root (deterministic
  within one container/CI image; pin the image for byte-diffing).
- G2: the mandated `sh -c` form execs host-arch `/usr/bin/*` on the
  oracle; a pure-guest RC5 comparison should use direct-applet
  invocation (`./busybox ls /`, `./busybox wc -c`).
- G3: `--trace` is parsed but emits nothing; a guest syscall tracer
  would have isolated the translator-side first fault precisely.
- G4: `PPC32RT_SYSROOT`/`LD_LIBRARY_PATH` interplay and the
  `/etc/ld.so.cache` host-fallback (qemu `-L` serves host files for
  sysroot-missing paths) deserve a contract note in `SPEC.md`.
- G5: `test_p5_dyn`'s `AT_BASE != 0` check passes only after L5a's
  `stack32.c` auxv hunk merges (current translator: `AT_BASE` absent).

## 8. Reproduction (lane container)

```sh
# toolchain + sysroot + oracle
apt-get install -y gcc-powerpc-linux-gnu libc6-dev-powerpc-cross \
    libc6-powerpc-cross qemu-user
powerpc-linux-gnu-gcc -O2 -fPIC -shared tests/test_p5_dynlib.c \
    -o _build/test_p5_dynlib.so
powerpc-linux-gnu-gcc -O2 -no-pie tests/test_p5_dyn.c \
    -o _build/test_p5_dyn -ldl
qemu-ppc -cpu 750 -L /usr/powerpc-linux-gnu ./_build/test_p5_dyn
# translator (post-E2 plumbing) + busybox gate
sh tools/qualify_busybox.sh
```
