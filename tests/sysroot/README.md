# tests/sysroot — Minimal committed PowerPC 32-bit guest sysroot

This directory holds the smallest root filesystem the dynamic parity
guests need under `--sysroot` (ppc32 `ld.so.1` resolves `/lib/...`
here first, qemu-style). It covers `p5_dyn`, `h4_cxx`, `p3_torture`,
and `tcg_smoke`:

- `lib/ld.so.1` — program interpreter (`PT_INTERP /lib/ld.so.1`)
- `lib/libc.so.6`
- `lib/libm.so.6`
- `lib/libdl.so.2`
- `lib/libpthread.so.0`
- `lib/libstdc++.so.6` (+ `libstdc++.so.6.0.33` target)
- `lib/libgcc_s.so.1`

Source: `libc6-powerpc-cross` and `libstdc++6-powerpc-cross`
(Debian trixie). Refresh inside the parity container:

    tar -cf /tmp/sysroot.tar -C /usr/powerpc-linux-gnu \
      lib/ld.so.1 lib/libc.so.6 lib/libm.so.6 lib/libdl.so.2 \
      lib/libpthread.so.0 lib/libstdc++.so.6 \
      lib/libstdc++.so.6.0.33 lib/libgcc_s.so.1

then extract with `tar -xf` on the host. Always transfer via tar:
copying the tree file-by-file across the macOS file-sharing boundary
corrupts the libraries (same discipline as `ppc64rt/tests/sysroot`).

Deliberately absent: `/etc/ld.so.cache` (on hosts that have one the
probe may open the host file; the guest loader finds no usable entry
and falls through to the sysroot paths), locale data, and anything
`ls`-style BusyBox tests would need (out of scope for Wave C2).
