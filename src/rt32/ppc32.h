/*
 * src/rt32/ppc32.h — Interfaces of the vendored PPC32 ISA-agnostic core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/ (itself vendored from a32rt,
 * SPEC D13): mechanical renames i686_/rt32_→ppc32_, I686_/RT32_→PPC32_,
 * all code retyped on the frozen `ppc32_ctx_t` from src/ppc32rt.h.
 * a32h_* / A32H_* handshake symbols are untouched (include/a32host.h is
 * byte-identical, D14).
 *
 * Per-file i686rt origins:
 *   ppc32_vm.c (+regions/priv) ← rt32_vm.c (window init, regions, brk,
 *                      mmap2/munmap/mprotect/mremap, gap finder — kept
 *                      functionally intact; D18/D19 semantics kept)
 *   ppc32_elf32.c      ← rt32_elf32.c (ELF32 loader, PT_INTERP via
 *                      sysroot; admission ELFCLASS32/ELFDATA2MSB/EM_PPC)
 *   ppc32_stack32.c    ← rt32_stack32.c (initial stack; PPC32 auxv lands
 *                      in Phase 2)
 *   ppc32_host.c       ← rt32_host.c (/dev/a32host probe)
 *   ppc32_a64_emit.c/.h ← rt32_a64_emit.c/.h (host-side AArch64
 *                      encoder reused by the Phase 2/3 DBT; prototypes live
 *                      in ppc32_a64_emit.h)
 *
 * Environment variables read by this code:
 *   PPC32RT_WINDOW — requested guest window base G for ppc32_vm_init
 *   PPC32RT_HOST   — set to "none" to skip the /dev/a32host probe
 */

#ifndef PPC32_H
#define PPC32_H

#include "ppc32rt.h"

#include <sys/mman.h>

/* macOS calls it MAP_ANON; Linux MAP_ANONYMOUS. */
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

/* Host handshake (ppc32_host.c) */
void ppc32_host_probe(ppc32_ctx_t *ctx);

/* Guest window & memory management (ppc32_vm.c) */
int      ppc32_vm_init(ppc32_ctx_t *ctx, uint64_t requested_window);
int      ppc32_vm_record_region(ppc32_ctx_t *ctx, uint32_t start, uint32_t end,
                              uint32_t prot, uint32_t flags, const char *name);
uint32_t ppc32_vm_brk(ppc32_ctx_t *ctx, uint32_t new_brk);
void ppc32_vm_reset_for_exec(ppc32_ctx_t *ctx);
uint32_t ppc32_vm_mmap2(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                       uint32_t flags, int fd, uint32_t pgoffset);
int      ppc32_vm_mprotect(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot);
int      ppc32_vm_munmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len);
uint32_t ppc32_vm_mremap(ppc32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                        uint32_t new_len, uint32_t flags, uint32_t new_addr);
void     ppc32_vm_sync_ctx(ppc32_ctx_t *ctx);

/* ELF32 loader & initial stack (ppc32_elf32.c, ppc32_stack32.c) */
typedef struct ppc32_elf_info {
    uint32_t entry;
    uint32_t phdr_vaddr;
    uint32_t phent;
    uint32_t phnum;
    uint32_t load_bias;
    uint32_t max_vaddr;
    uint32_t interp_base;
    uint32_t text_start;
    uint32_t text_end;
    char     interp_path[256];
} ppc32_elf_info_t;

int ppc32_open_guest_ro(const ppc32_ctx_t *ctx, const char *guest_path);
int ppc32_elf_load(ppc32_ctx_t *ctx, int exec_fd, const char *path,
                  ppc32_elf_info_t *out_info);
/* No kuser helper page exists on PPC32: the synthetic ppc32 vDSO/sigtramp
 * at PPC32_SIGTRAMP_BASE arrives with Phase 2/4 (SPEC 1.1). */
int ppc32_stack_setup(ppc32_ctx_t *ctx, const ppc32_elf_info_t *elf_info,
                     int guest_argc, char **guest_argv, char **host_envp,
                     uint32_t *out_sp);

#endif /* PPC32_H */
