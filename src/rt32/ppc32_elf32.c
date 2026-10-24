/*
 * src/rt32/ppc32_elf32.c — ELFCLASS32 big-endian (EM_PPC) loader
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/rt32_elf32.c (itself vendored
 * from a32rt/src/elf32.c @ d84feb3, SPEC D13): mechanical renames,
 * retyped on ppc32_ctx_t, admission parameterized on ELFCLASS32 /
 * ELFDATA2MSB / EM_PPC(20) per SPEC 1.1. Guest files are big-endian, so
 * every multi-byte header field is byte-swapped after pread (guest memory
 * itself stays big-endian; REV16/REV/REV64 under interp/dbt, SPEC 2.1).
 */

#define _GNU_SOURCE
#include "ppc32.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define EI_NIDENT   16U
#define ELFCLASS32  1U
#define ELFDATA2MSB 2U
#define ET_EXEC     2U
#define ET_DYN      3U
#define EM_PPC      20U

#define PT_LOAD   1U
#define PT_INTERP 3U
#define PT_PHDR   6U

#define PF_X 0x1U
#define PF_W 0x2U
#define PF_R 0x4U

typedef struct elf32_ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

/* Swap one ELF32 header from file (big-endian) to host order in place. */
static void elf_swap_ehdr(elf32_ehdr_t *e)
{
    e->e_type      = ppc32_be16(e->e_type);
    e->e_machine   = ppc32_be16(e->e_machine);
    e->e_version   = ppc32_be32(e->e_version);
    e->e_entry     = ppc32_be32(e->e_entry);
    e->e_phoff     = ppc32_be32(e->e_phoff);
    e->e_shoff     = ppc32_be32(e->e_shoff);
    e->e_flags     = ppc32_be32(e->e_flags);
    e->e_ehsize    = ppc32_be16(e->e_ehsize);
    e->e_phentsize = ppc32_be16(e->e_phentsize);
    e->e_phnum     = ppc32_be16(e->e_phnum);
    e->e_shentsize = ppc32_be16(e->e_shentsize);
    e->e_shnum     = ppc32_be16(e->e_shnum);
    e->e_shstrndx  = ppc32_be16(e->e_shstrndx);
}

/* Swap one ELF32 program header from file (big-endian) to host order. */
static void elf_swap_phdr(elf32_phdr_t *p)
{
    p->p_type   = ppc32_be32(p->p_type);
    p->p_offset = ppc32_be32(p->p_offset);
    p->p_vaddr  = ppc32_be32(p->p_vaddr);
    p->p_paddr  = ppc32_be32(p->p_paddr);
    p->p_filesz = ppc32_be32(p->p_filesz);
    p->p_memsz  = ppc32_be32(p->p_memsz);
    p->p_flags  = ppc32_be32(p->p_flags);
    p->p_align  = ppc32_be32(p->p_align);
}

int ppc32_open_guest_ro(const ppc32_ctx_t *ctx, const char *guest_path)
{
    if (guest_path == NULL || guest_path[0] == '\0') {
        return -1;
    }
    /* Absolute guest paths resolve against the sysroot here; the full
     * resolver (relative paths, /proc magic) arrives with the Phase 2
     * syscall marshal. */
    if (ctx != NULL && guest_path[0] == '/' &&
        ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char resolved[PATH_MAX];
        int n = snprintf(resolved, sizeof(resolved), "%s%s", ctx->sysroot, guest_path);
        if (n > 0 && (size_t)n < sizeof(resolved)) {
            int fd = open(resolved, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    return open(guest_path, O_RDONLY | O_CLOEXEC);
}

static int pread_full(int fd, void *buf, size_t count, off_t offset)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = pread(fd, p + total, count - total, offset + (off_t)total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int protect_and_record_seg(ppc32_ctx_t *ctx, uint32_t start, uint32_t end,
                                  uint32_t guest_prot, const char *label)
{
    if (mprotect(ppc32_guest_ptr(ctx, start), end - start, ppc32_host_prot(ctx, guest_prot)) != 0) {
        fprintf(stderr, "ppc32rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                label, start, end, strerror(errno));
        return -1;
    }
    ppc32_vm_record_region(ctx, start, end, guest_prot, 0x12U, label);
    return 0;
}

static int load_elf32_image(ppc32_ctx_t *ctx, int fd, uint32_t default_pie_base,
                            const char *label, ppc32_elf_info_t *out)
{
    elf32_ehdr_t ehdr;
    if (pread_full(fd, &ehdr, sizeof(ehdr), 0) != 0) {
        fprintf(stderr, "ppc32rt: %s: failed to read ELF header\n", label);
        return -1;
    }

    if (ehdr.e_ident[0] != 0x7fU || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
        fprintf(stderr, "ppc32rt: %s: not an ELF file\n", label);
        return -1;
    }
    if (ehdr.e_ident[4] != ELFCLASS32 || ehdr.e_ident[5] != ELFDATA2MSB) {
        fprintf(stderr, "ppc32rt: %s: not a 32-bit big-endian ELF\n", label);
        return -1;
    }
    elf_swap_ehdr(&ehdr);
    if (ehdr.e_machine != EM_PPC) {
        fprintf(stderr, "ppc32rt: %s: not a PowerPC (EM_PPC) ELF\n", label);
        return -1;
    }
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        fprintf(stderr, "ppc32rt: %s: unsupported ELF type %u\n", label, ehdr.e_type);
        return -1;
    }
    if (ehdr.e_phentsize != sizeof(elf32_phdr_t) || ehdr.e_phnum == 0U || ehdr.e_phnum > 64U) {
        fprintf(stderr, "ppc32rt: %s: invalid program header table\n", label);
        return -1;
    }

    elf32_phdr_t phdrs[64];
    size_t phdr_bytes = (size_t)ehdr.e_phnum * sizeof(elf32_phdr_t);
    if (pread_full(fd, phdrs, phdr_bytes, (off_t)ehdr.e_phoff) != 0) {
        fprintf(stderr, "ppc32rt: %s: failed to read program headers\n", label);
        return -1;
    }
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        elf_swap_phdr(&phdrs[i]);
    }

    uint32_t min_vaddr = UINT32_MAX;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0U) {
            if (phdrs[i].p_vaddr < min_vaddr) {
                min_vaddr = phdrs[i].p_vaddr;
            }
        }
    }
    if (min_vaddr == UINT32_MAX) {
        fprintf(stderr, "ppc32rt: %s: no PT_LOAD segments\n", label);
        return -1;
    }

    uint32_t load_bias = 0U;
    if (ehdr.e_type == ET_DYN && min_vaddr < 0x10000U) {
        load_bias = default_pie_base;
    }

    if (ehdr.e_entry == 0U) {
        fprintf(stderr, "ppc32rt: %s: missing entry point (e_entry == 0)\n", label);
        return -1;
    }
    if ((ehdr.e_entry & 3U) != 0U) {
        /* PowerPC instructions are fixed 4-byte words; nip must be aligned. */
        fprintf(stderr, "ppc32rt: %s: misaligned entry point 0x%x\n", label, ehdr.e_entry);
        return -1;
    }

    uint64_t entry64 = 0ULL;
    if (ehdr.e_entry != 0U) {
        entry64 = (uint64_t)ehdr.e_entry + (uint64_t)load_bias;
        if (entry64 < 0x10000ULL || entry64 >= (uint64_t)PPC32_TASK_SIZE_TOP) {
            fprintf(stderr, "ppc32rt: %s: entry point 0x%llx out of guest bounds\n",
                    label, (unsigned long long)entry64);
            return -1;
        }
    }

    memset(out, 0, sizeof(*out));
    out->load_bias = load_bias + ppc32_page_down(min_vaddr);
    out->entry     = (uint32_t)entry64;
    out->phent     = ehdr.e_phentsize;
    out->phnum     = ehdr.e_phnum;
    /* e_entry alignment was verified above; every PT_LOAD executable byte
     * range is a valid 4-byte-aligned nip candidate. */

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type == PT_PHDR) {
            uint64_t phdr_va64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
            if (phdr_va64 + phdr_bytes <= (uint64_t)PPC32_TASK_SIZE_TOP) {
                out->phdr_vaddr = (uint32_t)phdr_va64;
            }
        } else if (ph->p_type == PT_INTERP) {
            if (ph->p_filesz == 0U || ph->p_filesz >= sizeof(out->interp_path)) {
                fprintf(stderr, "ppc32rt: %s: invalid PT_INTERP filesz %u\n", label, ph->p_filesz);
                return -1;
            }
            if (pread_full(fd, out->interp_path, ph->p_filesz, (off_t)ph->p_offset) != 0) {
                return -1;
            }
            out->interp_path[ph->p_filesz] = '\0';
            if (out->interp_path[0] == '\0') {
                return -1;
            }
        }
    }

    uint32_t highest_mapped_end  = 0U;
    uint32_t highest_mapped_prot = 0U;
    uint32_t prev_seg_end        = 0U;
    uint32_t fallback_phdr_vaddr = 0U;
    bool     entry_in_load       = false;
    bool     phdr_in_load        = false;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0U) {
            continue;
        }
        if (ph->p_filesz > ph->p_memsz) {
            fprintf(stderr, "ppc32rt: %s: invalid segment filesz (0x%x) > memsz (0x%x)\n",
                    label, ph->p_filesz, ph->p_memsz);
            return -1;
        }

        uint64_t seg_vaddr64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
        uint64_t memsz       = (uint64_t)ph->p_memsz;
        if (seg_vaddr64 >= (uint64_t)PPC32_TASK_SIZE_TOP ||
            seg_vaddr64 + memsz > (uint64_t)PPC32_TASK_SIZE_TOP) {
            fprintf(stderr, "ppc32rt: %s: segment [0x%llx, 0x%llx) out of guest bounds\n",
                    label, (unsigned long long)seg_vaddr64,
                    (unsigned long long)(seg_vaddr64 + memsz));
            return -1;
        }

        uint32_t seg_vaddr = (uint32_t)seg_vaddr64;
        uint64_t seg_end64 = seg_vaddr64 + memsz;
        if (seg_vaddr < prev_seg_end) {
            fprintf(stderr, "ppc32rt: %s: overlapping or out-of-order PT_LOAD segment at 0x%x\n",
                    label, seg_vaddr);
            return -1;
        }
        prev_seg_end = (uint32_t)seg_end64;

        if (out->entry != 0U) {
            /* PowerPC: fixed 4-byte instructions, entry verified aligned. */
            uint32_t entry_pc      = out->entry;
            uint32_t entry_min_len = 4U;
            if ((ph->p_flags & PF_X) != 0U &&
                entry_pc >= seg_vaddr &&
                (uint64_t)entry_pc + entry_min_len <= seg_vaddr64 + memsz) {
                entry_in_load = true;
            }
        }
        uint32_t page_start = ppc32_page_down(seg_vaddr);
        uint64_t map_end64  = (seg_end64 + 0xFFFULL) & ~0xFFFULL;
        if (page_start < 0x10000U || map_end64 > (uint64_t)PPC32_TASK_SIZE_TOP) {
            fprintf(stderr, "ppc32rt: %s: segment [0x%x, 0x%llx) out of guest bounds\n",
                    label, page_start, (unsigned long long)map_end64);
            return -1;
        }
        uint32_t map_end   = (uint32_t)map_end64;
        uint32_t map_start = (page_start < highest_mapped_end) ? highest_mapped_end : page_start;
        for (size_t r = 0U; r < ctx->region_count; r++) {
            if (map_start < ctx->regions[r].end && map_end > ctx->regions[r].start) {
                fprintf(stderr, "ppc32rt: %s: segment [0x%x, 0x%x) overlaps existing region\n",
                        label, map_start, map_end);
                return -1;
            }
        }

        uint32_t guest_prot = ((ph->p_flags & PF_R) ? (uint32_t)PROT_READ : 0U) |
                              ((ph->p_flags & PF_W) ? (uint32_t)PROT_WRITE : 0U) |
                              ((ph->p_flags & PF_X) ? (uint32_t)PROT_EXEC : 0U);

        uint32_t shared_end  = (map_end < map_start) ? map_end : map_start;
        uint32_t merged_prot = highest_mapped_prot | guest_prot;
        if (page_start < map_start) {
            if (mprotect(ppc32_guest_ptr(ctx, page_start), shared_end - page_start,
                         PROT_READ | PROT_WRITE) != 0) {
                fprintf(stderr, "ppc32rt: %s: mprotect RW failed on shared page [0x%x, 0x%x): %s\n",
                        label, page_start, shared_end, strerror(errno));
                return -1;
            }
        }

        if (map_end > map_start) {
            void *res = mmap(ppc32_guest_ptr(ctx, map_start), map_end - map_start,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (res == MAP_FAILED) {
                fprintf(stderr, "ppc32rt: %s: failed to map segment [0x%x, 0x%x): %s\n",
                        label, map_start, map_end, strerror(errno));
                return -1;
            }
        }

        uint32_t read_file_off = ph->p_offset;
        uint32_t read_file_len = ph->p_filesz;
        if (ph->p_filesz > 0U) {
            uint32_t page_off = ph->p_vaddr & 0xFFFU;
            uint32_t dst_va   = seg_vaddr;
            if (page_start == map_start && page_off != 0U && ph->p_offset >= page_off) {
                read_file_off = ph->p_offset - page_off;
                read_file_len = ph->p_filesz + page_off;
                dst_va        = map_start;
            }
            if (pread_full(fd, ppc32_guest_ptr(ctx, dst_va), read_file_len,
                           (off_t)read_file_off) != 0) {
                fprintf(stderr, "ppc32rt: %s: failed to read segment payload\n", label);
                return -1;
            }
        }

        if (ph->p_memsz > ph->p_filesz) {
            memset(ppc32_guest_ptr(ctx, seg_vaddr + ph->p_filesz), 0,
                   (size_t)(ph->p_memsz - ph->p_filesz));
        }

        if (page_start < map_start) {
            if (protect_and_record_seg(ctx, page_start, shared_end, merged_prot, label) != 0) {
                return -1;
            }
            highest_mapped_prot = merged_prot;
        }
        if (map_end > map_start) {
            if (protect_and_record_seg(ctx, map_start, map_end, guest_prot, label) != 0) {
                return -1;
            }
            highest_mapped_end  = map_end;
            highest_mapped_prot = guest_prot;
        }

        if (ph->p_flags & PF_X) {
            if (out->text_start == 0U || seg_vaddr < out->text_start) {
                out->text_start = seg_vaddr;
            }
            if (seg_vaddr + ph->p_memsz > out->text_end) {
                out->text_end = seg_vaddr + ph->p_memsz;
            }
        }

        uint32_t base_va = (read_file_off < ph->p_offset) ? page_start : seg_vaddr;
        if (out->phdr_vaddr != 0U &&
            out->phdr_vaddr >= base_va &&
            (uint64_t)out->phdr_vaddr + phdr_bytes <= (uint64_t)base_va + (uint64_t)read_file_len) {
            phdr_in_load = true;
        }
        if (fallback_phdr_vaddr == 0U && read_file_off <= ehdr.e_phoff &&
            (uint64_t)ehdr.e_phoff + phdr_bytes <= (uint64_t)read_file_off + (uint64_t)read_file_len) {
            fallback_phdr_vaddr = base_va + (ehdr.e_phoff - read_file_off);
        }

        if (map_end > out->max_vaddr) {
            out->max_vaddr = map_end;
        }
    }

    if (!phdr_in_load) {
        out->phdr_vaddr = 0U;
    }
    if (out->phdr_vaddr == 0U) {
        out->phdr_vaddr = fallback_phdr_vaddr;
    }

    /* e_entry == 0 is rejected above; PowerPC has a single fixed-width
     * instruction set, so no interworking scan is needed. */

    if (!entry_in_load) {
        fprintf(stderr, "ppc32rt: %s: entry point 0x%x is not within any PT_LOAD segment\n",
                label, out->entry);
        return -1;
    }

    return 0;
}

int ppc32_elf_load(ppc32_ctx_t *ctx, int exec_fd, const char *path, ppc32_elf_info_t *out_info)
{
    if (!ctx || !out_info) {
        return -1;
    }

    int fd = exec_fd;
    if (fd < 0) {
        if (!path) {
            return -1;
        }
        fd = ppc32_open_guest_ro(ctx, path);
        if (fd < 0) {
            fprintf(stderr, "ppc32rt: cannot open '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }

    int rc = load_elf32_image(ctx, fd, 0x00400000U, path ? path : "[guest]", out_info);
    close(fd);
    if (rc != 0) {
        return -1;
    }

    ctx->elf_base  = out_info->load_bias;
    ctx->elf_entry = out_info->entry;
    ctx->brk_base  = ppc32_page_up(out_info->max_vaddr);
    ctx->brk_curr  = ctx->brk_base;

    /* Load PT_INTERP if present */
    if (out_info->interp_path[0] != '\0') {
        int ifd = ppc32_open_guest_ro(ctx, out_info->interp_path);
        if (ifd < 0) {
            fprintf(stderr, "ppc32rt: cannot open interpreter '%s': %s\n",
                    out_info->interp_path, strerror(errno));
            return -1;
        }

        ppc32_elf_info_t interp_info;
        uint32_t interp_base = (ctx->brk_base > 0x60000000U) ? ctx->brk_base : 0x60000000U;
        int irc = load_elf32_image(ctx, ifd, interp_base, out_info->interp_path, &interp_info);
        close(ifd);
        if (irc != 0) {
            return -1;
        }
        out_info->interp_base = interp_info.load_bias;
        ctx->interp_base      = interp_info.load_bias;
        ctx->elf_entry        = interp_info.entry;
        uint32_t interp_end   = ppc32_page_up(interp_info.max_vaddr);
        if (ctx->brk_base >= interp_info.load_bias && ctx->brk_base < interp_end) {
            ctx->brk_base = interp_end;
            ctx->brk_curr = ctx->brk_base;
        }
    }

    return 0;
}

/* No kuser helper page exists on PPC32: the synthetic ppc32 vDSO/sigtramp
 * at PPC32_SIGTRAMP_BASE (0xbfffe000) arrives with Phase 2/4 (SPEC 1.1). */
