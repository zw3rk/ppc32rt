/*
 * src/rt32/ppc32_vm_priv.h — Private shared decls for ppc32_vm.c / ppc32_vm_regions.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal only (never installed): the VM globals and the `*_locked`
 * region helpers. Callers must hold the VM lock (vm_lock_acquire).
 */

#ifndef PPC32_VM_PRIV_H
#define PPC32_VM_PRIV_H

#include "ppc32.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PPC32_WINDOW_SIZE         0x100000000ULL
#define PPC32_MMAP_BASE_32        0x30000000U /* Guest non-fixed mmap base */
#define PPC32_MMAP_TOP_32         0xB0000000U /* Below the guest stack (base 0xBF7F0000) */
#define PPC32_MAP_FIXED           0x10U
#define PPC32_MAP_ANONYMOUS       0x20U
#define PPC32_MAP_FIXED_NOREPLACE 0x100000U
#define PPC32_MREMAP_MAYMOVE      1U
#define PPC32_MREMAP_FIXED        2U

extern _Atomic uint32_t g_vm_lock;
extern ppc32_ctx_t     *g_vm_root_ctx;
extern uint32_t         g_vm_brk_base;
extern uint32_t         g_vm_brk_curr;
extern uint32_t         g_vm_mmap_cursor;
extern ppc32_region_t   g_vm_regions[PPC32_MAX_REGIONS];
extern size_t           g_vm_region_count;

void     vm_lock_acquire(void);
void     vm_lock_release(void);
uint64_t page_align_up(uint64_t v);
int      vm_reserve_prot_none(ppc32_ctx_t *ctx, uint32_t start,
                              uint32_t len);
int      vm_munmap_locked(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len);

void vm_sync_from_ctx(ppc32_ctx_t *ctx);
void vm_sync_brk_to_ctx(ppc32_ctx_t *ctx);
void vm_copy_state_to_ctx(ppc32_ctx_t *dst);
void vm_sync_to_ctx(ppc32_ctx_t *ctx);
int  vm_dup_fd(int fd);
bool vm_same_backing_fd(int fd_a, int fd_b);
int  vm_create_shared_anon_fd(uint64_t size);
int  vm_grow_shared_anon_fd(int fd, uint64_t req_sz);
bool vm_can_modify_range_locked(uint32_t start, uint32_t end, bool insert_mid);
void vm_remove_region_at(size_t idx);
int  vm_insert_region_raw(uint32_t start, uint32_t end, uint32_t prot,
                          uint32_t flags, const char *name);
int  vm_insert_region_raw_ex(uint32_t start, uint32_t end, uint32_t prot,
                             uint32_t flags, int fd, uint64_t offset,
                             const char *name);
void vm_coalesce_regions_locked(void);
void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end);
int  vm_record_region_locked(uint32_t start, uint32_t end, uint32_t prot,
                             uint32_t flags, const char *name);
int  vm_record_region_ex_locked(uint32_t start, uint32_t end, uint32_t prot,
                                uint32_t flags, int fd, uint64_t offset,
                                const char *name);
int  vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot);
bool vm_range_overlaps_locked(uint32_t start, uint32_t end);
bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz);
bool vm_check_mapped_range_ex_locked(uint32_t start, uint32_t end,
                                     uint32_t *out_prot, uint32_t *out_flags,
                                     int *out_fd, uint64_t *out_offset,
                                     char *out_name, size_t name_sz);
int  vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va);
int  vm_find_free_gap_aligned_locked(uint64_t aligned_len, uint64_t align,
                                     uint32_t *out_va);

#endif /* PPC32_VM_PRIV_H */
