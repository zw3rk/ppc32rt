/*
 * src/vm/vm32.h — Two-regime Class-A 32-bit VM interface (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, sections 4.3-4.6 and 5.1: every Class-A
 * translator reserves the 4 GiB guest window [G, G + 4 GiB) in one of two
 * regimes selected by the dynamic host page size H (never hardcoded):
 *
 *   Regime A1 (H == 4096: native 4K Linux kernels and every hyper-linux
 *   run, where Stage-1 EL1 tables stay 4 KiB): a single MAP_PRIVATE
 *   anonymous window with x20 = G; DBT emits 1-instruction
 *   [x20, wAddr, uxtw] accesses; guest fork() uses native MAP_PRIVATE COW.
 *
 *   Regime A2 (H > 4096: standalone 16 KiB macOS Mach-O backend_darwin.c
 *   and 16K/64K Linux without /dev/a32host): the same 4 GiB span is a
 *   single MAP_PRIVATE anonymous arena whose active host pages carry the
 *   union of their 4 KiB sub-page protections (PROT_READ | PROT_WRITE,
 *   never PROT_EXEC); x20 = &tlb[0] and every DBT access goes through the
 *   7-instruction Soft-TLB fast path (section 4.3) with the 32-bit guest
 *   address zero-extended into w1 first (mov w1, wAddr).
 *
 * This header is the forward-looking shared contract for the DBT emit
 * lanes. Until the Coordinator wires src/vm/ into SRCS, the interpreter
 * carries a small static copy of the LL/SC core (see the STWCX. case in
 * src/interp/interp.c); the DBT lanes unify both behind this API.
 *
 * Curated C11: no VLAs, no _Generic, no <threads.h>. Never touches x18
 * (no inline asm anywhere in src/vm/).
 */

#ifndef PPC32RT_VM_VM32_H
#define PPC32RT_VM_VM32_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"

/* Guest ABI page granule (ppc32) and host-side regime selector. */
#define VM32_GUEST_PAGE_SIZE 4096U
#define VM32_GUEST_PAGE_MASK 4095U
#define VM32_WINDOW_SIZE 0x100000000ULL

typedef enum {
    VM32_REGIME_UNSET = 0,
    VM32_REGIME_A1_DIRECT = 1, /* H == 4096: [x20, wAddr, uxtw] */
    VM32_REGIME_A2_SOFT_TLB = 2 /* H > 4096: 7-insn Soft-TLB */
} vm32_regime_t;

/* Per-4 KiB guest page state tracked for Regime A2 (section 4.3/4.6).
 * Prot values reuse the Linux PROT_READ (0x1) / PROT_WRITE (0x2) bits;
 * PROT_EXEC is never stored: guest X implies host R (ppc32_host_prot),
 * so the union below never maps a guest data page executable (W^X). */
#define VM32_PAGE_UNMAPPED 0U
#define VM32_PAGE_ANON 1U
#define VM32_PAGE_COW_CLEAN 2U
#define VM32_PAGE_COW_DIRTY 3U
#define VM32_PAGE_SHARED 4U
#define VM32_PAGE_EOF_TRAP 5U

/* ---- Regime selection and window/arena lifetime (src/vm/vm32.c) ---- */

vm32_regime_t vm32_select_regime(size_t host_page_size);
vm32_regime_t vm32_current_regime(void);

/* Reserve [G, G + 4 GiB) for the selected regime and publish ctx fields.
 * Returns 0 on success, negative errno on failure. Leaves the legacy
 * ppc32_vm_init window untouched: the caller picks one owner per boot. */
int vm32_init(ppc32_ctx_t *ctx, uint64_t requested_window);

/* Canonical host address of a guest VA. Fixed for the mapping lifetime:
 * in-place COW promotion (PAGE_COW_CLEAN -> PAGE_COW_DIRTY) never moves
 * HVA, so sibling CLONE_VM threads and futex keys stay coherent. */
void *vm32_hva(const ppc32_ctx_t *ctx, uint32_t gva);

/* Arena base backing [G, G + 4 GiB) in Regime A2 (== G in Regime A1). */
uintptr_t vm32_arena_base(void);

/* ---- 7-instruction Soft-TLB (UNIFICATION-PLAN section 4.3) ---- */

#define VM32_TLB_BITS 12U
#define VM32_TLB_SIZE (1U << VM32_TLB_BITS) /* 4096 entries */
#define VM32_TLB_INVALID_TAG (~UINT64_C(0))

typedef struct {
    uint64_t read_tag; /* Offset 0: (gva & ~0xFFF) if readable & < EOF, SEQ_CST */
    uintptr_t addend; /* Offset 8: host_page_base - (gva & ~0xFFF) */
    uint64_t write_tag; /* Offset 16: (gva & ~0xFFF) iff writable &&
                         * !cow_clean && !has_code && !has_reservation */
    uint64_t flags_reserved; /* Offset 24: zero, keeps 32 B alignment */
} vm32_tlb_entry_t;

_Static_assert(sizeof(vm32_tlb_entry_t) == 32,
    "Soft-TLB entry must be 32 bytes");

/* Fast-path probe: true on tag hit with N-byte alignment, addend out.
 * Instructions 1-6 of the emitted sequence have no PSTATE or x0/x1 side
 * effects, so a miss cleanly reaches the 2-insn per-site stub. */
bool vm32_tlb_probe(uint32_t gva, bool is_store, uint32_t width,
    uintptr_t *addend_out);

/* Slow path shared by every .L_tlb_miss_site_k stub (ctx, x1 = gva,
 * x0 = value, block id, 16-bit site index intact). Returns 0 and fills
 * hva_out on success, negative guest-signal code on fault. */
int vm32_tlb_miss(ppc32_ctx_t *ctx, uint32_t gva, bool is_store,
    void **hva_out);

/* Populate one 4 KiB translation after a mapping change. */
void vm32_tlb_fill(uint32_t gva_page, uintptr_t host_page_base,
    bool readable, bool writable);

/* Range-selective invalidation (< 512 pages) else full clear (M5). */
void vm32_tlb_invalidate_range(uint32_t start_gva, uint32_t end_gva);
void vm32_tlb_invalidate_all(void);

/* ---- Regime A2 host-page permission unions (RC-U3 finding 3) ----
 *
 * One host page (H > 4096) packs several 4 KiB guest sub-pages, so a
 * guest-4K mprotect/mmap/munmap cannot map 1:1 onto a host mprotect:
 * the host page must carry the UNION of its mapped sub-pages' R/W
 * bits (PROT_READ | PROT_WRITE, never PROT_EXEC), recomputed from the
 * per-sub-page state below on every permission change. In Regime A1
 * (H == 4096) the union of one page is the page itself, so the sync
 * is a no-op and the record calls only keep the Soft-TLB arrays
 * truthful for a future regime switch; direct host mappings stay
 * authoritative there.
 *
 * Callers mirror state only AFTER the host mapping call succeeds
 * (section 4.5 Step 3 -> Step 4), so failures mutate zero state.
 * All functions are no-ops on empty ranges and tolerate unmapped gaps. */

/* Dynamic host page size (sysconf(_SC_PAGESIZE), cached, never
 * hardcoded) and whether union semantics apply (H > 4096). */
size_t vm32_host_page_size(void);
bool vm32_is_a2(void);

/* Publish an already-reserved window base as the union arena without
 * reserving (the legacy ppc32_vm_init owner path). Selects the regime
 * from the dynamic host page size. */
void vm32_shadow_window(uint64_t base);

/* Record a mapping change over [start_gva, end_gva): prot uses the
 * PROT_READ/PROT_WRITE bits (exec is stripped), state is one of the
 * VM32_PAGE_* values above (out-of-range states fall back to ANON). */
void vm32_record_map(uint32_t start_gva, uint32_t end_gva, uint8_t prot,
    uint8_t state);
void vm32_record_protect(uint32_t start_gva, uint32_t end_gva,
    uint8_t prot);
void vm32_record_unmap(uint32_t start_gva, uint32_t end_gva);

/* Mark one page's COW line dirty after promotion (COW_CLEAN ->
 * COW_DIRTY) and re-enable its write tag; no-ops on other states. */
void vm32_note_cow_dirty(uint32_t gva_page);
void vm32_mark_eof_trap(uint32_t start_gva, uint32_t end_gva);
bool vm32_page_is_eof_trap(uint32_t gva);

/* Recompute and apply the union prot of every host page intersecting
 * [start_gva, end_gva): PROT_NONE where no sub-page is mapped, else
 * the OR of mapped sub-pages' R/W bits (never PROT_EXEC). Returns 0
 * or a negative errno. No-op when not in Regime A2. */
int vm32_sync_host_range(uint32_t start_gva, uint32_t end_gva);

/* A2 permission application for guest mprotect over [start_gva,
 * start_gva + len): records prot, then applies the per-host-page
 * unions. A2-only; A1 callers keep their direct host mprotect. */
int vm32_protect_union(uint32_t start_gva, uint32_t len, uint8_t prot);

/* A2 unmap over [start_gva, start_gva + len): records UNMAPPED, then
 * downgrades fully-emptied host pages to PROT_NONE via the union. */
int vm32_unmap_union(uint32_t start_gva, uint32_t len);

/* ---- LL/SC reservation + true atomic RMW (section 4.4) ---- */

#define VM32_LL_LINES 1024U
#define VM32_LL_LINE_SHIFT 6U /* 64-byte lines */

/* Record an LWARX reservation: ctx ownership, address, value snapshot,
 * and the line epoch sampled with SEQ_CST. */
void vm32_ll_record(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val);

/* Attempt STWCX.: verifies ownership, address, line epoch (SEQ_CST) and
 * value, then performs the store with a SEQ_CST atomic on HVA. True on
 * success (CR0.EQ = 1 shape), false on reservation loss. Either way the
 * caller's reservation is consumed. */
bool vm32_sc_attempt(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val);

/* Bump a line epoch when a store lands on a reserved page through any
 * path (DBT slow path, interp, copyout, sigframe). Forces write_tag ==
 * ~0 on reserved pages so stores always trap here. */
void vm32_reservation_bump(uint32_t gva_aligned);

/* ---- Relative DBT memory-site records (section 4.3.3) ---- */

typedef enum {
    VM32_NPC_SEQUENTIAL = 0,
    VM32_NPC_STATIC_TARGET = 1,
    VM32_NPC_DYNAMIC_CTX = 2
} vm32_npc_mode_t;

typedef struct {
    uint16_t seq_start_offset;
    uint16_t host_insn_offset;
    uint16_t cont_insn_offset;
    uint16_t guest_pc_delta;
    int32_t npc_delta;
    uint32_t insn_word;
    int16_t sp_rollback_delta;
    uint8_t npc_mode;
    uint8_t width;
    uint8_t flags;
    uint8_t val_or_dst_reg;
    uint8_t addr_base_reg;
    uint8_t reserved;
} vm32_mem_site_t;

_Static_assert(sizeof(vm32_mem_site_t) == 24,
    "vm32_mem_site_t must be 24 bytes");

#define VM32_SITE_STORE (1U << 0)
#define VM32_SITE_SIGNED (1U << 1)
#define VM32_SITE_BE (1U << 2)
#define VM32_SITE_IN_DELAY_SLOT (1U << 3)
#define VM32_SITE_PRE_COMMITTED_SP (1U << 4)

/* ---- Provider A file backing (section 5.1, src/vm/vm_file.c) ---- */

int vm_file_populate_private(void *hva, int host_fd, uint64_t file_offset,
    size_t len);
void vm_file_note_private(int host_fd, uint32_t gva_base, uint32_t pages,
    uint64_t map_offset);
void vm_file_promote_cow(uint32_t gva_page);
int vm_file_on_truncate(uint64_t new_size);
int vm_file_hook_write(int host_fd, uint64_t end_offset);

#endif /* PPC32RT_VM_VM32_H */
