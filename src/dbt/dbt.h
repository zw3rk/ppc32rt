/*
 * src/dbt/dbt.h — AArch64 DBT core API (Phase 2, lane L2b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Block translator driver: guest basic blocks of up to 64 instructions
 * (stopping at control transfers or guest page crossings) are translated
 * to AArch64 into RW staging, flipped to PROT_READ|PROT_EXEC with an
 * I-cache flush before execution (W^X; guest data pages are never
 * PROT_EXEC), and run via the trampoline. Direct block chaining goes
 * through the emitted slot/IBTC/RAS paths; bail-outs return to the
 * C dispatch loop in dbt_run.
 *
 * Engine contract (consumed by lane L2c and the Phase-2 main driver):
 *   - dbt_run mirrors interp_run driver semantics: it translates and
 *     executes blocks until ctx->exit_reason != NONE, then returns the
 *     reason, so main.c can swap engines.
 *   - UNDEF exits (undecodable word, or single-step) fall back to one
 *     interp_step and then resume translation; SYSCALL/TRAP/FAULT are
 *     returned to the caller for dispatch.
 *   - ppc32_dbt_invalidate_range satisfies the rt32 extern used by
 *     vm_invalidate_jit (page-version invalidation).
 *
 * Narrow emit callback (owned by lane L2c, defined here so both lanes
 * share one signature):
 *   typedef int (*ppc32_emit_fn)(a64_buf_t *b,
 *                                const ppc32_insn_t *insn, uint32_t pc);
 *   - Return 0 when the instruction was emitted; dbt.c ends the block
 *     after control-transfer/terminal ops (B, BC, BCLR, BCCTR, SC,
 *     UNDEF) on its own, so the emitter only emits the exit sequences.
 *   - Return nonzero when the instruction cannot be emitted; dbt.c ends
 *     the block with an exit_branch to the unemitted pc (or a single
 *     exit_undef when nothing was emitted yet, forcing interp_step
 *     progress and ruling out retranslate spins).
 *   Until L2c lands, dbt.c installs a TEMPORARY all-fallback emitter
 *   (every call returns nonzero); every block is then one exit_undef
 *   plus interp_step, which is exactly interp semantics.
 *
 * Trampoline contract (trampoline_a64.S):
 *   uint32_t ppc32_jit_run_block(ppc32_ctx_t *ctx, const void *code,
 *                                void *cur_entry, const void *epoch_ptr);
 *   - On entry: x19 = ctx, x20 = ctx->guest_base (xG), x27 = cur_entry,
 *     x28 = epoch_ptr (&g_cache_epoch), x24 = chain-delta accumulator.
 *   - Emitted code returns with `ret`, w15 = exit destination pc,
 *     w16 = PPC32_EXIT_* reason. The trampoline stores exit_reason and
 *     exit_dest, stores nip = w15 for BRANCH/UNDEF/SYSCALL exits (TRAP
 *     and FAULT exits store nip themselves before returning), folds the
 *     x24 chain delta into ctx->chain_hits, and returns the reason.
 *   - Callee-saved host state (x19-x28, fp, lr) is preserved; the
 *     platform register is never touched; emitted code may use
 *     w0-w17/w21-w23 and v0-v7 only.
 */

#ifndef PPC32RT_DBT_H
#define PPC32RT_DBT_H

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"
#include "interp/decode.h"
#include "rt32/ppc32_a64_emit.h"

/* Maximum guest instructions per translated block (matches the interp
 * block budget so --difftest compares equal-length chunks). */
#define PPC32_DBT_BLOCK_BUDGET 64U

/* Direct-mapped translation cache size (power of two). */
#define PPC32_DBT_HT_BITS 10U
#define PPC32_DBT_HT_SIZE (1U << PPC32_DBT_HT_BITS)

/* Per-op emitter callback (lane L2c owns the implementation). */
typedef int (*ppc32_emit_fn)(a64_buf_t *b, const ppc32_insn_t *insn,
    uint32_t pc);

/*
 * Translation-cache entry. The FIRST 24 bytes alias the ctx IBTC/RAS
 * entry layout (key@0, epoch@4, host_code@8, entry@16) so emitted
 * chaining code can treat both uniformly; ret_entry@96 and
 * slot_entry[8]@152 are read by the carried a64 exit sequences
 * (x27 = cur_entry). Offsets are pinned by static asserts below.
 */
typedef struct ppc32_block {
    uint64_t keyepoch;              /* +0:  key | ((uint64_t)epoch << 32) */
    void    *host_code;             /* +8 */
    void    *entry;                 /* +16 (code address branched to) */
    uint64_t pad0[9];               /* +24 .. +88 */
    void    *ret_entry;             /* +96 (call fallthrough, or NULL) */
    uint64_t pad1[6];               /* +104 .. +144 */
    void    *slot_entry[8];         /* +152 .. (direct-chain slots) */
    uint32_t guest_pc;              /* block start (key) */
    uint32_t pagever;               /* page version sampled at install */
    uint32_t slot_pc[8];            /* exit_slot_pcs copy (backfill) */
    unsigned slot_count;
    uint32_t ret_pc;                /* wanted ret_entry key (or 0) */
    bool     occupied;
} ppc32_block_t;

_Static_assert(offsetof(ppc32_block_t, host_code) == 8,
    "emit reads host_code @8");
_Static_assert(offsetof(ppc32_block_t, entry) == 16,
    "emit reads entry @16");
_Static_assert(offsetof(ppc32_block_t, ret_entry) == 96,
    "emit reads ret_entry @96");
_Static_assert(offsetof(ppc32_block_t, slot_entry) == 152,
    "emit reads slot_entry @152");

/* Trampoline (trampoline_a64.S). Never call with NULL code/entry. */
uint32_t ppc32_jit_run_block(ppc32_ctx_t *ctx, const void *code,
    void *cur_entry, const void *epoch_ptr);

/* Run translated blocks until exit_reason != NONE; return the reason.
 * Mirrors the interp_run/main.c driver: SYSCALL returns with nip AT the
 * sc word (the syscall layer advances past it), UNDEF is retried via
 * interp_step and resumed internally. */
int dbt_run(ppc32_ctx_t *ctx);

/* Drop every translated block and sever all IBTC/RAS links. */
void dbt_invalidate_all(ppc32_ctx_t *ctx);

/* Satisfies the rt32 extern: drop blocks overlapping [start, end) and
 * sever every IBTC/RAS/slot link into the range. end is exclusive;
 * start >= end is a no-op. Safe to call outside block execution. */
void ppc32_dbt_invalidate_range(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end);

/* Install/replace the per-op emitter (lane L2c). NULL restores the
 * temporary all-fallback emitter. */
void ppc32_dbt_set_emitter(ppc32_emit_fn fn);

/* ---- cache.c internals (shared with dbt.c only) ---- */
/* H1 SMC post-store hook (src/dbt/cache.c): evict translations
 * overlapping [ea, ea + len) so chained re-entry runs fresh bytes.
 * cur is the executing entry (link-severed, never unmapped). */
void ppc32_smc_store(ppc32_ctx_t *ctx, uint32_t ea, uint32_t len,
    void *cur);
/* P1 inline-guard base: occupancy bitmap over guest 4 KiB pages. */
const uint64_t *ppc32_code_pages_base(void);
ppc32_block_t *ppc32_cache_lookup(ppc32_ctx_t *ctx, uint32_t pc);
ppc32_block_t *ppc32_cache_install(ppc32_ctx_t *ctx, uint32_t pc,
    const uint32_t *words, size_t nwords, const uint32_t *slot_pcs,
    unsigned nslots, bool is_call, uint32_t ret_pc);
/* P32-R6-1: flush this ctx's IBTC/RAS when its entries predate the
 * current generation, and record ctx->ibtc_synced_epoch for the
 * quiescent reclaimer. The dispatch loop calls this before lookup. */
void ppc32_cache_sync_ctx(ppc32_ctx_t *ctx);
/* P32-R6-1: fork protocol for s_cache_lock (wired into proc.c):
 * prepare holds it across the snapshot, parent releases, child drops
 * the inherited held value and forgets dead peer registrations. */
void ppc32_cache_fork_prepare(void);
void ppc32_cache_fork_parent(void);
void ppc32_cache_fork_child(void);
/* Drop one ctx from the sync registry (call before freeing it). */
void ppc32_cache_forget_ctx(const ppc32_ctx_t *ctx);
void ppc32_cache_invalidate_range(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end);
void ppc32_cache_invalidate_all(ppc32_ctx_t *ctx);
uint32_t *ppc32_cache_epoch_ptr(void);

#endif /* PPC32RT_DBT_H */
