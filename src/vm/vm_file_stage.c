/*
 * src/vm/vm_file_stage.c — A2 sub-page MAP_SHARED staging + coherence
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from vm_file.c (file-size discipline). On hosts with H > 4096
 * a guest MAP_SHARED mapping whose file offset is 4 KiB-aligned but not
 * host-aligned cannot be mmap'd MAP_SHARED from the file directly (host
 * offsets need H alignment). Each distinct (st_dev, st_ino, file_offset)
 * family then shares one memfd-backed staging object sized to the
 * host-rounded mapping length: every alias mmaps the SAME object
 * MAP_SHARED at its own GVA, so stores through one alias (or across
 * fork, which keeps MAP_SHARED shared) are visible through all of them.
 *
 * Overlapping aliases at different file offsets cannot share one
 * object (a memfd mmap offset must be host-aligned, so only the exact
 * file_offset base maps at guest address zero bias). They cohere
 * instead (P32-R4-3): every landed guest store fans out through
 * vm_file_shared_cohere_store to each overlapping same-inode group
 * plus the file itself (write-through, so direct MAP_SHARED aliases
 * and ordinary file I/O observe it), and ordinary file writes refresh
 * overlapping groups via vm_file_shared_refresh_file_range.
 *
 * Fill comes from the file at map time; short reads (EOF) zero-fill
 * and pages wholly beyond the rounded-up EOF still trap via
 * vm_file_trap_beyond_eof. Because staged stores reach the file
 * synchronously, an acquire-time size/mtime change is always foreign:
 * the group refills clean from the file and never drains a stale
 * snapshot back over newer file contents (P32-R4-4). Host-rounded
 * padding beyond EOF is never written to the file.
 *
 * All entry points run under the VM lock (the mmap/munmap/mremap paths
 * hold it); the two fan-out/fan-in helpers additionally take it
 * themselves when the caller does not hold it (syscall/store paths),
 * so they never nest under it. No entry point takes the inode lock or
 * the TLB lock (P32-R4-8 lock order). Slots are dropped by the
 * region-side GC once no live region's file range overlaps them
 * (P32-R4-5 overlap identity, not exact-offset match).
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"
#include "rt32/ppc32_vm_priv.h"
#include "vm/vm_file_int.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define VM_FILE_STAGED_GROUPS 32U

typedef struct {
    uint32_t in_use;
    uint64_t dev;
    uint64_t ino;
    uint64_t file_offset;
    size_t staged_len;
    int stage_fd;
    int src_fd;
    uint64_t file_size;
    uint64_t mtime_ns;
} vm_file_staged_t;

static vm_file_staged_t g_staged[VM_FILE_STAGED_GROUPS];
static _Atomic uint32_t g_stage_live = 0U;

/* P32-R5-7: prefer a writable retained fd for write-through. */
static bool stage_fd_writable(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    int acc;
    if (fl < 0 || fd < 0) {
        return false;
    }
    acc = fl & O_ACCMODE;
    return acc == O_WRONLY || acc == O_RDWR;
}

static size_t stage_round_host(size_t len)
{
    size_t h = vm32_host_page_size();

    if (h < VM32_GUEST_PAGE_SIZE) {
        h = VM32_GUEST_PAGE_SIZE;
    }
    return (len + h - 1U) & ~(h - 1U);
}

static int stage_pwrite_all(int fd, const void *buf, size_t len,
    uint64_t off)
{
    size_t done = 0U;

    while (done < len) {
        ssize_t w = pwrite(fd, (const char *)buf + done, len - done,
            (off_t)(off + (uint64_t)done));

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (w == 0) {
            return -EIO;
        }
        done += (size_t)w;
    }
    return 0;
}

/* Fill [stage_off, stage_off + len) of the staging object from the file
 * at file_off + stage_off (P32-R4-2: the source tracks the destination
 * bias, so growing a group copies the extension bytes from the right
 * file offset); short reads (EOF) zero-fill the remainder. */
static int stage_fill(int stage_fd, int src_fd, uint64_t file_off,
    size_t stage_off, size_t len)
{
    char buf[8192];
    size_t done = 0U;

    while (done < len) {
        size_t want = (len - done < sizeof buf) ? len - done : sizeof buf;
        ssize_t r = pread(src_fd, buf, want,
            (off_t)(file_off + (uint64_t)stage_off + (uint64_t)done));

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (r == 0) {
            size_t z = done;

            (void)memset(buf, 0, sizeof buf);
            while (z < len) {
                size_t w = (len - z < sizeof buf) ? len - z : sizeof buf;
                int rc = stage_pwrite_all(stage_fd, buf, w,
                    (uint64_t)stage_off + (uint64_t)z);

                if (rc != 0) {
                    return rc;
                }
                z += w;
            }
            return 0;
        }
        {
            int rc = stage_pwrite_all(stage_fd, buf, (size_t)r,
                (uint64_t)stage_off + (uint64_t)done);

            if (rc != 0) {
                return rc;
            }
        }
        done += (size_t)r;
    }
    return 0;
}

/* Copy one group's staged bytes back into the file over [wlo, whi),
 * clamped into the group's extent and the current file size so
 * zero-filled EOF tails and host-rounded padding never extend the
 * file. Best-effort: read/write errors stop the copy silently. */
static void stage_drain_locked(size_t idx, uint64_t wlo, uint64_t whi)
{
    char buf[8192];
    uint64_t fsz;
    uint64_t glo;
    uint64_t ghi;
    uint64_t off;
    int rc;

    if (idx >= VM_FILE_STAGED_GROUPS || g_staged[idx].in_use == 0U) {
        return;
    }
    rc = vm_file_fd_identity(g_staged[idx].src_fd, NULL, NULL, &fsz,
        NULL);
    if (rc != 0 || fsz == 0U) {
        return;
    }
    glo = g_staged[idx].file_offset;
    ghi = glo + (uint64_t)g_staged[idx].staged_len;
    if (wlo < glo) {
        wlo = glo;
    }
    if (whi > ghi) {
        whi = ghi;
    }
    if (whi > fsz) {
        whi = fsz;
    }
    if (whi <= wlo) {
        return;
    }
    off = wlo;
    while (off < whi) {
        size_t want = ((uint64_t)sizeof buf < whi - off) ?
            sizeof buf : (size_t)(whi - off);
        ssize_t r = pread(g_staged[idx].stage_fd, buf, want,
            (off_t)(off - g_staged[idx].file_offset));

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        if (stage_pwrite_all(g_staged[idx].src_fd, buf, (size_t)r,
                off) != 0) {
            break;
        }
        off += (uint64_t)r;
    }
    /* The drain itself ticks the file mtime: re-baseline so a later
     * acquire does not mistake our own writeback for a foreign change. */
    g_staged[idx].file_size = fsz;
    (void)vm_file_fd_identity(g_staged[idx].src_fd, NULL, NULL, NULL,
        &g_staged[idx].mtime_ns);
}

int vm_file_shared_acquire(int src_fd, uint64_t file_offset, size_t len,
    int *out_stage_fd)
{
    uint64_t dev;
    uint64_t ino;
    uint64_t fsz;
    uint64_t mtime;
    size_t need;
    size_t i;
    size_t free = VM_FILE_STAGED_GROUPS;

    if (src_fd < 0 || len == 0U || out_stage_fd == NULL) {
        return -EINVAL;
    }
    if (vm_file_fd_identity(src_fd, &dev, &ino, &fsz, &mtime) != 0) {
        return -errno;
    }
    need = stage_round_host(len);
    if (need == 0U) {
        return -ENOMEM;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        int rc;

        if (g_staged[i].in_use == 0U) {
            if (free == VM_FILE_STAGED_GROUPS) {
                free = i;
            }
            continue;
        }
        if (g_staged[i].dev != dev || g_staged[i].ino != ino ||
            g_staged[i].file_offset != file_offset) {
            continue;
        }
        if (g_staged[i].file_size != fsz ||
            g_staged[i].mtime_ns != mtime) {
            /* P32-R4-4: the size/mtime delta is foreign (staged stores
             * already reached the file via write-through), so refill
             * clean from the file instead of draining the stale
             * snapshot back over the newer file contents. */
            if (g_staged[i].staged_len < need &&
                ftruncate(g_staged[i].stage_fd, (off_t)need) != 0) {
                return -errno;
            }
            if (g_staged[i].staged_len < need) {
                g_staged[i].staged_len = need;
            }
            rc = stage_fill(g_staged[i].stage_fd, src_fd, file_offset,
                0U, g_staged[i].staged_len);
            if (rc != 0) {
                return rc;
            }
        } else if (g_staged[i].staged_len < need) {
            size_t old = g_staged[i].staged_len;

            if (ftruncate(g_staged[i].stage_fd, (off_t)need) != 0) {
                return -errno;
            }
            g_staged[i].staged_len = need;
            rc = stage_fill(g_staged[i].stage_fd, src_fd, file_offset,
                old, need - old);
            if (rc != 0) {
                return rc;
            }
        }
        g_staged[i].file_size = fsz;
        g_staged[i].mtime_ns = mtime;
        if (!stage_fd_writable(g_staged[i].src_fd) &&
            stage_fd_writable(src_fd)) {
            int nfd = vm_dup_fd(src_fd);
            if (nfd >= 0) {
                (void)close(g_staged[i].src_fd);
                g_staged[i].src_fd = nfd;
            }
        }
        *out_stage_fd = g_staged[i].stage_fd;
        return 0;
    }
    if (free == VM_FILE_STAGED_GROUPS) {
        return -ENOMEM;
    }
    {
        int sfd = vm_create_shared_anon_fd((uint64_t)need);
        int dfd;
        int rc;

        if (sfd < 0) {
            return sfd;
        }
        dfd = vm_dup_fd(src_fd);
        if (dfd < 0) {
            (void)close(sfd);
            return -errno;
        }
        rc = stage_fill(sfd, src_fd, file_offset, 0U, need);
        if (rc != 0) {
            (void)close(sfd);
            (void)close(dfd);
            return rc;
        }
        g_staged[free].dev = dev;
        g_staged[free].ino = ino;
        g_staged[free].file_offset = file_offset;
        g_staged[free].staged_len = need;
        g_staged[free].stage_fd = sfd;
        g_staged[free].src_fd = dfd;
        g_staged[free].file_size = fsz;
        g_staged[free].mtime_ns = mtime;
        g_staged[free].in_use = 1U;
        atomic_fetch_add_explicit(&g_stage_live, 1U, memory_order_relaxed);
        *out_stage_fd = sfd;
        return 0;
    }
}

void vm_file_shared_writeback_file_range(int fd, uint64_t lo, uint64_t hi)
{
    uint64_t dev;
    uint64_t ino;
    size_t i;

    if (fd < 0 || hi <= lo) {
        return;
    }
    if (vm_file_fd_identity(fd, &dev, &ino, NULL, NULL) != 0) {
        return;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t ghi;

        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        ghi = glo + (uint64_t)g_staged[i].staged_len;
        if (ghi <= lo || glo >= hi) {
            continue;
        }
        stage_drain_locked(i, (glo > lo) ? glo : lo,
            (ghi < hi) ? ghi : hi);
    }
}

size_t vm_file_shared_group_count(void)
{
    return VM_FILE_STAGED_GROUPS;
}

bool vm_file_shared_group_key(size_t idx, uint64_t *dev_out,
    uint64_t *ino_out, uint64_t *off_out, size_t *len_out)
{
    if (idx >= VM_FILE_STAGED_GROUPS || g_staged[idx].in_use == 0U ||
        dev_out == NULL || ino_out == NULL || off_out == NULL) {
        return false;
    }
    *dev_out = g_staged[idx].dev;
    *ino_out = g_staged[idx].ino;
    *off_out = g_staged[idx].file_offset;
    if (len_out != NULL) {
        *len_out = g_staged[idx].staged_len;
    }
    return true;
}

/* Map one staged sub-page MAP_SHARED file range at its (host-aligned)
 * guest address: acquire (or reuse) the family staging object and mmap it
 * MAP_SHARED over the arena slice, then publish guest permissions. The
 * region record (caller's file identity) stays owned by the caller.
 * Returns 0 or a negative errno. Runs under the VM lock. */
int vm_file_shared_map_at(void *host_target, size_t map_len, int use_fd,
    uint64_t host_off, uint32_t target_va, uint32_t map_end, uint8_t prot,
    uint8_t state)
{
    int stage_fd = -1;
    int rc = vm_file_shared_acquire(use_fd, host_off, map_len, &stage_fd);
    void *res;

    if (rc != 0) {
        return rc;
    }
    res = mmap(host_target, map_len, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED, stage_fd, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    vm32_record_map(target_va, map_end, prot, state);
    (void)vm32_sync_host_range(target_va, map_end);
    return 0;
}

void vm_file_shared_drop_group(uint64_t dev, uint64_t ino, uint64_t off)
{
    size_t i;

    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino || g_staged[i].file_offset != off) {
            continue;
        }
        /* P32-R4-4: no drain-back on drop. Guest stores already reached
         * the file via write-through, so draining the whole extent here
         * would write stale clean staged pages over newer external
         * write() bytes. Just release the object. */
        (void)close(g_staged[i].stage_fd);
        (void)close(g_staged[i].src_fd);
        g_staged[i].in_use = 0U;
        g_staged[i].staged_len = 0U;
        atomic_fetch_sub_explicit(&g_stage_live, 1U, memory_order_relaxed);
        return;
    }
}

/* Refresh every live same-inode group overlapping the file range
 * [flo, fhi) from the file (clean fan-in: the file is authoritative
 * for bytes that arrived through direct MAP_SHARED aliases or
 * ordinary file I/O). Clamped to the file size; beyond-EOF padding
 * keeps its zero fill. Caller holds the VM lock. */
static void stage_refresh_groups(uint64_t dev, uint64_t ino, uint64_t flo,
    uint64_t fhi)
{
    uint64_t fsz;
    uint64_t mtime;
    size_t i;

    if (fhi <= flo ||
        atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t ghi;
        uint64_t rlo;
        uint64_t rhi;

        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        ghi = glo + (uint64_t)g_staged[i].staged_len;
        rlo = (glo > flo) ? glo : flo;
        rhi = (ghi < fhi) ? ghi : fhi;
        if (rhi <= rlo) {
            continue;
        }
        if (stage_fill(g_staged[i].stage_fd, g_staged[i].src_fd,
                glo, (size_t)(rlo - glo), (size_t)(rhi - rlo)) != 0) {
            continue;
        }
        if (vm_file_fd_identity(g_staged[i].src_fd, NULL, NULL, &fsz,
                &mtime) == 0) {
            g_staged[i].file_size = fsz;
            g_staged[i].mtime_ns = mtime;
        }
    }
}

/* Fan landed guest bytes at file range [flo, fhi) (backing hva) out to
 * every overlapping same-inode group, and — for true guest stores —
 * through to the file itself (clamped to EOF so the write never
 * extends the file). Caller holds the VM lock. */
static void stage_fanout_groups(uint64_t dev, uint64_t ino, uint64_t flo,
    uint64_t fhi, const void *hva, bool write_file)
{
    uint64_t fsz = 0ULL;
    uint64_t mtime = 0ULL;
    size_t i;

    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t ghi;
        uint64_t rlo;
        uint64_t rhi;

        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        ghi = glo + (uint64_t)g_staged[i].staged_len;
        rlo = (glo > flo) ? glo : flo;
        rhi = (ghi < fhi) ? ghi : fhi;
        if (rhi <= rlo) {
            continue;
        }
        (void)stage_pwrite_all(g_staged[i].stage_fd,
            (const char *)hva + (rlo - flo), (size_t)(rhi - rlo),
            rlo - glo);
    }
    int wfd = -1;

    if (!write_file) {
        return;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        if (stage_fd_writable(g_staged[i].src_fd)) {
            wfd = g_staged[i].src_fd;
            break;
        }
    }
    if (wfd < 0) {
        return;
    }
    if (vm_file_fd_identity(wfd, NULL, NULL, &fsz, NULL) != 0 ||
        flo >= fsz) {
        return;
    }
    if (fhi > fsz) {
        fhi = fsz;
    }
    if (fhi <= flo) {
        return;
    }
    if (stage_pwrite_all(wfd, hva, (size_t)(fhi - flo), flo) == 0 &&
        vm_file_fd_identity(wfd, NULL, NULL, &fsz, &mtime) == 0) {
        size_t j;

        for (j = 0U; j < VM_FILE_STAGED_GROUPS; j++) {
            if (g_staged[j].in_use == 0U || g_staged[j].dev != dev ||
                g_staged[j].ino != ino) {
                continue;
            }
            g_staged[j].file_size = fsz;
            g_staged[j].mtime_ns = mtime;
        }
    }
}

/* Coherence fan-out for one landed guest range (caller holds the VM
 * lock): for every MAP_SHARED file-backed region overlapping guest
 * [ea, ea + len), copy the landed guest bytes (hva already holds
 * them) into overlapping same-inode groups, and — for true guest
 * stores — write them through to the file. No refresh-from-file here:
 * the guest store, stwcx., copyout, or read() already landed in hva,
 * so a refresh would overwrite hva with stale bytes before fan-out
 * reads it (P32-R4-3). Private mappings never participate: their
 * stores stay copy-on-write local. */
static void cohere_locked(const ppc32_ctx_t *ctx, uint32_t ea,
    uint32_t len, bool write_file)
{
    uint64_t end64;
    uint32_t end;
    size_t i;

    if (ctx == NULL || len == 0U ||
        atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    end64 = (uint64_t)ea + (uint64_t)len;
    if (end64 > 0x100000000ULL) {
        end64 = 0x100000000ULL;
    }
    end = (uint32_t)end64;
    if (end <= ea) {
        return;
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        const ppc32_region_t *r = &g_vm_regions[i];
        uint32_t lo;
        uint32_t hi;
        uint64_t dev;
        uint64_t ino;
        uint64_t flo;
        uint64_t fhi;
        const void *hva;

        if (r->fd < 0 || (r->flags & 0x01U) == 0U ||
            (r->flags & PPC32_MAP_ANONYMOUS) != 0U) {
            continue;
        }
        if (r->end <= ea || r->start >= end) {
            continue;
        }
        if (vm_file_fd_identity(r->fd, &dev, &ino, NULL, NULL) != 0) {
            continue;
        }
        lo = (r->start > ea) ? r->start : ea;
        hi = (r->end < end) ? r->end : end;
        flo = r->offset + (uint64_t)(lo - r->start);
        fhi = r->offset + (uint64_t)(hi - r->start);
        hva = (const void *)((uintptr_t)ppc32_guest_ptr(ctx, lo));
        stage_fanout_groups(dev, ino, flo, fhi, hva, write_file);
    }
}

void vm_file_shared_cohere_store(const ppc32_ctx_t *ctx, uint32_t ea,
    uint32_t len)
{
    bool held;

    if (atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    cohere_locked(ctx, ea, len, true);
    if (!held) {
        vm_lock_release();
    }
}

void vm_file_shared_cohere_read(const ppc32_ctx_t *ctx, uint32_t ea,
    uint32_t len)
{
    bool held;

    if (atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    cohere_locked(ctx, ea, len, false);
    if (!held) {
        vm_lock_release();
    }
}

void vm_file_shared_refresh_file_range(int fd, uint64_t lo, uint64_t hi)
{
    uint64_t dev;
    uint64_t ino;
    bool held;

    if (fd < 0 || hi <= lo ||
        atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    if (vm_file_fd_identity(fd, &dev, &ino, NULL, NULL) != 0) {
        return;
    }
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    stage_refresh_groups(dev, ino, lo, hi);
    if (!held) {
        vm_lock_release();
    }
}

bool vm_file_shared_group_referenced(int fd, uint64_t off, uint64_t len)
{
    uint64_t dev;
    uint64_t ino;
    uint64_t end;
    size_t i;

    if (fd < 0 || len == 0U ||
        atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return false;
    }
    if (vm_file_fd_identity(fd, &dev, &ino, NULL, NULL) != 0) {
        return false;
    }
    end = off + (uint64_t)len;
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t ghi;

        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        ghi = glo + (uint64_t)g_staged[i].staged_len;
        if (glo < end && off < ghi) {
            return true;
        }
    }
    return false;
}

void vm_file_shared_truncate_range(int fd, uint64_t lo, uint64_t hi)
{
    static const char zeros[8192] = { 0 };
    uint64_t dev;
    uint64_t ino;
    uint64_t fsz;
    uint64_t mtime;
    size_t i;

    if (fd < 0 || hi <= lo ||
        atomic_load_explicit(&g_stage_live, memory_order_relaxed) == 0U) {
        return;
    }
    if (vm_file_fd_identity(fd, &dev, &ino, &fsz, &mtime) != 0) {
        return;
    }
    /* P32-R4-9: do NOT clamp hi to the post-truncate file size here:
     * shrinking must zero the truncated tail inside each staging
     * group, so hi is clamped per group to its own extent below.
     * Staged zeroing never extends the file (the caller holds the
     * VM lock). */
    if (hi <= lo) {
        return;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t rlo;
        uint64_t rhi;

        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        rlo = (glo > lo) ? glo : lo;
        rhi = glo + (uint64_t)g_staged[i].staged_len;
        if (rhi > hi) {
            rhi = hi;
        }
        if (rhi <= rlo) {
            continue;
        }
        while (rlo < rhi) {
            size_t w = (rhi - rlo < sizeof zeros) ?
                (size_t)(rhi - rlo) : sizeof zeros;

            if (stage_pwrite_all(g_staged[i].stage_fd, zeros, w,
                    rlo - glo) != 0) {
                break;
            }
            rlo += (uint64_t)w;
        }
        g_staged[i].file_size = fsz;
        g_staged[i].mtime_ns = mtime;
    }
}
