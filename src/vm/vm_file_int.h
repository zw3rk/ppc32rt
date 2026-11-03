/*
 * src/vm/vm_file_int.h — Private shared decls for vm_file.c / vm_file_stage.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal only (never installed): stable file identity via fstat plus
 * the cross-TU lock contract. Staging slots are keyed by (st_dev,
 * st_ino), never by reusable fd numbers (P32-R4-10), and every path
 * honors one global acquisition order (P32-R4-8):
 *
 *   VM lock (rt32) -> TLB lock (vm32_tlb.c) -> inode lock (vm_file.c)
 *
 * Staging entry points run under the VM lock and never take the inode
 * lock; truncate/file-mutation paths update inode records first and
 * only then touch TLB state or guest memory, so fork (which takes
 * VM -> TLB -> inode -> LL across its snapshot) cannot deadlock
 * against them.
 */

#ifndef PPC32RT_VM_VM_FILE_INT_H
#define PPC32RT_VM_VM_FILE_INT_H

#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>

/* Stable identity of an open file description: device + inode numbers,
 * current size, and mtime in nanoseconds (second granularity would miss
 * same-second same-size rewrites). Returns 0 or a negative errno. */
static inline int vm_file_fd_identity(int fd, uint64_t *dev_out,
    uint64_t *ino_out, uint64_t *size_out, uint64_t *mtime_ns_out)
{
    struct stat hs;
    uint64_t sec;
    uint64_t nsec;

    if (fd < 0) {
        return -EBADF;
    }
    if (fstat(fd, &hs) != 0) {
        return -errno;
    }
    if (dev_out != NULL) {
        *dev_out = (uint64_t)hs.st_dev;
    }
    if (ino_out != NULL) {
        *ino_out = (uint64_t)hs.st_ino;
    }
    if (size_out != NULL) {
        *size_out = (hs.st_size > 0) ? (uint64_t)hs.st_size : 0ULL;
    }
    if (mtime_ns_out != NULL) {
        sec = (uint64_t)(int64_t)hs.st_mtime;
#if defined(__linux__)
        nsec = (uint64_t)(int64_t)hs.st_mtim.tv_nsec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
        nsec = (uint64_t)(int64_t)hs.st_mtimespec.tv_nsec;
#else
        nsec = 0ULL;
#endif
        *mtime_ns_out = sec * 1000000000ULL + nsec;
    }
    return 0;
}

#endif /* PPC32RT_VM_VM_FILE_INT_H */
