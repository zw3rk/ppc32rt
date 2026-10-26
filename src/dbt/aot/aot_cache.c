/*
 * src/dbt/aot/aot_cache.c — Persistent AOT block cache (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reader/writer for src/dbt/aot/aot.h. Append-only writer (the sealer
 * lane adds fsync/rename publication); linear-scan reader (the index
 * lane adds the hash table once block counts grow). All site records
 * round-trip byte-identical so warm-cache fault recovery, signal PC
 * rewind, and quiescence lookups behave exactly like cold translation.
 *
 * Full-read/full-write loops with EINTR retry; short reads of header
 * fields fail closed (-EIO) instead of executing truncated code.
 * Curated C11, no x18.
 */

#define _POSIX_C_SOURCE 200809L

#include "dbt/aot/aot.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const void *buf, size_t len)
{
    size_t done = 0U;

    while (done < len) {
        ssize_t r = write(fd, (const char *)buf + done, len - done);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (r == 0) {
            return -EIO;
        }
        done += (size_t)r;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    size_t done = 0U;

    while (done < len) {
        ssize_t r = read(fd, (char *)buf + done, len - done);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (r == 0) {
            return -EIO;
        }
        done += (size_t)r;
    }
    return 0;
}

bool ppc32_aot_header_ok(const ppc32_aot_hdr_t *hdr)
{
    if (hdr == NULL) {
        return false;
    }
    if (memcmp(hdr->magic, PPC32_AOT_MAGIC, PPC32_AOT_MAGIC_LEN) != 0) {
        return false;
    }
    if (hdr->version != PPC32_AOT_VERSION) {
        return false;
    }
    return true;
}

int ppc32_aot_append(int cache_fd, uint32_t guest_pc_base,
    const void *code, uint32_t code_len, const vm32_mem_site_t *sites,
    uint32_t site_count)
{
    ppc32_aot_block_hdr_t bh;
    int rc;

    if (cache_fd < 0 || (code_len != 0U && code == NULL) ||
        (site_count != 0U && sites == NULL)) {
        return -EINVAL;
    }
    if (code_len > 65536U || site_count > 512U) {
        return -E2BIG;
    }
    (void)memset(&bh, 0, sizeof bh);
    bh.guest_pc_base = guest_pc_base;
    bh.code_len = code_len;
    bh.site_count = site_count;
    rc = write_all(cache_fd, &bh, sizeof bh);
    if (rc != 0) {
        return rc;
    }
    if (code_len != 0U) {
        rc = write_all(cache_fd, code, code_len);
        if (rc != 0) {
            return rc;
        }
    }
    if (site_count != 0U) {
        rc = write_all(cache_fd, sites,
            (size_t)site_count * sizeof *sites);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int ppc32_aot_lookup(int cache_fd, uint32_t guest_pc_base,
    void *code_out, uint32_t code_cap, vm32_mem_site_t *sites_out,
    uint32_t site_cap, uint32_t *code_len_out, uint32_t *site_count_out)
{
    ppc32_aot_hdr_t hdr;
    uint32_t i;
    int rc;

    if (cache_fd < 0) {
        return -EINVAL;
    }
    if (lseek(cache_fd, 0, SEEK_SET) == (off_t)-1) {
        return -errno;
    }
    rc = read_all(cache_fd, &hdr, sizeof hdr);
    if (rc != 0) {
        return rc;
    }
    if (!ppc32_aot_header_ok(&hdr)) {
        return -EBADMSG;
    }
    for (i = 0U; i < hdr.block_count; i++) {
        ppc32_aot_block_hdr_t bh;

        rc = read_all(cache_fd, &bh, sizeof bh);
        if (rc != 0) {
            return rc;
        }
        if (bh.code_len > 65536U || bh.site_count > 512U) {
            return -EBADMSG;
        }
        if (bh.guest_pc_base == guest_pc_base) {
            if (bh.code_len > code_cap || bh.site_count > site_cap) {
                return -EOVERFLOW;
            }
            if (bh.code_len != 0U) {
                rc = read_all(cache_fd, code_out, bh.code_len);
                if (rc != 0) {
                    return rc;
                }
            }
            if (bh.site_count != 0U) {
                rc = read_all(cache_fd, sites_out,
                    (size_t)bh.site_count * sizeof *sites_out);
                if (rc != 0) {
                    return rc;
                }
            }
            if (code_len_out != NULL) {
                *code_len_out = bh.code_len;
            }
            if (site_count_out != NULL) {
                *site_count_out = bh.site_count;
            }
            return 1;
        }
        if (lseek(cache_fd,
            (off_t)bh.code_len +
                (off_t)((size_t)bh.site_count * sizeof *sites_out),
            SEEK_CUR) == (off_t)-1) {
            return -errno;
        }
    }
    return 0;
}
