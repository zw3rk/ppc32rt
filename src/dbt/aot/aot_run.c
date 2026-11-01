/*
 * src/dbt/aot/aot_run.c — Persistent AOT block-cache run wiring.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * See aot_run.h. File layout follows aot.h; block_count lives at file
 * offset 16 and is rewritten after every append (append-only, so a
 * crash loses at most the tail). A corrupt header (or profile
 * mismatch) truncates back to a fresh file instead of executing
 * anything from it (mutation rejection, fail-closed).
 */

#define _POSIX_C_SOURCE 200809L

#include "dbt/aot/aot_run.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/aot/aot.h"

#define AOT_RUN_NAME "ppc32-aot.cache"
#define AOT_RUN_CODE_CAP 65552U
/* ppc32_aot_hdr_t layout: magic[8] version block_count profile
 * reserved (all u32 LE); block_count sits at byte offset 12. */
#define AOT_RUN_COUNT_OFF 12U

static int s_fd = -1;
static uint32_t s_blocks = 0U;
static unsigned char *s_code = NULL;
static bool s_ready = false;

static int run_pwrite_count(void)
{
    unsigned char raw[4];

    raw[0] = (unsigned char)(s_blocks & 0xFFU);
    raw[1] = (unsigned char)((s_blocks >> 8) & 0xFFU);
    raw[2] = (unsigned char)((s_blocks >> 16) & 0xFFU);
    raw[3] = (unsigned char)((s_blocks >> 24) & 0xFFU);
    if (pwrite(s_fd, raw, sizeof raw, (off_t)AOT_RUN_COUNT_OFF) !=
        (ssize_t)sizeof raw) {
        return -errno;
    }
    return 0;
}

static int run_init_file(const char *path, uint32_t profile)
{
    ppc32_aot_hdr_t hdr;
    ssize_t n;

    if (path == NULL) {
        return -EINVAL;
    }
    s_fd = open(path, O_RDWR | O_CREAT, 0644);
    if (s_fd < 0) {
        return -errno;
    }
    n = read(s_fd, &hdr, sizeof hdr);
    if (n == (ssize_t)sizeof hdr && ppc32_aot_header_ok(&hdr) &&
        hdr.profile == profile) {
        s_blocks = hdr.block_count;
        s_ready = true;
        return 0;
    }
    /* Fresh or corrupt/profile-mismatched file: re-init in place
     * (a directory path fails open() above, so no ISDIR case here). */
    (void)memset(&hdr, 0, sizeof hdr);
    (void)memcpy(hdr.magic, PPC32_AOT_MAGIC, PPC32_AOT_MAGIC_LEN);
    hdr.version = PPC32_AOT_VERSION;
    hdr.block_count = 0U;
    hdr.profile = profile;
    if (ftruncate(s_fd, 0) != 0 || lseek(s_fd, 0, SEEK_SET) == (off_t)-1) {
        close(s_fd);
        s_fd = -1;
        return -EIO;
    }
    /* Host-order struct write: the cache is host-local and every
     * supported host (aarch64 Linux/Darwin) is little-endian, matching
     * the format. The header is 24 bytes by static assert. */
    if (write(s_fd, &hdr, sizeof hdr) != (ssize_t)sizeof hdr) {
        close(s_fd);
        s_fd = -1;
        return -EIO;
    }
    s_blocks = 0U;
    s_ready = true;
    return 0;
}

static int run_ensure_open(ppc32_ctx_t *ctx)
{
    char path[4096];
    struct stat st;

    if (s_fd >= 0) {
        return 0;
    }
    if (s_ready) {
        return -EBADF;
    }
    s_ready = true;
    if (ctx == NULL || ctx->cache_dir == NULL ||
        ctx->cache_dir[0] == '\0') {
        return -EINVAL;
    }
    if (stat(ctx->cache_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        size_t n = strlen(ctx->cache_dir);

        if (n + 1U + sizeof AOT_RUN_NAME >= sizeof path) {
            return -ENAMETOOLONG;
        }
        (void)memcpy(path, ctx->cache_dir, n);
        path[n] = '/';
        (void)memcpy(path + n + 1U, AOT_RUN_NAME, sizeof AOT_RUN_NAME);
    } else {
        size_t n = strlen(ctx->cache_dir);

        if (n + 1U >= sizeof path) {
            return -ENAMETOOLONG;
        }
        (void)memcpy(path, ctx->cache_dir, n + 1U);
    }
    /* Effective profile: is_spe is authoritative post-load (unset
     * --profile defaults to classic, matching the loader). */
    return run_init_file(path,
        ctx->is_spe ? (uint32_t)PPC32_PROFILE_SPE :
            (uint32_t)PPC32_PROFILE_CLASSIC);
}

void ppc32_aot_note_block(ppc32_ctx_t *ctx, uint32_t guest_pc,
    const void *code, uint32_t code_len)
{
    uint32_t got_len = 0U;
    uint32_t got_sites = 0U;
    int rc;

    if (ctx == NULL || ctx->cache_dir == NULL || code == NULL ||
        code_len == 0U || code_len > 65536U) {
        return;
    }
    if (run_ensure_open(ctx) != 0 || s_fd < 0) {
        return;
    }
    if (s_code == NULL) {
        s_code = (unsigned char *)malloc(AOT_RUN_CODE_CAP);
        if (s_code == NULL) {
            return;
        }
    }
    /* Warm consult: a hit means an earlier run (or an earlier
     * translation in this run) already recorded this block. */
    rc = ppc32_aot_lookup(s_fd, guest_pc, s_code, AOT_RUN_CODE_CAP,
        NULL, 0U, &got_len, &got_sites);
    if (rc == 1) {
        return;
    }
    if (lseek(s_fd, 0, SEEK_END) == (off_t)-1) {
        return;
    }
    if (ppc32_aot_append(s_fd, guest_pc, code, code_len, NULL, 0U) != 0) {
        return;
    }
    s_blocks++;
    (void)run_pwrite_count();
}
