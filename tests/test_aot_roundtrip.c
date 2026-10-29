/*
 * tests/test_aot_roundtrip.c — host-native AOT block-cache round-trip check.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the persistent AOT block cache (src/dbt/aot/aot_cache.c)
 * through its public API only: a hand-written file header carrying
 * PPC32_AOT_MAGIC plus one appended block (code + relative site table)
 * reads back byte-identical through ppc32_aot_lookup (hit returns 1);
 * an unknown guest PC misses (returns 0); undersized caller buffers
 * fail closed (-EOVERFLOW); a magic-corrupted copy fails header
 * validation and lookup (-EBADMSG). Prints AOT-ROUNDTRIP: PASS.
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_aot_roundtrip.c \
 *     src/dbt/aot/aot_cache.c -o /tmp/test_aot_roundtrip && \
 *     /tmp/test_aot_roundtrip
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dbt/aot/aot.h"

static int failures = 0;

static void expect(int cond, const char *what)
{
    if (cond == 0) {
        printf("AOT-ROUNDTRIP FAIL: %s\n", what);
        failures++;
    }
}

static int write_all(int fd, const void *buf, size_t len)
{
    size_t done = 0u;
    while (done < len) {
        ssize_t r = write(fd, (const char *)buf + done, len - done);
        if (r <= 0) {
            return -EIO;
        }
        done += (size_t)r;
    }
    return 0;
}

int main(void)
{
    char path[64];
    char bad_path[80];
    ppc32_aot_hdr_t hdr;
    vm32_mem_site_t sites[2];
    vm32_mem_site_t sites_out[2];
    uint8_t code_out[16];
    uint32_t code_len = 0u;
    uint32_t site_count = 0u;
    int fd;
    static const uint8_t code[12] = {
        0xDEu, 0xADu, 0xBEu, 0xEFu, 0x01u, 0x02u,
        0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u
    };

    (void)memset(&hdr, 0, sizeof hdr);
    (void)memcpy(hdr.magic, PPC32_AOT_MAGIC, PPC32_AOT_MAGIC_LEN);
    hdr.version = PPC32_AOT_VERSION;
    hdr.block_count = 1u;
    hdr.profile = 0u;
    hdr.reserved = 0u;
    expect(ppc32_aot_header_ok(&hdr), "hand-built header validates");
    hdr.version = PPC32_AOT_VERSION + 1u;
    expect(!ppc32_aot_header_ok(&hdr), "wrong version rejected");
    expect(!ppc32_aot_header_ok(NULL), "NULL header rejected");
    hdr.version = PPC32_AOT_VERSION;

    (void)memset(sites, 0, sizeof sites);
    sites[0].guest_pc_delta = 4u;
    sites[0].insn_word = 0x7C000214u;
    sites[0].width = 4u;
    sites[1].guest_pc_delta = 8u;
    sites[1].insn_word = 0x4800000Cu;
    sites[1].width = 4u;

    (void)snprintf(path, sizeof path, "/tmp/ppc32-aot-%ld.bin",
        (long)getpid());
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    expect(fd >= 0, "create cache file");
    expect(write_all(fd, &hdr, sizeof hdr) == 0, "write file header");
    expect(ppc32_aot_append(fd, 0x10000100u, code, (uint32_t)sizeof code,
        sites, 2u) == 0, "append block");
    expect(ppc32_aot_append(fd, 0x10000200u, NULL, 0u, NULL, 0u) == 0,
        "append empty block");
    expect(ppc32_aot_append(-1, 0u, code, (uint32_t)sizeof code,
        sites, 2u) == -EINVAL, "append bad fd rejected");

    (void)memset(code_out, 0, sizeof code_out);
    (void)memset(sites_out, 0, sizeof sites_out);
    expect(ppc32_aot_lookup(fd, 0x10000100u, code_out, sizeof code_out,
        sites_out, 2u, &code_len, &site_count) == 1, "lookup hit");
    expect(code_len == sizeof code && site_count == 2u,
        "lookup lengths match");
    expect(memcmp(code_out, code, sizeof code) == 0,
        "lookup code byte-identical");
    expect(memcmp(sites_out, sites, sizeof sites) == 0,
        "lookup sites byte-identical");
    expect(ppc32_aot_lookup(fd, 0xDEAD0000u, code_out, sizeof code_out,
        sites_out, 2u, &code_len, &site_count) == 0, "lookup miss -> 0");
    expect(ppc32_aot_lookup(fd, 0x10000100u, code_out, 4u,
        sites_out, 2u, &code_len, &site_count) == -EOVERFLOW,
        "short code buffer -> -EOVERFLOW");
    (void)close(fd);

    (void)snprintf(bad_path, sizeof bad_path, "%s-bad", path);
    {
        uint8_t buf[512];
        ssize_t n;
        int src = open(path, O_RDONLY);
        int dst;
        expect(src >= 0, "reopen for corrupt copy");
        n = read(src, buf, sizeof buf);
        (void)close(src);
        expect(n > 16, "cache file big enough to corrupt");
        buf[0] ^= 0xFFu;
        dst = open(bad_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        expect(dst >= 0 && write_all(dst, buf, (size_t)n) == 0,
            "write bad-magic copy");
        if (dst >= 0) {
            int rc;
            (void)memset(code_out, 0, sizeof code_out);
            rc = ppc32_aot_lookup(dst, 0x10000100u, code_out,
                sizeof code_out, sites_out, 2u, &code_len, &site_count);
            expect(rc == -EBADMSG, "bad magic lookup fails closed");
            (void)close(dst);
        }
    }

    (void)unlink(path);
    (void)unlink(bad_path);

    if (failures == 0) {
        printf("AOT-ROUNDTRIP: PASS\n");
        return 0;
    }
    printf("AOT-ROUNDTRIP: FAIL (%d)\n", failures);
    return 1;
}
