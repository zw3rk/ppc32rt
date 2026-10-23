/* Phase E lane E05 probe: big-endian string/multiple/byte-reverse loads.
 *
 * Pure Curated C11 model of PowerPC Book I lmw/stmw, lswi/stswi,
 * lhbrx/lwbrx/sthbrx/stwbrx semantics plus instruction-encoding helpers.
 * Compiles for the host (native check) and cross-compiles for powerpc;
 * the same vectors run under qemu-ppc -cpu 750 / -cpu e500v2.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* D-form: op(6) | RT(5) | RA(5) | D(16). Used by lmw (op 46), stmw (op 47). */
static uint32_t enc_dform(unsigned op, unsigned rt, unsigned ra, uint16_t d)
{
    return ((uint32_t)op << 26) | ((uint32_t)(rt & 31u) << 21) |
        ((uint32_t)(ra & 31u) << 16) | (uint32_t)d;
}

/* X-form, Rc=0: op31 | RT | RA | RB | XO(10) | 0. lswi=597, stswi=725,
 * lhbrx=790, lwbrx=534, sthbrx=918, stwbrx=662. For lswi/stswi the RB
 * field carries NB (0 means 32). */
static uint32_t enc_xform(unsigned rt, unsigned ra, unsigned rb, unsigned xo)
{
    return ((uint32_t)31u << 26) | ((uint32_t)(rt & 31u) << 21) |
        ((uint32_t)(ra & 31u) << 16) | ((uint32_t)(rb & 31u) << 11) |
        ((uint32_t)(xo & 1023u) << 1);
}

static uint32_t be_ld32(const uint8_t *m)
{
    return ((uint32_t)m[0] << 24) | ((uint32_t)m[1] << 16) |
        ((uint32_t)m[2] << 8) | (uint32_t)m[3];
}

static void be_st32(uint8_t *m, uint32_t v)
{
    m[0] = (uint8_t)(v >> 24);
    m[1] = (uint8_t)(v >> 16);
    m[2] = (uint8_t)(v >> 8);
    m[3] = (uint8_t)v;
}

static uint32_t rev32(uint32_t v)
{
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
        ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* lmw model: load r[rd]..r[31] as consecutive big-endian words. */
static void model_lmw(uint32_t *gpr, unsigned rd, const uint8_t *mem)
{
    unsigned r;
    for (r = rd; r < 32u; r++) {
        gpr[r] = be_ld32(mem + (r - rd) * 4u);
    }
}

/* stmw model: store r[rs]..r[31] as consecutive big-endian words. */
static void model_stmw(const uint32_t *gpr, unsigned rs, uint8_t *mem)
{
    unsigned r;
    for (r = rs; r < 32u; r++) {
        be_st32(mem + (r - rs) * 4u, gpr[r]);
    }
}

/* lswi model: NB==0 means 32 bytes; bytes fill registers MSB-first,
 * wrapping the register index mod 32 (ANALYTICAL: wrap pending qemu).
 * Trailing bytes of a partial last register are left untouched here;
 * qemu decides zero-vs-preserve (ANALYTICAL). */
static void model_lswi(uint32_t *gpr, unsigned rt, unsigned ra_nb0,
    const uint8_t *mem, unsigned nb)
{
    uint32_t n = (nb == 0u) ? 32u : nb;
    uint32_t i;
    (void)ra_nb0;
    for (i = 0; i < n; i++) {
        unsigned reg = (rt + (i >> 2)) & 31u;
        unsigned shift = 24u - ((i & 3u) * 8u);
        gpr[reg] = (gpr[reg] & ~((uint32_t)0xFFu << shift)) |
            ((uint32_t)mem[i] << shift);
    }
}

/* Mirror of the SPEC section 2.1 context prefix (offsets must match). */
struct ctx_prefix {
    uint32_t gpr[32];
    uint32_t gpr_hi[32];
    uint32_t nip;
    uint32_t lr;
    uint32_t ctr;
    uint32_t cr;
    uint32_t xer;
    uint32_t fpscr;
    uint32_t spefscr;
    uint64_t acc;
    uint64_t fpr[32];
};

static int fails = 0;

static void check_enc(const char *name, uint32_t got, uint32_t want)
{
    printf("%-18s = 0x%08X (want 0x%08X) %s\n", name, got, want,
        got == want ? "ok" : "MISMATCH");
    if (got != want) {
        fails++;
    }
}

int main(void)
{
    /* Canonical encoding vectors (Book I opcode/XO arithmetic). */
    check_enc("lmw r5,8(r6)", enc_dform(46u, 5u, 6u, 8u), 0xB8A60008u);
    check_enc("stmw r5,8(r6)", enc_dform(47u, 5u, 6u, 8u), 0xBCA60008u);
    check_enc("lmw r0,0(r0)", enc_dform(46u, 0u, 0u, 0u), 0xB8000000u);
    check_enc("lswi r4,r5,3", enc_xform(4u, 5u, 3u, 597u), 0x7C851CAAu);
    check_enc("stswi r4,r5,3", enc_xform(4u, 5u, 3u, 725u), 0x7C851DAAu);
    check_enc("lswi r4,r5,0", enc_xform(4u, 5u, 0u, 597u), 0x7C8504AAu);
    check_enc("lwbrx r3,0,r4", enc_xform(3u, 0u, 4u, 534u), 0x7C60242Cu);
    check_enc("lhbrx r4,r5,r6", enc_xform(4u, 5u, 6u, 790u), 0x7C85362Cu);
    check_enc("sthbrx r4,r5,r6", enc_xform(4u, 5u, 6u, 918u), 0x7C85372Cu);
    check_enc("stwbrx r4,r5,r6", enc_xform(4u, 5u, 6u, 662u), 0x7C85352Cu);

    /* Byte-order ground truth on a fixed vector. */
    {
        static const uint8_t mem[8] = { 0x00u, 0x11u, 0x22u, 0x33u, 0x44u,
            0x55u, 0x66u, 0x77u };
        uint32_t norm = be_ld32(mem);
        uint32_t brx = rev32(norm);
        uint32_t hbrx = ((uint32_t)mem[1] << 8) | (uint32_t)mem[0];
        uint32_t gpr[32] = { 0 };
        uint8_t out[8] = { 0 };
        printf("lwz  model = 0x%08X (want 0x00112233)\n", norm);
        printf("lwbrx model = 0x%08X (want 0x33221100)\n", brx);
        printf("lhbrx model = 0x%08X (want 0x00001100)\n", hbrx);
        if (norm != 0x00112233u || brx != 0x33221100u || hbrx != 0x00001100u) {
            fails++;
        }
        model_lmw(gpr, 30u, mem);
        printf("lmw r30..r31 = 0x%08X 0x%08X (want 0x00112233 0x44556677)\n",
            gpr[30], gpr[31]);
        if (gpr[30] != 0x00112233u || gpr[31] != 0x44556677u) {
            fails++;
        }
        gpr[30] = 0xAABBCCDDu;
        gpr[31] = 0x11223344u;
        model_stmw(gpr, 30u, out);
        printf("stmw bytes = %02X %02X %02X %02X %02X %02X %02X %02X\n",
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
        if (out[0] != 0xAAu || out[3] != 0xDDu || out[4] != 0x11u ||
            out[7] != 0x44u) {
            fails++;
        }
        /* lswi n=5: r4 full word, top byte of r5; r5 low 3 bytes kept. */
        {
            uint32_t r[32] = { 0 };
            r[5] = 0x00FFFFFFu;
            model_lswi(r, 4u, 0u, mem, 5u);
            printf("lswi n=5: r4=0x%08X r5=0x%08X\n", r[4], r[5]);
            if (r[4] != 0x00112233u || (r[5] >> 24) != 0x44u) {
                fails++;
            }
        }
        /* lswi NB=0 loads 32 bytes -> r4..r11. */
        {
            uint8_t big[32];
            uint32_t r[32] = { 0 };
            unsigned i;
            for (i = 0; i < 32u; i++) {
                big[i] = (uint8_t)i;
            }
            model_lswi(r, 4u, 0u, big, 0u);
            printf("lswi n=0: r4=0x%08X r11=0x%08X (want 0x00010203 0x1C1D1E1F)\n",
                r[4], r[11]);
            if (r[4] != 0x00010203u || r[11] != 0x1C1D1E1Fu) {
                fails++;
            }
        }
    }

    printf("sizeof(ctx_prefix)=0x%lX (want 0x228)\n",
        (unsigned long)sizeof(struct ctx_prefix));
    printf("offsetof(nip)=0x%lX offsetof(acc)=0x%lX offsetof(fpr)=0x%lX\n",
        (unsigned long)offsetof(struct ctx_prefix, nip),
        (unsigned long)offsetof(struct ctx_prefix, acc),
        (unsigned long)offsetof(struct ctx_prefix, fpr));
    if (sizeof(struct ctx_prefix) != 0x228u ||
        offsetof(struct ctx_prefix, nip) != 0x100u ||
        offsetof(struct ctx_prefix, acc) != 0x120u ||
        offsetof(struct ctx_prefix, fpr) != 0x128u) {
        fails++;
    }
    /* gpr_hi overlay note: evr[32] lives at 0x80 in the full context. */
    printf("offsetof(gpr_hi)=0x%lX (want 0x80)\n",
        (unsigned long)offsetof(struct ctx_prefix, gpr_hi));
    if (offsetof(struct ctx_prefix, gpr_hi) != 0x80u) {
        fails++;
    }

    printf(fails == 0 ? "E05 probe: ALL OK\n" : "E05 probe: %d FAILURES\n",
        fails);
    return fails != 0;
}
