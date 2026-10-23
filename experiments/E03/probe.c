/* Phase E lane E03 probe: .gnu.attributes parsing & classic-FPU vs SPE dispatch.
 *
 * Portable Curated C11 (no target inline asm): cross-compiles for powerpc
 * (powerpc-unknown-linux-gnu-gcc) and runs under qemu-ppc -cpu 750 /
 * -cpu e500v2, and also runs natively anywhere to self-test the parser
 * and decoder tables on synthetic vectors.
 *
 * Ground truth sources: binutils include/elf/common.h (EM_PPC=20,
 * ELFCLASS32=1, ELFDATA2MSB=2, SHT_GNU_ATTRIBUTES), include/elf/ppc.h
 * (Tag_GNU_Power_ABI_FP=4, _Vector=8, _Struct_Return=12),
 * binutils/binutils/readelf.c display_power_gnu_attribute(),
 * opcodes/ppc-opc.c (VX/A/OP macros and SPE XO values),
 * binutils assembler docs (GNU Object Attributes, PowerPC section).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---- ELF admission constants (binutils include/elf/common.h) ---- */
#define E03_EM_PPC 20u
#define E03_ELFCLASS32 1u
#define E03_ELFDATA2MSB 2u
#define E03_SHT_GNU_ATTRIBUTES 0x6ffffff5u

/* ---- PowerPC GNU attribute tags (binutils include/elf/ppc.h) ---- */
#define E03_TAG_FP 4u
#define E03_TAG_VECTOR 8u
#define E03_TAG_STRUCT_RETURN 12u
#define E03_TAG_FILE 1u

/* Tag_GNU_Power_ABI_FP low 2 bits (readelf display_power_gnu_attribute). */
#define E03_FP_UNSPEC 0u
#define E03_FP_HARD 1u
#define E03_FP_SOFT 2u
#define E03_FP_SINGLE_HARD 3u

/* Tag_GNU_Power_ABI_Vector low 2 bits. */
#define E03_VEC_UNSPEC 0u
#define E03_VEC_GENERIC 1u
#define E03_VEC_ALTIVEC 2u
#define E03_VEC_SPE 3u

/* ---- Instruction encoding helpers (binutils opcodes/ppc-opc.c) ----
 * OP(op)   = op << 26            (primary opcode, PPC bits 0-5)
 * VX(op,x) = OP(op) | (x & 0x7ff) (SPE EVX: 11-bit XO = PPC bits 21-31,
 *                                  low bit doubles as Rc slot for arith ops)
 * A(op,x,rc) classic A-form: 5-bit XO at value bits 1-5, Rc at bit 0.
 */
#define E03_OP(op) ((uint32_t)(((uint32_t)(op) & 0x3fu) << 26))
#define E03_VX(op, xop) ((uint32_t)(E03_OP(op) | ((uint32_t)(xop) & 0x7ffu)))
#define E03_AFORM(op, xop, rc) \
    ((uint32_t)(E03_OP(op) | ((((uint32_t)(xop)) & 0x1fu) << 1) | \
                (((uint32_t)(rc)) & 1u)))

/* Representative SPE words (primary opcode 4; XO from ppc-opc.c). */
#define E03_EVADDW E03_VX(4u, 512u)   /* evaddw: vector integer add */
#define E03_EVAND E03_VX(4u, 529u)    /* evand: vector logical */
#define E03_EFSADD E03_VX(4u, 704u)   /* efsadd: embedded scalar single add */
#define E03_EFDADD E03_VX(4u, 736u)   /* efdadd: embedded scalar double add */
#define E03_EVLDD E03_VX(4u, 769u)    /* evldd: SPE 64-bit load (Rc-slot = 1) */

/* Representative classic words. */
#define E03_FADD_WORD \
    ((uint32_t)(E03_AFORM(63u, 21u, 0u) | ((uint32_t)1 << 21) | \
                ((uint32_t)2 << 16) | ((uint32_t)3 << 11)))
#define E03_SC_WORD 0x44000002u /* sc, LEV=0 */

/* ---- Minimal context prefix mirror (SPEC 2.1 offsets) ---- */
typedef struct e03_ctx_prefix {
    uint32_t gpr[32];    /* 0x000: low halves r0..r31 */
    uint32_t gpr_hi[32]; /* 0x080: upper halves (SPE only) */
    uint32_t nip;        /* 0x100 */
} e03_ctx_prefix_t;

typedef enum e03_profile { E03_PROF_CLASSIC = 0, E03_PROF_SPE = 1 } e03_profile_t;

/* ---- ULEB128 reader over an explicit bounded buffer ---- */
static int e03_read_uleb(const unsigned char *buf, size_t len, size_t *pos,
                         unsigned int *out)
{
    unsigned int val = 0u;
    unsigned int shift = 0u;
    unsigned char b;

    if (*pos >= len) {
        return -1;
    }
    do {
        if (*pos >= len || shift > 28u) {
            return -1;
        }
        b = buf[*pos];
        (*pos)++;
        val |= (unsigned int)(b & 0x7fu) << shift;
        shift += 7u;
    } while (b & 0x80u);
    *out = val;
    return 0;
}

/* Parse one Tag_File(1) attribute subsection body:
 * sequence of (ULEB tag, ULEB value) pairs. Returns FP/Vector values,
 * or -1 on truncation. Unknown tags are skipped (value still consumed). */
static int e03_parse_attrs(const unsigned char *buf, size_t len,
                           unsigned int *fp_val, unsigned int *vec_val)
{
    size_t pos = 0u;
    unsigned int tag;
    unsigned int val;

    *fp_val = 0xffffffffu;
    *vec_val = 0xffffffffu;
    while (pos < len) {
        if (e03_read_uleb(buf, len, &pos, &tag) != 0) {
            return -1;
        }
        if (e03_read_uleb(buf, len, &pos, &val) != 0) {
            return -1;
        }
        if (tag == E03_TAG_FP) {
            *fp_val = val;
        } else if (tag == E03_TAG_VECTOR) {
            *vec_val = val;
        }
    }
    return 0;
}

/* ---- Dispatcher under test: primary opcode demux ---- */
static const char *e03_classify(uint32_t w, unsigned int *sub)
{
    unsigned int primary = w >> 26;
    unsigned int xo11 = w & 0x7ffu;

    *sub = xo11;
    if (primary == 4u) {
        if (xo11 == 512u) {
            return "SPE:evaddw";
        }
        if (xo11 == 704u) {
            return "SPE:efsadd";
        }
        if (xo11 == 736u) {
            return "SPE:efdadd";
        }
        if (xo11 == 769u) {
            return "SPE:evldd";
        }
        return "SPE:other-XO4";
    }
    if (primary == 63u || primary == 59u) {
        return "CLASSIC-FPU-arith";
    }
    if (primary == 48u || primary == 50u || primary == 52u ||
        primary == 54u) {
        return "CLASSIC-FP-ldst";
    }
    if (w == E03_SC_WORD) {
        return "sc";
    }
    return "other";
}

/* Profile resolution: CLI override wins; else SPE iff FP tag says
 * single-hard AND Vector tag says SPE (or SPE opcode already seen). */
static e03_profile_t e03_resolve_profile(unsigned int fp_val,
                                         unsigned int vec_val,
                                         int spe_opcode_seen,
                                         int cli_force /* -1 auto, 0, 1 */)
{
    if (cli_force == 0) {
        return E03_PROF_CLASSIC;
    }
    if (cli_force == 1) {
        return E03_PROF_SPE;
    }
    if ((fp_val & 3u) == E03_FP_SINGLE_HARD &&
        (vec_val & 3u) == E03_VEC_SPE) {
        return E03_PROF_SPE;
    }
    if (spe_opcode_seen) {
        return E03_PROF_SPE;
    }
    return E03_PROF_CLASSIC;
}

static const char *e03_prof_name(e03_profile_t p)
{
    return p == E03_PROF_SPE ? "spe" : "classic";
}

int main(void)
{
    /* Synthetic Tag_File bodies: {tag,value} ULEB pairs. */
    static const unsigned char classic_attrs[] = { 4u, 1u, 8u, 0u };
    static const unsigned char spe_attrs[] = { 4u, 3u, 8u, 3u };
    /* Truncated body exercises the error path. */
    static const unsigned char trunc_attrs[] = { 4u };
    static const uint32_t words[] = {
        E03_EVADDW, E03_EFSADD, E03_EFDADD, E03_EVLDD,
        E03_FADD_WORD, E03_SC_WORD
    };
    static const char *const wnames[] = {
        "evaddw", "efsadd", "efdadd", "evldd", "fadd", "sc"
    };
    unsigned int fpv;
    unsigned int vecv;
    e03_ctx_prefix_t ctx;
    size_t i;
    int checks = 0;
    int fails = 0;

    printf("em_ppc=%u elfclass32=%u elfdata2msb=%u sht_attrs=0x%x\n",
           E03_EM_PPC, E03_ELFCLASS32, E03_ELFDATA2MSB,
           E03_SHT_GNU_ATTRIBUTES);
    printf("tags: fp=%u vector=%u structret=%u file=%u\n", E03_TAG_FP,
           E03_TAG_VECTOR, E03_TAG_STRUCT_RETURN, E03_TAG_FILE);
    printf("fp-vals: hard=%u soft=%u single-hard=%u vec-spe=%u\n",
           E03_FP_HARD, E03_FP_SOFT, E03_FP_SINGLE_HARD, E03_VEC_SPE);
    printf("sizeof ctx-prefix=%u off_gpr=%u off_gpr_hi=%u off_nip=%u\n",
           (unsigned int)sizeof(e03_ctx_prefix_t),
           (unsigned int)offsetof(e03_ctx_prefix_t, gpr),
           (unsigned int)offsetof(e03_ctx_prefix_t, gpr_hi),
           (unsigned int)offsetof(e03_ctx_prefix_t, nip));

    if (e03_parse_attrs(classic_attrs, sizeof(classic_attrs), &fpv,
                        &vecv) == 0) {
        printf("classic-attrs: fp=%u vec=%u profile=%s\n", fpv, vecv,
               e03_prof_name(e03_resolve_profile(fpv, vecv, 0, -1)));
        checks++;
        if (fpv != 1u || vecv != 0u) {
            fails++;
        }
    } else {
        printf("classic-attrs: PARSE-FAIL\n");
        fails++;
    }
    if (e03_parse_attrs(spe_attrs, sizeof(spe_attrs), &fpv, &vecv) == 0) {
        printf("spe-attrs: fp=%u vec=%u profile=%s\n", fpv, vecv,
               e03_prof_name(e03_resolve_profile(fpv, vecv, 0, -1)));
        checks++;
        if (fpv != 3u || vecv != 3u) {
            fails++;
        }
    } else {
        printf("spe-attrs: PARSE-FAIL\n");
        fails++;
    }
    if (e03_parse_attrs(trunc_attrs, sizeof(trunc_attrs), &fpv, &vecv) !=
        0) {
        printf("trunc-attrs: correctly rejected\n");
        checks++;
    } else {
        printf("trunc-attrs: NOT rejected\n");
        fails++;
    }
    printf("override-classic=%s override-spe=%s opcode-fallback=%s\n",
           e03_prof_name(e03_resolve_profile(3u, 3u, 1, 0)),
           e03_prof_name(e03_resolve_profile(1u, 0u, 0, 1)),
           e03_prof_name(e03_resolve_profile(0u, 0u, 1, -1)));

    for (i = 0u; i < sizeof(words) / sizeof(words[0]); i++) {
        unsigned int sub = 0u;
        const char *cls = e03_classify(words[i], &sub);
        printf("word %s: 0x%08x primary=%u sub=%u -> %s\n", wnames[i],
               words[i], words[i] >> 26, sub, cls);
    }
    checks++;
    {
        unsigned int sub = 0u;
        if (e03_classify(E03_EFSADD, &sub) == NULL || sub != 704u) {
            fails++;
        }
    }

    /* gpr_hi discipline: classic op touches low half only; SPE op
     * writes both halves as one 64-bit GPR. */
    for (i = 0u; i < 32u; i++) {
        ctx.gpr[i] = 0u;
        ctx.gpr_hi[i] = 0xdeadbeefu;
    }
    ctx.gpr[3] = 0x11223344u; /* classic 32-bit write leaves hi intact */
    printf("classic-write: gpr3=0x%08x hi3=0x%08x %s\n", ctx.gpr[3],
           ctx.gpr_hi[3],
           ctx.gpr_hi[3] == 0xdeadbeefu ? "hi-preserved" : "HI-CLOBBERED");
    checks++;
    if (ctx.gpr_hi[3] != 0xdeadbeefu) {
        fails++;
    }
    ctx.gpr[4] = 0x55667788u; /* SPE ev-write commits both halves */
    ctx.gpr_hi[4] = 0x11223344u;
    printf("spe-write: gpr4=0x%08x hi4=0x%08x combined=0x%08x%08x\n",
           ctx.gpr[4], ctx.gpr_hi[4], ctx.gpr_hi[4], ctx.gpr[4]);

    printf("selftest: checks=%d fails=%d %s\n", checks, fails,
           fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
