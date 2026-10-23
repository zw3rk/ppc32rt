/* Phase E lane E06 probe: TLS r2 thread pointer & lwarx/stwcx. reservation.
 *
 * Portable Curated C11. Cross-compile for powerpc (classic 750 / e500v2)
 * and run under qemu-ppc -cpu 750 / -cpu e500v2; also builds and runs on
 * the host for the machine-independent self-checks. No VLAs, no
 * sprintf/strcpy/strcat, no <threads.h>, no _Generic.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Linux PPC32 ABI constants (arch/powerpc UAPI + sched.h). */
#define PPC_NR_CLONE 120
#define PPC_NR_SET_TID_ADDRESS 232
#define PPC_CLONE_SETTLS 0x00080000u
#define PPC_SC_ENCODING 0x44000002u

/* X-form encoders: primary opcode 31; lwarx XO=20 Rc=0, stwcx. XO=150 Rc=1. */
static uint32_t enc_lwarx(unsigned rt, unsigned ra, unsigned rb)
{
    return (31u << 26) | ((rt & 31u) << 21) | ((ra & 31u) << 16) |
        ((rb & 31u) << 11) | (20u << 1) | 0u;
}

static uint32_t enc_stwcx(unsigned rs, unsigned ra, unsigned rb)
{
    return (31u << 26) | ((rs & 31u) << 21) | ((ra & 31u) << 16) |
        ((rb & 31u) << 11) | (150u << 1) | 1u;
}

/* Mirror of the SPEC section 2.1 unified context layout (offsets in bytes). */
typedef struct ppc32_ctx_shape {
    uint32_t gpr[32]; /* 0x000 */
    uint32_t gpr_hi[32]; /* 0x080 */
    uint32_t nip; /* 0x100 */
    uint32_t lr; /* 0x104 */
    uint32_t ctr; /* 0x108 */
    uint32_t cr; /* 0x10c */
    uint32_t xer; /* 0x110 */
    uint32_t fpscr; /* 0x114 */
    uint32_t spefscr; /* 0x118 */
    uint32_t pad_11c; /* 0x11c: pad so acc lands on 0x120 */
    uint64_t acc; /* 0x120 */
    uint64_t fpr[32]; /* 0x128 */
    uint64_t guest_base; /* 0x228 */
    uint32_t res_addr; /* 0x230 */
    uint32_t res_val; /* 0x234 */
    uint8_t res_valid; /* 0x238 */
    uint8_t is_spe; /* 0x239 */
} ppc32_ctx_shape;

_Static_assert(offsetof(ppc32_ctx_shape, gpr) == 0x000, "gpr");
_Static_assert(offsetof(ppc32_ctx_shape, gpr_hi) == 0x080, "gpr_hi");
_Static_assert(offsetof(ppc32_ctx_shape, nip) == 0x100, "nip");
_Static_assert(offsetof(ppc32_ctx_shape, acc) == 0x120, "acc");
_Static_assert(offsetof(ppc32_ctx_shape, fpr) == 0x128, "fpr");
_Static_assert(offsetof(ppc32_ctx_shape, guest_base) == 0x228, "G");
_Static_assert(offsetof(ppc32_ctx_shape, res_addr) == 0x230, "res_addr");
_Static_assert(offsetof(ppc32_ctx_shape, res_val) == 0x234, "res_val");
_Static_assert(offsetof(ppc32_ctx_shape, res_valid) == 0x238, "res_valid");
_Static_assert(offsetof(ppc32_ctx_shape, is_spe) == 0x239, "is_spe");

/* Minimal translator reservation model: single global {word EA, valid}. */
typedef struct res_state {
    uint32_t addr;
    uint8_t valid;
} res_state;

static void res_grant(res_state *r, uint32_t ea)
{
    r->addr = ea & ~3u;
    r->valid = 1;
}

static int res_stwcx(res_state *r, uint32_t ea)
{
    int ok = (r->valid != 0) && (r->addr == (ea & ~3u));
    r->valid = 0; /* any executed stwcx. consumes the reservation */
    return ok;
}

static void res_invalidate(res_state *r)
{
    r->valid = 0;
}

static uint32_t read_r2(void)
{
#if defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC)
    uint32_t v = 0u;
    __asm__ volatile ("mr %0, 2" : "=r" (v));
    return v;
#else
    return 0u; /* non-PPC host: r2 read not applicable */
#endif
}

int main(void)
{
    unsigned fails = 0u;
    res_state r;
    r.addr = 0u;
    r.valid = 0;

    printf("lwarx r4,r3,r5  = 0x%08x (expect 0x7c832828)\n", enc_lwarx(4u, 3u, 5u));
    printf("stwcx. r4,r3,r5 = 0x%08x (expect 0x7c83292d)\n", enc_stwcx(4u, 3u, 5u));
    printf("sc              = 0x%08x\n", (unsigned)PPC_SC_ENCODING);
    printf("CLONE_SETTLS    = 0x%08x\n", (unsigned)PPC_CLONE_SETTLS);
    printf("NR_clone(ppc)   = %d\n", PPC_NR_CLONE);
    printf("NR_set_tid_address(ppc) = %d\n", PPC_NR_SET_TID_ADDRESS);
    printf("sizeof(ctx)     = %u\n", (unsigned)sizeof(ppc32_ctx_shape));
    printf("off guest_base  = 0x%x\n", (unsigned)offsetof(ppc32_ctx_shape, guest_base));
    printf("off res_addr    = 0x%x\n", (unsigned)offsetof(ppc32_ctx_shape, res_addr));
    printf("off res_valid   = 0x%x\n", (unsigned)offsetof(ppc32_ctx_shape, res_valid));
    printf("r2              = 0x%08x\n", read_r2());

    if (enc_lwarx(4u, 3u, 5u) != 0x7c832828u) {
        printf("FAIL lwarx encoding\n");
        fails++;
    }
    if (enc_stwcx(4u, 3u, 5u) != 0x7c83292du) {
        printf("FAIL stwcx encoding\n");
        fails++;
    }

    /* Grant then succeed once; reservation is consumed. */
    res_grant(&r, 0x1000u);
    if (!res_stwcx(&r, 0x1000u)) {
        printf("FAIL first stwcx should succeed\n");
        fails++;
    }
    if (res_stwcx(&r, 0x1000u)) {
        printf("FAIL second stwcx must fail (consumed)\n");
        fails++;
    }

    /* Syscall/signal/thread-switch invalidation forces failure + retry. */
    res_grant(&r, 0x2000u);
    res_invalidate(&r);
    if (res_stwcx(&r, 0x2000u)) {
        printf("FAIL stwcx after invalidate must fail\n");
        fails++;
    }

    /* A newer lwarx overwrites the older grant. */
    res_grant(&r, 0x3000u);
    res_grant(&r, 0x4000u);
    if (res_stwcx(&r, 0x3000u)) {
        printf("FAIL stale address must fail after re-grant\n");
        fails++;
    }
    res_grant(&r, 0x4000u);
    if (!res_stwcx(&r, 0x4002u)) {
        printf("FAIL same-word alias must succeed\n");
        fails++;
    }

    printf(fails == 0u ? "E06-SELFCHECK PASS\n" : "E06-SELFCHECK FAIL %u\n", fails);
    return fails == 0u ? 0 : 1;
}
