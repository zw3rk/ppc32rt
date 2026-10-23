/*
 * Phase E lane E02 probe: rotate-and-mask wrap-around (MB > ME) & XER.CA.
 *
 * Reference C11 model of rlwinm / rlwimi / rlwnm mask generation (including
 * MB > ME wrap), sraw / srawi with XER[CA], addc / addze / subfc / subfze
 * carry propagation, and Rc=1 CR0 update. Every vector carries a hardcoded
 * expected value so a run gates itself (nonzero exit on mismatch).
 *
 * Build/powerpc: cross-compile for 32-bit PowerPC and run under
 *   qemu-ppc -cpu 750   and   qemu-ppc -cpu e500v2.
 * On a PowerPC target (__powerpc__) the probe additionally executes the real
 * instructions through inline asm and compares against model + expected.
 * On any other host only the model self-check runs.
 *
 * Curated C11: -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror clean.
 * No VLAs, no Annex K, no sprintf/strcpy/strcat, no <threads.h>.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* XER bit masks, IBM MSB-0 numbering (Book I). CA/SO corroborated against
 * QEMU target/ppc/cpu.h (XER_CA=29 -> 0x20000000) and Linux SPRN_XER=1. */
#define E02_XER_SO (0x80000000U)
#define E02_XER_OV (0x40000000U)
#define E02_XER_CA (0x20000000U)

/* CR0 occupies CR bits 0..3: LT=0x80000000 GT=0x40000000 EQ=0x20000000
 * SO=0x10000000 (matches SPEC section 2.3 CR0.SO error convention). */
#define E02_CR0_LT (0x80000000U)
#define E02_CR0_GT (0x40000000U)
#define E02_CR0_EQ (0x20000000U)
#define E02_CR0_SO (0x10000000U)

/* Minimal XER/CR carrier; layout printed via sizeof/offsetof below. */
struct e02_xer_state {
	uint32_t xer;
	uint32_t cr;
	uint32_t nip;
};

static uint32_t e02_rotl32(uint32_t v, unsigned sh)
{
	sh &= 31U;
	if (sh == 0U) {
		return v;
	}
	return (uint32_t)((v << sh) | (v >> (32U - sh)));
}

/*
 * Book I MASK(MB,ME): 1-bits for IBM bit numbers MB..ME; wraps when MB>ME.
 * ml = [MB,31], mh = [ME+1,31]; MB<=ME gives ml^mh, MB>ME gives ~(ml^mh).
 */
static uint32_t e02_mask32(unsigned mb, unsigned me)
{
	uint32_t ml = (mb == 0U) ? 0xFFFFFFFFU : (0xFFFFFFFFU >> mb);
	uint32_t mh = (me >= 31U) ? 0U : (0xFFFFFFFFU >> (me + 1U));
	uint32_t x = (uint32_t)(ml ^ mh);
	if (mb <= me) {
		return x;
	}
	return (uint32_t)~x;
}

static uint32_t e02_rlwinm(uint32_t rs, unsigned sh, unsigned mb, unsigned me)
{
	return (uint32_t)(e02_rotl32(rs, sh) & e02_mask32(mb, me));
}

static uint32_t e02_rlwimi(uint32_t ra, uint32_t rs, unsigned sh, unsigned mb,
    unsigned me)
{
	uint32_t mask = e02_mask32(mb, me);
	return (uint32_t)((e02_rotl32(rs, sh) & mask) | (ra & (uint32_t)~mask));
}

static uint32_t e02_rlwnm(uint32_t rs, uint32_t rb, unsigned mb, unsigned me)
{
	return (uint32_t)(e02_rotl32(rs, (unsigned)(rb & 31U)) &
	    e02_mask32(mb, me));
}

/* addc: rd = a + b; CA = carry out. */
static uint32_t e02_addc(uint32_t a, uint32_t b, uint32_t *ca_out)
{
	uint64_t sum = (uint64_t)a + (uint64_t)b;
	*ca_out = (uint32_t)(sum >> 32);
	return (uint32_t)sum;
}

/* addze: rd = ra + CA. */
static uint32_t e02_addze(uint32_t ra, uint32_t ca_in, uint32_t *ca_out)
{
	uint64_t sum = (uint64_t)ra + (uint64_t)(ca_in & 1U);
	*ca_out = (uint32_t)(sum >> 32);
	return (uint32_t)sum;
}

/* subfc rD,rA,rB: rd = rb - ra; CA = 1 iff no borrow (rb >= ra). */
static uint32_t e02_subfc(uint32_t ra, uint32_t rb, uint32_t *ca_out)
{
	*ca_out = (rb >= ra) ? 1U : 0U;
	return (uint32_t)((uint64_t)rb - (uint64_t)ra);
}

/* subfze rD,rA: rd = ~ra + CA. */
static uint32_t e02_subfze(uint32_t ra, uint32_t ca_in, uint32_t *ca_out)
{
	uint64_t sum = (uint64_t)(uint32_t)~ra + (uint64_t)(ca_in & 1U);
	*ca_out = (uint32_t)(sum >> 32);
	return (uint32_t)sum;
}

/* Low-n-bits mask of the bits a right shift by n drops (n in 1..31). */
static uint32_t e02_dropped(uint32_t rs, unsigned n)
{
	if (n == 0U) {
		return 0U;
	}
	if (n >= 32U) {
		return rs;
	}
	return (uint32_t)(rs & (0xFFFFFFFFU >> (32U - n)));
}

/*
 * srawi oracle rule (QEMU trans_SRAWI, the SPEC ground-truth oracle):
 * SH=0 copies RS and CLEARS CA; SH>0 sets CA iff RS is negative and any
 * dropped low bit is 1. Vectors S5/S6 pin the SH=0 clearing behavior.
 */
static uint32_t e02_srawi(uint32_t rs, unsigned sh, uint32_t *ca_out)
{
	int32_t s = (int32_t)rs;
	sh &= 31U;
	if (sh == 0U) {
		*ca_out = 0U;
		return rs;
	}
	*ca_out = ((s < 0) && (e02_dropped(rs, sh) != 0U)) ? 1U : 0U;
	return (uint32_t)(s >> sh);
}

/*
 * sraw oracle rule (QEMU helper_SRAW): n = RB & 0x3F; n >= 32 saturates to
 * sign extension with CA = (result != 0); n == 0 copies RS and CLEARS CA;
 * else CA iff RS negative and any dropped bit is 1.
 */
static uint32_t e02_sraw(uint32_t rs, uint32_t rb, uint32_t *ca_out)
{
	unsigned n = (unsigned)(rb & 63U);
	int32_t s = (int32_t)rs;
	if (n >= 32U) {
		*ca_out = (s < 0) ? 1U : 0U;
		return (s < 0) ? 0xFFFFFFFFU : 0U;
	}
	if (n == 0U) {
		*ca_out = 0U;
		return rs;
	}
	*ca_out = ((s < 0) && (e02_dropped(rs, n) != 0U)) ? 1U : 0U;
	return (uint32_t)(s >> n);
}

/* Rc=1: CR0 = [LT,GT,EQ,SO<-XER.SO]. */
static uint32_t e02_cr0_of(uint32_t rd, uint32_t xer)
{
	uint32_t cr0 = 0U;
	int32_t s = (int32_t)rd;
	if (s < 0) {
		cr0 |= E02_CR0_LT;
	} else if (s > 0) {
		cr0 |= E02_CR0_GT;
	} else {
		cr0 |= E02_CR0_EQ;
	}
	if ((xer & E02_XER_SO) != 0U) {
		cr0 |= E02_CR0_SO;
	}
	return cr0;
}

/* M-form encoding: rlwinm PO=21, rlwimi PO=20, rlwnm PO=23. */
static uint32_t e02_enc_m(unsigned po, unsigned rs, unsigned ra, unsigned sh,
    unsigned mb, unsigned me, unsigned rc)
{
	return (uint32_t)(((po & 63U) << 26) | ((rs & 31U) << 21) |
	    ((ra & 31U) << 16) | ((sh & 31U) << 11) | ((mb & 31U) << 6) |
	    ((me & 31U) << 1) | (rc & 1U));
}

/* XO-form encoding: PO=31, OE bit 10, XO bits 1..10. */
static uint32_t e02_enc_xo(unsigned rt, unsigned ra, unsigned rb, unsigned oe,
    unsigned xo, unsigned rc)
{
	return (uint32_t)(((31U) << 26) | ((rt & 31U) << 21) |
	    ((ra & 31U) << 16) | ((rb & 31U) << 11) | ((oe & 1U) << 10) |
	    ((xo & 1023U) << 1) | (rc & 1U));
}

static int e02_fails = 0;

static void e02_check(const char *name, uint32_t got, uint32_t want)
{
	if (got == want) {
		(void)printf("PASS %-12s got=0x%08" PRIX32 "\n", name, got);
	} else {
		(void)printf("FAIL %-12s got=0x%08" PRIX32 " want=0x%08" PRIX32
		    "\n", name, got, want);
		e02_fails++;
	}
}

#if defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC)
/* Target-only execution of real instructions (fixed vectors; SH/MB/ME are
 * assembler immediates, so each vector is its own mnemonic). */
static uint32_t e02_hw_rlwinm_bext(uint32_t rs)
{
	uint32_t rd = 0U;
	__asm__ volatile ("rlwinm %0,%1,24,24,31" : "=r" (rd) : "r" (rs));
	return rd;
}
#endif

int main(void)
{
	uint32_t ca = 0U;
	uint32_t r = 0U;

	(void)printf("E02 rotate-mask/XER.CA probe (sizeof state=%u)\n",
	    (unsigned)sizeof(struct e02_xer_state));
	(void)printf("off xer=%u cr=%u nip=%u\n",
	    (unsigned)offsetof(struct e02_xer_state, xer),
	    (unsigned)offsetof(struct e02_xer_state, cr),
	    (unsigned)offsetof(struct e02_xer_state, nip));

	/* Encodings printed from the formulae for objdump cross-check. */
	(void)printf("enc rlwinm r3,r4,0,0,31  =0x%08" PRIX32 "\n",
	    e02_enc_m(21U, 4U, 3U, 0U, 0U, 31U, 0U));
	(void)printf("enc rlwinm r3,r4,24,24,31=0x%08" PRIX32 "\n",
	    e02_enc_m(21U, 4U, 3U, 24U, 24U, 31U, 0U));
	(void)printf("enc rlwimi r3,r4,0,24,31 =0x%08" PRIX32 "\n",
	    e02_enc_m(20U, 4U, 3U, 0U, 24U, 31U, 0U));
	(void)printf("enc rlwnm  r3,r4,r5,0,31 =0x%08" PRIX32 "\n",
	    e02_enc_m(23U, 4U, 3U, 5U, 0U, 31U, 0U));
	(void)printf("enc sraw   r3,r4,r5      =0x%08" PRIX32 "\n",
	    e02_enc_xo(4U, 3U, 5U, 0U, 792U, 0U));
	(void)printf("enc srawi  r3,r4,1       =0x%08" PRIX32 "\n",
	    e02_enc_xo(4U, 3U, 1U, 0U, 824U, 0U));
	(void)printf("enc addc   r3,r4,r5      =0x%08" PRIX32 "\n",
	    e02_enc_xo(3U, 4U, 5U, 0U, 10U, 0U));
	(void)printf("enc addze  r3,r4         =0x%08" PRIX32 "\n",
	    e02_enc_xo(3U, 4U, 0U, 0U, 202U, 0U));
	(void)printf("enc subfc  r3,r4,r5      =0x%08" PRIX32 "\n",
	    e02_enc_xo(3U, 4U, 5U, 0U, 8U, 0U));
	(void)printf("enc subfze r3,r4         =0x%08" PRIX32 "\n",
	    e02_enc_xo(3U, 4U, 0U, 0U, 200U, 0U));

	/* Mask spot checks incl. wrap-around. */
	e02_check("mask0-31", e02_mask32(0U, 31U), 0xFFFFFFFFU);
	e02_check("mask8-31", e02_mask32(8U, 31U), 0x00FFFFFFU);
	e02_check("mask0-0", e02_mask32(0U, 0U), 0x80000000U);
	e02_check("mask31-31", e02_mask32(31U, 31U), 0x00000001U);
	e02_check("mask24-7w", e02_mask32(24U, 7U), 0xFF0000FFU);
	e02_check("mask16-15w", e02_mask32(16U, 15U), 0xFFFFFFFFU);

	/* rlwinm vectors. */
	e02_check("R1.ident", e02_rlwinm(0x12345678U, 0U, 0U, 31U), 0x12345678U);
	e02_check("R2.alls", e02_rlwinm(0xFFFFFFFFU, 8U, 0U, 31U), 0xFFFFFFFFU);
	e02_check("R3.rot1", e02_rlwinm(0x80000001U, 1U, 0U, 31U), 0x00000003U);
	e02_check("R4.bext", e02_rlwinm(0x12345678U, 24U, 24U, 31U), 0x00000056U);
	e02_check("R5.wrapf", e02_rlwinm(0xA5A5A5A5U, 0U, 16U, 15U), 0xA5A5A5A5U);
	e02_check("R6.wrapp", e02_rlwinm(0x12345678U, 0U, 24U, 7U), 0x12000078U);
	e02_check("R7.bit0", e02_rlwinm(0xFFFFFFFFU, 0U, 0U, 0U), 0x80000000U);
	e02_check("R8.clr8", e02_rlwinm(0xFFFFFFFFU, 0U, 8U, 31U), 0x00FFFFFFU);

	/* rlwimi vectors. */
	e02_check("I1.ins8", e02_rlwimi(0xFFFFFF00U, 0xABU, 0U, 24U, 31U),
	    0xFFFFFFABU);
	e02_check("I2.insw", e02_rlwimi(0x00000000U, 0xFFFFFFFFU, 0U, 24U, 7U),
	    0xFF0000FFU);
	e02_check("I3.clear", e02_rlwimi(0x12345678U, 0U, 0U, 0U, 31U),
	    0x00000000U);

	/* rlwnm vectors (n = RB & 0x1F). */
	e02_check("N1.sh1", e02_rlwnm(0x00000001U, 1U, 0U, 31U), 0x00000002U);
	e02_check("N2.sh4", e02_rlwnm(0x80000000U, 4U, 0U, 31U), 0x00000008U);
	e02_check("N3.n32", e02_rlwnm(0xDEADBEEFU, 0x20U, 0U, 31U), 0xDEADBEEFU);

	/* srawi vectors (CA needs a dropped 1-bit, not just a negative RS). */
	r = e02_srawi(0x80000000U, 1U, &ca);
	e02_check("S1.rd", r, 0xC0000000U);
	e02_check("S1.ca", ca, 0U);
	r = e02_srawi(0x80000001U, 1U, &ca);
	e02_check("S1b.rd", r, 0xC0000000U);
	e02_check("S1b.ca", ca, 1U);
	r = e02_srawi(0x40000000U, 1U, &ca);
	e02_check("S2.rd", r, 0x20000000U);
	e02_check("S2.ca", ca, 0U);
	r = e02_srawi(0x80000001U, 31U, &ca);
	e02_check("S3.rd", r, 0xFFFFFFFFU);
	e02_check("S3.ca", ca, 1U);
	r = e02_srawi(0x7FFFFFFFU, 31U, &ca);
	e02_check("S4.rd", r, 0x00000000U);
	e02_check("S4.ca", ca, 0U);
	r = e02_srawi(0x80000000U, 0U, &ca);
	e02_check("S5.rd", r, 0x80000000U);
	e02_check("S5.ca", ca, 0U);
	r = e02_srawi(0x40000000U, 0U, &ca);
	e02_check("S6.rd", r, 0x40000000U);
	e02_check("S6.ca", ca, 0U);

	/* sraw vectors. */
	r = e02_sraw(0x80000000U, 1U, &ca);
	e02_check("W1.rd", r, 0xC0000000U);
	e02_check("W1.ca", ca, 0U);
	r = e02_sraw(0x80000001U, 1U, &ca);
	e02_check("W1b.rd", r, 0xC0000000U);
	e02_check("W1b.ca", ca, 1U);
	r = e02_sraw(0x80000000U, 32U, &ca);
	e02_check("W2.rd", r, 0xFFFFFFFFU);
	e02_check("W2.ca", ca, 1U);
	r = e02_sraw(0x80000005U, 0U, &ca);
	e02_check("W3.rd", r, 0x80000005U);
	e02_check("W3.ca", ca, 0U);
	r = e02_sraw(0xFFFFFFFFU, 0x3FU, &ca);
	e02_check("W4.rd", r, 0xFFFFFFFFU);
	e02_check("W4.ca", ca, 1U);

	/* XER.CA carry propagation. */
	r = e02_addc(0xFFFFFFFFU, 1U, &ca);
	e02_check("A1.addc", r, 0x00000000U);
	e02_check("A1.ca", ca, 1U);
	r = e02_addc(0x7FFFFFFFU, 1U, &ca);
	e02_check("A2.addc", r, 0x80000000U);
	e02_check("A2.ca", ca, 0U);
	r = e02_addze(5U, 1U, &ca);
	e02_check("A3.addze", r, 6U);
	e02_check("A3.ca", ca, 0U);
	r = e02_addze(0xFFFFFFFFU, 1U, &ca);
	e02_check("A4.addze", r, 0U);
	e02_check("A4.ca", ca, 1U);
	r = e02_subfc(3U, 5U, &ca);
	e02_check("A5.subfc", r, 2U);
	e02_check("A5.ca", ca, 1U);
	r = e02_subfc(5U, 3U, &ca);
	e02_check("A6.subfc", r, 0xFFFFFFFEU);
	e02_check("A6.ca", ca, 0U);
	r = e02_subfc(0U, 0U, &ca);
	e02_check("A7.subfc", r, 0U);
	e02_check("A7.ca", ca, 1U);
	r = e02_subfze(0U, 1U, &ca);
	e02_check("A8.subfze", r, 0U);
	e02_check("A8.ca", ca, 1U);
	r = e02_subfze(5U, 1U, &ca);
	e02_check("A9.subfze", r, 0xFFFFFFFBU);
	e02_check("A9.ca", ca, 0U);
	r = e02_subfze(0U, 0U, &ca);
	e02_check("A10.subfze", r, 0xFFFFFFFFU);
	e02_check("A10.ca", ca, 0U);

	/* Rc=1 CR0 update. */
	e02_check("C1.eq", e02_cr0_of(0U, 0U), E02_CR0_EQ);
	e02_check("C2.lt", e02_cr0_of(0x80000000U, 0U), E02_CR0_LT);
	e02_check("C3.gt", e02_cr0_of(1U, 0U), E02_CR0_GT);
	e02_check("C4.soeq", e02_cr0_of(0U, E02_XER_SO),
	    (uint32_t)(E02_CR0_EQ | E02_CR0_SO));

#if defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC)
	(void)printf("TARGET run: executing real instructions\n");
	e02_check("T1.hw", e02_hw_rlwinm_bext(0x12345678U), 0x00000056U);
#else
	(void)printf("TARGET run: skipped (host build, no __powerpc__)\n");
#endif

	if (e02_fails == 0) {
		(void)printf("E02 RESULT: all model vectors pass\n");
	} else {
		(void)printf("E02 RESULT: %d mismatches\n", e02_fails);
	}
	return e02_fails;
}
