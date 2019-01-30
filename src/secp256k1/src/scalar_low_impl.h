/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SCALAR_REPR_IMPL_H_
#define _SECP256K1_SCALAR_REPR_IMPL_H_

#include "scalar.h"

#include <string.h>

SECP256K1_INLINE static int secp256k1_scalar_is_even(const struct secp256k1_scalar *a) {
    return !(a->d & 1);
}

SECP256K1_INLINE static void secp256k1_scalar_clear(struct secp256k1_scalar *r) { r->d = 0; }
SECP256K1_INLINE static void secp256k1_scalar_set_int(struct secp256k1_scalar *r, unsigned int v) { r->d = v; }

SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits(const struct secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    if (offset < 32)
        return ((a->d >> offset) & ((((uint32_t)1) << count) - 1));
    else
        return 0;
}

SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits_var(const struct secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    return secp256k1_scalar_get_bits(a, offset, count);
}

SECP256K1_INLINE static int secp256k1_scalar_check_overflow(const struct secp256k1_scalar *a) { return a->d >= EXHAUSTIVE_TEST_ORDER; }

static int secp256k1_scalar_add(struct secp256k1_scalar *r, const struct secp256k1_scalar *a, const struct secp256k1_scalar *b) {
    r->d = (a->d + b->d) % EXHAUSTIVE_TEST_ORDER;
    return r->d < b->d;
}

static void secp256k1_scalar_cadd_bit(struct secp256k1_scalar *r, unsigned int bit, int flag) {
    if (flag && bit < 32)
        r->d += (1 << bit);
#ifdef VERIFY
    VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
#endif
}

static void secp256k1_scalar_set_b32(struct secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    const int base = 0x100 % EXHAUSTIVE_TEST_ORDER;
    int i;
    r->d = 0;
    for (i = 0; i < 32; i++) {
       r->d = ((r->d * base) + b32[i]) % EXHAUSTIVE_TEST_ORDER;
    }
    /* just deny overflow, it basically always happens */
    if (overflow) *overflow = 0;
}

static void secp256k1_scalar_get_b32(unsigned char *bin, const struct secp256k1_scalar* a) {
    memset(bin, 0, 32);
    bin[28] = a->d >> 24; bin[29] = a->d >> 16; bin[30] = a->d >> 8; bin[31] = a->d;
}

SECP256K1_INLINE static int secp256k1_scalar_is_zero(const struct secp256k1_scalar *a) {
    return a->d == 0;
}

static void secp256k1_scalar_negate(struct secp256k1_scalar *r, const struct secp256k1_scalar *a) {
    if (a->d == 0) {
        r->d = 0;
    } else {
        r->d = EXHAUSTIVE_TEST_ORDER - a->d;
    }
}

SECP256K1_INLINE static int secp256k1_scalar_is_one(const struct secp256k1_scalar *a) {
    return a->d == 1;
}

static int secp256k1_scalar_is_high(const struct secp256k1_scalar *a) {
    return a->d > EXHAUSTIVE_TEST_ORDER / 2;
}

static int secp256k1_scalar_cond_negate(struct secp256k1_scalar *r, int flag) {
    if (flag) secp256k1_scalar_negate(r, r);
    return flag ? -1 : 1;
}

static void secp256k1_scalar_mul(struct secp256k1_scalar *r, const struct secp256k1_scalar *a, const struct secp256k1_scalar *b) {
    r->d = (a->d * b->d) % EXHAUSTIVE_TEST_ORDER;
}

static int secp256k1_scalar_shr_int(struct secp256k1_scalar *r, int n) {
    int ret;
    VERIFY_CHECK(n > 0);
    VERIFY_CHECK(n < 16);
    ret = r->d & ((1 << n) - 1);
    r->d >>= n;
    return ret;
}

static void secp256k1_scalar_sqr(struct secp256k1_scalar *r, const struct secp256k1_scalar *a) {
    r->d = (a->d * a->d) % EXHAUSTIVE_TEST_ORDER;
}

static void secp256k1_scalar_split_128(struct secp256k1_scalar *r1, struct secp256k1_scalar *r2, const struct secp256k1_scalar *a) {
    r1->d = a->d;
    r2->d = 0;
}

SECP256K1_INLINE static int secp256k1_scalar_eq(const struct secp256k1_scalar *a, const struct secp256k1_scalar *b) {
    return a->d == b->d;
}

#endif
