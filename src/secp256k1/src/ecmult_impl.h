/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_IMPL_H_
#define SECP256K1_ECMULT_IMPL_H_

#include <string.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"

#if defined(EXHAUSTIVE_TEST_ORDER)
/* We need to lower these values for exhaustive tests because
 * the tables cannot have infinities in them (this breaks the
 * affine-isomorphism stuff which tracks z-ratios) */
#  if EXHAUSTIVE_TEST_ORDER > 128
#    define WINDOW_A 5
#    define WINDOW_G 8
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define WINDOW_A 4
#    define WINDOW_G 4
#  else
#    define WINDOW_A 2
#    define WINDOW_G 2
#  endif
#else
/* optimal for 128-bit and 256-bit exponents. */
#define WINDOW_A 5
/** larger numbers may result in slightly better performance, at the cost of
    exponentially larger precomputed tables. */
#ifdef USE_ENDOMORPHISM
/** Two tables for window size 15: 1.375 MiB. */
#define WINDOW_G 15
#else
/** One table for window size 16: 1.375 MiB. */
#define WINDOW_G 16
#endif
#endif

#ifdef USE_ENDOMORPHISM
#define WNAF_BITS 128
#else
#define WNAF_BITS 256
#endif
#define WNAF_SIZE_BITS(bits, w) (((bits) + (w) - 1) / (w))
#define WNAF_SIZE(w) WNAF_SIZE_BITS(WNAF_BITS, w)

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))

/* The number of objects allocated on the scratch space for ecmult_multi algorithms */
#define PIPPENGER_SCRATCH_OBJECTS 6
#define STRAUSS_SCRATCH_OBJECTS 6

#define PIPPENGER_MAX_BUCKET_WINDOW 12

/* Minimum number of points for which pippenger_wnaf is faster than strauss wnaf */
#ifdef USE_ENDOMORPHISM
#define ECMULT_PIPPENGER_THRESHOLD 88
#else
#define ECMULT_PIPPENGER_THRESHOLD 160
#endif

#ifdef USE_ENDOMORPHISM
#define ECMULT_MAX_POINTS_PER_BATCH 5000000
#else
#define ECMULT_MAX_POINTS_PER_BATCH 10000000
#endif

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
static void secp256k1_ecmult_odd_multiples_table(int n, secp256k1_gej *prej, secp256k1_fe *zr, const secp256k1_gej *a) {
    secp256k1_gej d;
    secp256k1_ge a_ge, d_ge;
    int i;

    VERIFY_CHECK(!a->infinity);

    secp256k1_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    secp256k1_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    secp256k1_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

/** Fill a table 'pre' with precomputed odd multiples of a.
 *
 *  There are two versions of this function:
 *  - secp256k1_ecmult_odd_multiples_table_globalz_windowa which brings its
 *    resulting point set to a single constant Z denominator, stores the X and Y
 *    coordinates as ge_storage points in pre, and stores the global Z in rz.
 *    It only operates on tables sized for WINDOW_A wnaf multiples.
 *  - secp256k1_ecmult_odd_multiples_table_storage_var, which converts its
 *    resulting point set to actually affine points, and stores those in pre.
 *    It operates on tables of any size, but uses heap-allocated temporaries.
 *
 *  To compute a*P + b*G, we compute a table for P using the first function,
 *  and for G using the second (which requires an inverse, but it only needs to
 *  happen once).
 */
static void secp256k1_ecmult_odd_multiples_table_globalz_windowa(secp256k1_ge *pre, secp256k1_fe *globalz, const secp256k1_gej *a) {
    secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), prej, zr, a);
    /* Bring them to the same Z denominator. */
    secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A), pre, globalz, prej, zr);
}

static void secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a, const secp256k1_callback *cb) {
    secp256k1_gej *prej = (secp256k1_gej*)checked_malloc(cb, sizeof(secp256k1_gej) * n);
    secp256k1_ge *prea = (secp256k1_ge*)checked_malloc(cb, sizeof(secp256k1_ge) * n);
    secp256k1_fe *zr = (secp256k1_fe*)checked_malloc(cb, sizeof(secp256k1_fe) * n);
    int i;

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(n, prej, zr, a);
    /* Convert them in batch to affine coordinates. */
    secp256k1_ge_set_table_gej_var(prea, prej, zr, n);
    /* Convert them to compact storage form. */
    for (i = 0; i < n; i++) {
        secp256k1_ge_to_storage(&pre[i], &prea[i]);
    }

    free(prea);
    free(prej);
    free(zr);
}

/** The following two macro retrieves a particular odd multiple from a table
 *  of precomputed multiples. */
#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        secp256k1_ge_neg((r), &(pre)[(-(n)-1)/2]); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        secp256k1_ge_from_storage((r), &(pre)[((n)-1)/2]); \
    } else { \
        secp256k1_ge_from_storage((r), &(pre)[(-(n)-1)/2]); \
        secp256k1_ge_neg((r), (r)); \
    } \
} while(0)

static void secp256k1_ecmult_context_init(secp256k1_ecmult_context *ctx) {
    ctx->pre_g = NULL;
#ifdef USE_ENDOMORPHISM
    ctx->pre_g_128 = NULL;
#endif
}

static void secp256k1_ecmult_context_build(secp256k1_ecmult_context *ctx, const secp256k1_callback *cb) {
    secp256k1_gej gj;

    if (ctx->pre_g != NULL) {
        return;
    }

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    ctx->pre_g = (secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

    /* precompute the tables with odd multiples */
    secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g, &gj, cb);

#ifdef USE_ENDOMORPHISM
    {
        secp256k1_gej g_128j;
        int i;

        ctx->pre_g_128 = (secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

        /* calculate 2^128*generator */
        g_128j = gj;
        for (i = 0; i < 128; i++) {
            secp256k1_gej_double_var(&g_128j, &g_128j, NULL);
        }
        secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g_128, &g_128j, cb);
    }
#endif
}

static void secp256k1_ecmult_context_clone(secp256k1_ecmult_context *dst,
                                           const secp256k1_ecmult_context *src, const secp256k1_callback *cb) {
    if (src->pre_g == NULL) {
        dst->pre_g = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g = (secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g, src->pre_g, size);
    }
#ifdef USE_ENDOMORPHISM
    if (src->pre_g_128 == NULL) {
        dst->pre_g_128 = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g_128 = (secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g_128, src->pre_g_128, size);
    }
#endif
}

static int secp256k1_ecmult_context_is_built(const secp256k1_ecmult_context *ctx) {
    return ctx->pre_g != NULL;
}

static void secp256k1_ecmult_context_clear(secp256k1_ecmult_context *ctx) {
    free(ctx->pre_g);
#ifdef USE_ENDOMORPHISM
    free(ctx->pre_g_128);
#endif
    secp256k1_ecmult_context_init(ctx);
}


/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
    secp256k1_scalar s = *a;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    VERIFY_CHECK(wnaf != NULL);
    VERIFY_CHECK(0 <= len && len <= 256);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(2 <= w && w <= 31);

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    if (secp256k1_scalar_get_bits(&s, 255, 1)) {
        secp256k1_scalar_negate(&s, &s);
        sign = -1;
    }

    while (bit < len) {
        int now;
        int word;
        if (secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
#ifdef VERIFY
    CHECK(carry == 0);
    while (bit < 256) {
        CHECK(secp256k1_scalar_get_bits(&s, bit++, 1) == 0);
    }
#endif
    return last_set_bit + 1;
}

struct secp256k1_strauss_point_state {
#ifdef USE_ENDOMORPHISM
    secp256k1_scalar na_1, na_lam;
    int wnaf_na_1[130];
    int wnaf_na_lam[130];
    int bits_na_1;
    int bits_na_lam;
#else
    int wnaf_na[256];
    int bits_na;
#endif
    size_t input_pos;
};

struct secp256k1_strauss_state {
    secp256k1_gej* prej;
    secp256k1_fe* zr;
    secp256k1_ge* pre_a;
#ifdef USE_ENDOMORPHISM
    secp256k1_ge* pre_a_lam;
#endif
    struct secp256k1_strauss_point_state* ps;
};

static void secp256k1_ecmult_strauss_wnaf(const secp256k1_ecmult_context *ctx, const struct secp256k1_strauss_state *state, secp256k1_gej *r, int num, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_ge tmpa;
    secp256k1_fe Z;
#ifdef USE_ENDOMORPHISM
    /* Splitted G factors. */
    secp256k1_scalar ng_1, ng_128;
    int wnaf_ng_1[129];
    int bits_ng_1 = 0;
    int wnaf_ng_128[129];
    int bits_ng_128 = 0;
#else
    int wnaf_ng[256];
    int bits_ng = 0;
#endif
    int i;
    int bits = 0;
    int np;
    int no = 0;

    for (np = 0; np < num; ++np) {
        if (secp256k1_scalar_is_zero(&na[np]) || secp256k1_gej_is_infinity(&a[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
#ifdef USE_ENDOMORPHISM
        /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
        secp256k1_scalar_split_lambda(&state->ps[no].na_1, &state->ps[no].na_lam, &na[np]);

        /* build wnaf representation for na_1 and na_lam. */
        state->ps[no].bits_na_1   = secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_1,   130, &state->ps[no].na_1,   WINDOW_A);
        state->ps[no].bits_na_lam = secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_lam, 130, &state->ps[no].na_lam, WINDOW_A);
        VERIFY_CHECK(state->ps[no].bits_na_1 <= 130);
        VERIFY_CHECK(state->ps[no].bits_na_lam <= 130);
        if (state->ps[no].bits_na_1 > bits) {
            bits = state->ps[no].bits_na_1;
        }
        if (state->ps[no].bits_na_lam > bits) {
            bits = state->ps[no].bits_na_lam;
        }
#else
        /* build wnaf representation for na. */
        state->ps[no].bits_na     = secp256k1_ecmult_wnaf(state->ps[no].wnaf_na,     256, &na[np],      WINDOW_A);
        if (state->ps[no].bits_na > bits) {
            bits = state->ps[no].bits_na;
        }
#endif
        ++no;
    }

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     * The exception is the precomputed G table points, which are actually
     * affine. Compared to the base used for other points, they have a Z ratio
     * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
     * isomorphism to efficiently add with a known Z inverse.
     */
    if (no > 0) {
        /* Compute the odd multiples in Jacobian form. */
        secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), state->prej, state->zr, &a[state->ps[0].input_pos]);
        for (np = 1; np < no; ++np) {
            secp256k1_gej tmp = a[state->ps[np].input_pos];
#ifdef VERIFY
            secp256k1_fe_normalize_var(&(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
#endif
            secp256k1_gej_rescale(&tmp, &(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
            secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), state->prej + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &tmp);
            secp256k1_fe_mul(state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &(a[state->ps[np].input_pos].z));
        }
        /* Bring them to the same Z denominator. */
        secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A) * no, state->pre_a, &Z, state->prej, state->zr);
    } else {
        secp256k1_fe_set_int(&Z, 1);
    }

#ifdef USE_ENDOMORPHISM
    for (np = 0; np < no; ++np) {
        for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
            secp256k1_ge_mul_lambda(&state->pre_a_lam[np * ECMULT_TABLE_SIZE(WINDOW_A) + i], &state->pre_a[np * ECMULT_TABLE_SIZE(WINDOW_A) + i]);
        }
    }

    if (ng) {
        /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
        secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

        /* Build wnaf representation for ng_1 and ng_128 */
        bits_ng_1   = secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
        bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
        if (bits_ng_1 > bits) {
            bits = bits_ng_1;
        }
        if (bits_ng_128 > bits) {
            bits = bits_ng_128;
        }
    }
#else
    if (ng) {
        bits_ng     = secp256k1_ecmult_wnaf(wnaf_ng,     256, ng,      WINDOW_G);
        if (bits_ng > bits) {
            bits = bits_ng;
        }
    }
#endif

    secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        secp256k1_gej_double_var(r, r, NULL);
#ifdef USE_ENDOMORPHISM
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na_1 && (n = state->ps[np].wnaf_na_1[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
            if (i < state->ps[np].bits_na_lam && (n = state->ps[np].wnaf_na_lam[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a_lam + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
        if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g_128, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#else
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na && (n = state->ps[np].wnaf_na[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (i < bits_ng && (n = wnaf_ng[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#endif
    }

    if (!r->infinity) {
        secp256k1_fe_mul(&r->z, &r->z, &Z);
    }
}

static void secp256k1_ecmult(const secp256k1_ecmult_context *ctx, secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    struct secp256k1_strauss_point_state ps[1];
#ifdef USE_ENDOMORPHISM
    secp256k1_ge pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
#endif
    struct secp256k1_strauss_state state;

    state.prej = prej;
    state.zr = zr;
    state.pre_a = pre_a;
#ifdef USE_ENDOMORPHISM
    state.pre_a_lam = pre_a_lam;
#endif
    state.ps = ps;
    secp256k1_ecmult_strauss_wnaf(ctx, &state, r, 1, a, na, ng);
}

static size_t secp256k1_strauss_scratch_size(size_t n_points) {
#ifdef USE_ENDOMORPHISM
    static const size_t point_size = (2 * sizeof(secp256k1_ge) + sizeof(secp256k1_gej) + sizeof(secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct secp256k1_strauss_point_state) + sizeof(secp256k1_gej) + sizeof(secp256k1_scalar);
#else
    static const size_t point_size = (sizeof(secp256k1_ge) + sizeof(secp256k1_gej) + sizeof(secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct secp256k1_strauss_point_state) + sizeof(secp256k1_gej) + sizeof(secp256k1_scalar);
#endif
    return n_points*point_size;
}

static int secp256k1_ecmult_strauss_batch(const secp256k1_ecmult_context *ctx, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    secp256k1_gej* points;
    secp256k1_scalar* scalars;
    struct secp256k1_strauss_state state;
    size_t i;

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }

    if (!secp256k1_scratch_allocate_frame(scratch, secp256k1_strauss_scratch_size(n_points), STRAUSS_SCRATCH_OBJECTS)) {
        return 0;
    }
    points = (secp256k1_gej*)secp256k1_scratch_alloc(scratch, n_points * sizeof(secp256k1_gej));
    scalars = (secp256k1_scalar*)secp256k1_scratch_alloc(scratch, n_points * sizeof(secp256k1_scalar));
    state.prej = (secp256k1_gej*)secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_gej));
    state.zr = (secp256k1_fe*)secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_fe));
#ifdef USE_ENDOMORPHISM
    state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, n_points * 2 * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
    state.pre_a_lam = state.pre_a + n_points * ECMULT_TABLE_SIZE(WINDOW_A);
#else
    state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
#endif
    state.ps = (struct secp256k1_strauss_point_state*)secp256k1_scratch_alloc(scratch, n_points * sizeof(struct secp256k1_strauss_point_state));

    for (i = 0; i < n_points; i++) {
        if (!cb(&scalars[i], &points[i] , i+cb_offset, cbdata)) {
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
    }
    secp256k1_ecmult_strauss_wnaf(ctx, &state, r, n_points, points, scalars, inp_g_sc);
    secp256k1_scratch_deallocate_frame(scratch);
    return 1;
}

/* Wrapper for secp256k1_ecmult_multi_func interface */
static int secp256k1_ecmult_strauss_batch_single(const secp256k1_ecmult_context *actx, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return secp256k1_ecmult_strauss_batch(actx, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

static size_t secp256k1_strauss_max_points(secp256k1_scratch *scratch) {
    return secp256k1_scratch_max_allocation(scratch, STRAUSS_SCRATCH_OBJECTS) / secp256k1_strauss_scratch_size(1);
}

/** Convert a number to WNAF notation.
 *  The number becomes represented by sum(2^{wi} * wnaf[i], i=0..WNAF_SIZE(w)+1) - return_val.
 *  It has the following guarantees:
 *  - each wnaf[i] is either 0 or an odd integer between -(1 << w) and (1 << w)
 *  - the number of words set is always WNAF_SIZE(w)
 *  - the returned skew is 0 or 1
 */
static int secp256k1_wnaf_fixed(int *wnaf, const secp256k1_scalar *s, int w) {
    int skew = 0;
    int pos;
    int max_pos;
    int last_w;
    const secp256k1_scalar *work = s;

    if (secp256k1_scalar_is_zero(s)) {
        for (pos = 0; pos < WNAF_SIZE(w); pos++) {
            wnaf[pos] = 0;
        }
        return 0;
    }

    if (secp256k1_scalar_is_even(s)) {
        skew = 1;
    }

    wnaf[0] = secp256k1_scalar_get_bits_var(work, 0, w) + skew;
    /* Compute last window size. Relevant when window size doesn't divide the
     * number of bits in the scalar */
    last_w = WNAF_BITS - (WNAF_SIZE(w) - 1) * w;

    /* Store the position of the first nonzero word in max_pos to allow
     * skipping leading zeros when calculating the wnaf. */
    for (pos = WNAF_SIZE(w) - 1; pos > 0; pos--) {
        int val = secp256k1_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if(val != 0) {
            break;
        }
        wnaf[pos] = 0;
    }
    max_pos = pos;
    pos = 1;

    while (pos <= max_pos) {
        int val = secp256k1_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if ((val & 1) == 0) {
            wnaf[pos - 1] -= (1 << w);
            wnaf[pos] = (val + 1);
        } else {
            wnaf[pos] = val;
        }
        /* Set a coefficient to zero if it is 1 or -1 and the proceeding digit
         * is strictly negative or strictly positive respectively. Only change
         * coefficients at previous positions because above code assumes that
         * wnaf[pos - 1] is odd.
         */
        if (pos >= 2 && ((wnaf[pos - 1] == 1 && wnaf[pos - 2] < 0) || (wnaf[pos - 1] == -1 && wnaf[pos - 2] > 0))) {
            if (wnaf[pos - 1] == 1) {
                wnaf[pos - 2] += 1 << w;
            } else {
                wnaf[pos - 2] -= 1 << w;
            }
            wnaf[pos - 1] = 0;
        }
        ++pos;
    }

    return skew;
}

struct secp256k1_pippenger_point_state {
    int skew_na;
    size_t input_pos;
};

struct secp256k1_pippenger_state {
    int *wnaf_na;
    struct secp256k1_pippenger_point_state* ps;
};

/*
 * pippenger_wnaf computes the result of a multi-point multiplication as
 * follows: The scalars are brought into wnaf with n_wnaf elements each. Then
 * for every i < n_wnaf, first each point is added to a "bucket" corresponding
 * to the point's wnaf[i]. Second, the buckets are added together such that
 * r += 1*bucket[0] + 3*bucket[1] + 5*bucket[2] + ...
 */
static int secp256k1_ecmult_pippenger_wnaf(secp256k1_gej *buckets, int bucket_window, struct secp256k1_pippenger_state *state, secp256k1_gej *r, const secp256k1_scalar *sc, const secp256k1_ge *pt, size_t num) {
    size_t n_wnaf = WNAF_SIZE(bucket_window+1);
    size_t np;
    size_t no = 0;
    int i;
    int j;

    for (np = 0; np < num; ++np) {
        if (secp256k1_scalar_is_zero(&sc[np]) || secp256k1_ge_is_infinity(&pt[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
        state->ps[no].skew_na = secp256k1_wnaf_fixed(&state->wnaf_na[no*n_wnaf], &sc[np], bucket_window+1);
        no++;
    }
    secp256k1_gej_set_infinity(r);

    if (no == 0) {
        return 1;
    }

    for (i = n_wnaf - 1; i >= 0; i--) {
        secp256k1_gej running_sum;

        for(j = 0; j < ECMULT_TABLE_SIZE(bucket_window+2); j++) {
            secp256k1_gej_set_infinity(&buckets[j]);
        }

        for (np = 0; np < no; ++np) {
            int n = state->wnaf_na[np*n_wnaf + i];
            struct secp256k1_pippenger_point_state point_state = state->ps[np];
            secp256k1_ge tmp;
            int idx;

            if (i == 0) {
                /* correct for wnaf skew */
                int skew = point_state.skew_na;
                if (skew) {
                    secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                    secp256k1_gej_add_ge_var(&buckets[0], &buckets[0], &tmp, NULL);
                }
            }
            if (n > 0) {
                idx = (n - 1)/2;
                secp256k1_gej_add_ge_var(&buckets[idx], &buckets[idx], &pt[point_state.input_pos], NULL);
            } else if (n < 0) {
                idx = -(n + 1)/2;
                secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                secp256k1_gej_add_ge_var(&buckets[idx], &buckets[idx], &tmp, NULL);
            }
        }

        for(j = 0; j < bucket_window; j++) {
            secp256k1_gej_double_var(r, r, NULL);
        }

        secp256k1_gej_set_infinity(&running_sum);
        /* Accumulate the sum: bucket[0] + 3*bucket[1] + 5*bucket[2] + 7*bucket[3] + ...
         *                   = bucket[0] +   bucket[1] +   bucket[2] +   bucket[3] + ...
         *                   +         2 *  (bucket[1] + 2*bucket[2] + 3*bucket[3] + ...)
         * using an intermediate running sum:
         * running_sum = bucket[0] +   bucket[1] +   bucket[2] + ...
         *
         * The doubling is done implicitly by deferring the final window doubling (of 'r').
         */
        for(j = ECMULT_TABLE_SIZE(bucket_window+2) - 1; j > 0; j--) {
            secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[j], NULL);
            secp256k1_gej_add_var(r, r, &running_sum, NULL);
        }

        secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[0], NULL);
        secp256k1_gej_double_var(r, r, NULL);
        secp256k1_gej_add_var(r, r, &running_sum, NULL);
    }
    return 1;
}

/**
 * Returns optimal bucket_window (number of bits of a scalar represented by a
 * set of buckets) for a given number of points.
 */
static int secp256k1_pippenger_bucket_window(size_t n) {
    int i;
#ifdef USE_ENDOMORPHISM
    unsigned int size[11]= {1, 4, 20, 57, 136, 235, 1260, 1260, 4420, 7880, 16050};
#else
    unsigned int size[11]= {1, 11, 45, 100, 275, 625, 1850, 3400, 9630, 17900, 32800};
#endif

    for (i = 0; i < 11; ++i){
        if (n <= size[i])
            return i + 1;
    }


    return PIPPENGER_MAX_BUCKET_WINDOW;
}

/**
 * Returns the maximum optimal number of points for a bucket_window.
 */
static size_t secp256k1_pippenger_bucket_window_inv(int bucket_window) {
#ifdef USE_ENDOMORPHISM
    int size[11]= {1, 4, 20, 57, 136, 235, 1260, 1260, 4420, 7880, 16050};
#else
    int size[11]= {1, 11, 45, 100, 275, 625, 1850, 3400, 9630, 17900, 32800};
#endif

    if (bucket_window == PIPPENGER_MAX_BUCKET_WINDOW )
        return SIZE_MAX;

    else if(bucket_window >= 1 && bucket_window <= 11)
        return size[bucket_window - 1];
    return 0;
}

#ifdef USE_ENDOMORPHISM
SECP256K1_INLINE static void secp256k1_ecmult_endo_split(secp256k1_scalar *s1, secp256k1_scalar *s2, secp256k1_ge *p1, secp256k1_ge *p2) {
    secp256k1_scalar tmp = *s1;
    secp256k1_scalar_split_lambda(s1, s2, &tmp);
    secp256k1_ge_mul_lambda(p2, p1);

    if (secp256k1_scalar_is_high(s1)) {
        secp256k1_scalar_negate(s1, s1);
        secp256k1_ge_neg(p1, p1);
    }
    if (secp256k1_scalar_is_high(s2)) {
        secp256k1_scalar_negate(s2, s2);
        secp256k1_ge_neg(p2, p2);
    }
}
#endif

/**
 * Returns the scratch size required for a given number of points (excluding
 * base point G) without considering alignment.
 */
static size_t secp256k1_pippenger_scratch_size(size_t n_points, int bucket_window) {
#ifdef USE_ENDOMORPHISM
    size_t entries = 2*n_points + 2;
#else
    size_t entries = n_points + 1;
#endif
    size_t entry_size = sizeof(secp256k1_ge) + sizeof(secp256k1_scalar) + sizeof(struct secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);
    return ((1<<bucket_window) * sizeof(secp256k1_gej) + sizeof(struct secp256k1_pippenger_state) + entries * entry_size);
}

static int secp256k1_ecmult_pippenger_batch(const secp256k1_ecmult_context *ctx, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    /* Use 2(n+1) with the endomorphism, n+1 without, when calculating batch
     * sizes. The reason for +1 is that we add the G scalar to the list of
     * other scalars. */
#ifdef USE_ENDOMORPHISM
    size_t entries = 2*n_points + 2;
#else
    size_t entries = n_points + 1;
#endif
    secp256k1_ge *points;
    secp256k1_scalar *scalars;
    secp256k1_gej *buckets;
    struct secp256k1_pippenger_state *state_space;
    size_t idx = 0;
    size_t point_idx = 0;
    int i, j;
    int bucket_window;

    (void)ctx;
    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }

    bucket_window = secp256k1_pippenger_bucket_window(n_points);
    if (!secp256k1_scratch_allocate_frame(scratch, secp256k1_pippenger_scratch_size(n_points, bucket_window), PIPPENGER_SCRATCH_OBJECTS)) {
        return 0;
    }
    points = (secp256k1_ge *) secp256k1_scratch_alloc(scratch, entries * sizeof(*points));
    scalars = (secp256k1_scalar *) secp256k1_scratch_alloc(scratch, entries * sizeof(*scalars));
    state_space = (struct secp256k1_pippenger_state *) secp256k1_scratch_alloc(scratch, sizeof(*state_space));
    state_space->ps = (struct secp256k1_pippenger_point_state *) secp256k1_scratch_alloc(scratch, entries * sizeof(*state_space->ps));
    state_space->wnaf_na = (int *) secp256k1_scratch_alloc(scratch, entries*(WNAF_SIZE(bucket_window+1)) * sizeof(int));
    buckets = (secp256k1_gej *) secp256k1_scratch_alloc(scratch, (1<<bucket_window) * sizeof(*buckets));

    if (inp_g_sc != NULL) {
        scalars[0] = *inp_g_sc;
        points[0] = secp256k1_ge_const_g;
        idx++;
#ifdef USE_ENDOMORPHISM
        secp256k1_ecmult_endo_split(&scalars[0], &scalars[1], &points[0], &points[1]);
        idx++;
#endif
    }

    while (point_idx < n_points) {
        secp256k1_gej point;
        if (!cb(&scalars[idx], &point, point_idx + cb_offset, cbdata)) {
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        secp256k1_ge_set_gej(&points[idx], &point);
        idx++;
#ifdef USE_ENDOMORPHISM
        secp256k1_ecmult_endo_split(&scalars[idx - 1], &scalars[idx], &points[idx - 1], &points[idx]);
        idx++;
#endif
        point_idx++;
    }

    secp256k1_ecmult_pippenger_wnaf(buckets, bucket_window, state_space, r, scalars, points, idx);

    /* Clear data */
    for(i = 0; (size_t)i < idx; i++) {
        secp256k1_scalar_clear(&scalars[i]);
        state_space->ps[i].skew_na = 0;
        for(j = 0; j < WNAF_SIZE(bucket_window+1); j++) {
            state_space->wnaf_na[i * WNAF_SIZE(bucket_window+1) + j] = 0;
        }
    }
    for(i = 0; i < 1<<bucket_window; i++) {
        secp256k1_gej_clear(&buckets[i]);
    }
    secp256k1_scratch_deallocate_frame(scratch);
    return 1;
}


/* Wrapper for secp256k1_ecmult_multi_func interface */
static int secp256k1_ecmult_pippenger_batch_single(const secp256k1_ecmult_context *actx, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return secp256k1_ecmult_pippenger_batch(actx, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

/**
 * Returns the maximum number of points in addition to G that can be used with
 * a given scratch space. The function ensures that fewer points may also be
 * used.
 */
static size_t secp256k1_pippenger_max_points(secp256k1_scratch *scratch) {
    size_t max_alloc = secp256k1_scratch_max_allocation(scratch, PIPPENGER_SCRATCH_OBJECTS);
    int bucket_window;
    size_t res = 0;

    for (bucket_window = 1; bucket_window <= PIPPENGER_MAX_BUCKET_WINDOW; bucket_window++) {
        size_t n_points;
        size_t max_points = secp256k1_pippenger_bucket_window_inv(bucket_window);
        size_t space_for_points;
        size_t space_overhead;
        size_t entry_size = sizeof(secp256k1_ge) + sizeof(secp256k1_scalar) + sizeof(struct secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);

#ifdef USE_ENDOMORPHISM
        entry_size = 2*entry_size;
#endif
        space_overhead = ((1<<bucket_window) * sizeof(secp256k1_gej) + entry_size + sizeof(struct secp256k1_pippenger_state));
        if (space_overhead > max_alloc) {
            break;
        }
        space_for_points = max_alloc - space_overhead;

        n_points = space_for_points/entry_size;
        n_points = n_points > max_points ? max_points : n_points;
        if (n_points > res) {
            res = n_points;
        }
        if (n_points < max_points) {
            /* A larger bucket_window may support even more points. But if we
             * would choose that then the caller couldn't safely use any number
             * smaller than what this function returns */
            break;
        }
    }
    return res;
}


typedef int (*secp256k1_ecmult_multi_func)(const secp256k1_ecmult_context*, secp256k1_scratch*, secp256k1_gej*, const secp256k1_scalar*, secp256k1_ecmult_multi_callback cb, void*, size_t);
static int secp256k1_ecmult_multi_var(const secp256k1_ecmult_context *ctx, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    size_t i;

    int (*f)(const secp256k1_ecmult_context*, secp256k1_scratch*, secp256k1_gej*, const secp256k1_scalar*, secp256k1_ecmult_multi_callback cb, void*, size_t, size_t);
    size_t max_points;
    size_t n_batches;
    size_t n_batch_points;

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n == 0) {
        return 1;
    } else if (n == 0) {
        secp256k1_scalar szero;
        secp256k1_scalar_set_int(&szero, 0);
        secp256k1_ecmult(ctx, r, r, &szero, inp_g_sc);
        return 1;
    }

    max_points = secp256k1_pippenger_max_points(scratch);
    if (max_points == 0) {
        return 0;
    } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
        max_points = ECMULT_MAX_POINTS_PER_BATCH;
    }
    n_batches = (n+max_points-1)/max_points;
    n_batch_points = (n+n_batches-1)/n_batches;

    if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
        f = secp256k1_ecmult_pippenger_batch;
    } else {
        max_points = secp256k1_strauss_max_points(scratch);
        if (max_points == 0) {
            return 0;
        }
        n_batches = (n+max_points-1)/max_points;
        n_batch_points = (n+n_batches-1)/n_batches;
        f = secp256k1_ecmult_strauss_batch;
    }
    for(i = 0; i < n_batches; i++) {
        size_t nbp = n < n_batch_points ? n : n_batch_points;
        size_t offset = n_batch_points*i;
        secp256k1_gej tmp;
        if (!f(ctx, scratch, &tmp, i == 0 ? inp_g_sc : NULL, cb, cbdata, nbp, offset)) {
            return 0;
        }
        secp256k1_gej_add_var(r, r, &tmp, NULL);
        n -= nbp;
    }
    return 1;
}

#endif
