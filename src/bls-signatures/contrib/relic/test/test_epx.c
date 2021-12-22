/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Tests for elliptic curves defined over extensions of prime fields.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

static int memory(void) {
	err_t e;
	int code = RLC_ERR;
	ep2_t a;

	ep2_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep2_new(a);
			ep2_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util(void) {
	int l, code = RLC_ERR;
	ep2_t a, b, c;
	uint8_t bin[4 * RLC_FP_BYTES + 1];

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("copy and comparison are consistent") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			/* Compare points in affine coordinates. */
			if (ep2_cmp(a, c) != RLC_EQ) {
				ep2_copy(c, a);
				TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			}
			if (ep2_cmp(b, c) != RLC_EQ) {
				ep2_copy(c, b);
				TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep2_dbl(c, a);
			ep2_norm(c, c);
			ep2_dbl(a, a);
			TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep2_dbl(c, c);
			ep2_dbl(a, a);
			TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep2_rand(a);
			ep2_neg(b, a);
			TEST_ASSERT(ep2_cmp(a, b) != RLC_EQ, end);
			ep2_neg(b, b);
			TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
			ep2_neg(b, a);
			ep2_add(a, a, b);
			ep2_set_infty(b);
			TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep2_rand(a);
			ep2_set_infty(c);
			TEST_ASSERT(ep2_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep2_set_infty(a);
			TEST_ASSERT(ep2_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep2_set_infty(a);
			TEST_ASSERT(ep2_on_curve(a), end);
			ep2_rand(a);
			TEST_ASSERT(ep2_on_curve(a), end);
			fp2_rand(a->x);
			TEST_ASSERT(!ep2_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep2_rand(a);
			ep2_blind(a, a);
			TEST_ASSERT(ep2_on_curve(a), end);
		} TEST_END;

		TEST_CASE("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ep2_set_infty(a);
				l = ep2_size_bin(a, j);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
				ep2_rand(a);
				l = ep2_size_bin(a, j);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
				ep2_rand(a);
				ep2_dbl(a, a);
				l = ep2_size_bin(a, j);
				ep2_norm(a, a);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

static int addition(void) {
	int code = RLC_ERR;
	ep2_t a, b, c, d, e;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	ep2_null(d);
	ep2_null(e);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		ep2_new(d);
		ep2_new(e);

		TEST_CASE("point addition is commutative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_add(d, a, b);
			ep2_add(e, b, a);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			ep2_add(d, a, b);
			ep2_add(d, d, c);
			ep2_add(e, b, c);
			ep2_add(e, e, a);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep2_rand(a);
			ep2_set_infty(d);
			ep2_add(e, a, d);
			TEST_ASSERT(ep2_cmp(e, a) == RLC_EQ, end);
			ep2_add(e, d, a);
			TEST_ASSERT(ep2_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep2_rand(a);
			ep2_neg(d, a);
			ep2_add(e, a, d);
			TEST_ASSERT(ep2_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_add(d, a, b);
			ep2_add_basic(e, a, b);
			TEST_ASSERT(ep2_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
#if !defined(EP_MIXED) || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			ep2_add_projc(a, a, b);
			ep2_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep2_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep2_norm(a, a);
			ep2_norm(b, b);
			ep2_add(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep2_rand(a);
			ep2_rand(b);
			/* a in projective, b in affine coordinates. */
			ep2_add_projc(a, a, b);
			ep2_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep2_norm(a, a);
			ep2_add(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep2_rand(a);
			ep2_rand(b);
			/* a and b in affine coordinates. */
			ep2_add(d, a, b);
			ep2_add_projc(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	ep2_free(d);
	ep2_free(e);
	return code;
}

static int subtraction(void) {
	int code = RLC_ERR;
	ep2_t a, b, c, d;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	ep2_null(d);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		ep2_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_sub(c, a, b);
			ep2_sub(d, b, a);
			ep2_neg(d, d);
			TEST_ASSERT(ep2_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep2_rand(a);
			ep2_set_infty(c);
			ep2_sub(d, a, c);
			TEST_ASSERT(ep2_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep2_rand(a);
			ep2_sub(c, a, a);
			TEST_ASSERT(ep2_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	ep2_free(d);
	return code;
}

static int doubling(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("point doubling is correct") {
			ep2_rand(a);
			ep2_add(b, a, a);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep2_rand(a);
			ep2_dbl(b, a);
			ep2_dbl_basic(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep2_rand(a);
			/* a in projective coordinates. */
			ep2_dbl_projc(a, a);
			ep2_dbl_projc(b, a);
			ep2_norm(a, a);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep2_rand(a);
			ep2_dbl_projc(b, a);
			ep2_norm(b, b);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

static int multiplication(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep2_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep2_null(p);
	ep2_null(q);
	ep2_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep2_new(p);
		ep2_new(q);
		ep2_new(r);

		ep2_curve_get_gen(p);
		ep2_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep2_on_curve(p), end);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_gen(r, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_basic(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("sliding window point multiplication is correct") {
			bn_zero(k);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_slide(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_monty(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_lwnaf(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("multiplication by digit is correct") {
			ep2_mul_dig(r, p, 0);
			TEST_ASSERT(ep2_is_infty(r), end);
			ep2_mul_dig(r, p, 1);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep2_mul(q, p, k);
			ep2_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep2_free(p);
	ep2_free(q);
	ep2_free(r);
	return code;
}

static int fixed(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep2_t p, q, r, t[RLC_EPX_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep2_null(p);
	ep2_null(q);
	ep2_null(r);

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep2_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep2_new(p);
		ep2_new(q);
		ep2_new(r);

		ep2_curve_get_gen(p);
		ep2_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre(t, p);
			bn_zero(k);
			ep2_mul_fix(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_fix(q, t, k);
			ep2_mul(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep2_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("binary fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_basic(t, p);
			bn_zero(k);
			ep2_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_basic(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_basic(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_combs(t, p);
			bn_zero(k);
			ep2_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_combs(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_combs(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_combd(t, p);
			bn_zero(k);
			ep2_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_combd(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_combd(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ep2_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_lwnaf(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_lwnaf(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep2_free(t[i]);
		}
#endif
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(p);
	ep2_free(q);
	ep2_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous(void) {
	int code = RLC_ERR;
	bn_t n, k[2];
	ep2_t p[2], r;

	bn_null(n);
	bn_null(k[0]);
	bn_null(k[1]);
	ep2_null(p[0]);
	ep2_null(p[1]);
	ep2_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k[0]);
		bn_new(k[1]);
		ep2_new(p[0]);
		ep2_new(p[1]);
		ep2_new(r);

		ep2_curve_get_gen(p[0]);
		ep2_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

#if EP_SIM == BASIC || !defined(STRIP)
		TEST_CASE("basic simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
		TEST_CASE("interleaving for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
		TEST_CASE("jsf for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul_gen(p[1], k[0]);
			ep2_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k[0]);
	bn_free(k[1]);
	ep2_free(p[0]);
	ep2_free(p[1]);
	ep2_free(r);
	return code;
}

static int compression(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("point compression is correct") {
			ep2_rand(a);
			ep2_pck(b, a);
			TEST_ASSERT(ep2_upk(c, b) == 1, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

static int hashing(void) {
	int code = RLC_ERR;
	bn_t n;
	ep2_t p;
	ep2_t q;
	uint8_t msg[5];

	bn_null(n);
	ep2_null(p);
	ep2_null(q);

	RLC_TRY {
		bn_new(n);
		ep2_new(p);
		ep2_new(q);

		ep2_curve_get_ord(n);

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map(p, msg, sizeof(msg));
			TEST_ASSERT(ep2_is_infty(p) == 0, end);
			ep2_map_dst(q, msg, sizeof(msg), (const uint8_t *)"RELIC", 5);
			TEST_ASSERT(ep2_cmp(p, q) == RLC_EQ, end);
			ep2_mul(p, p, n);
			TEST_ASSERT(ep2_is_infty(p) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep2_free(p);
	ep2_free(q);
	return code;
}

static int frobenius(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;
	bn_t d, n;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		bn_new(d);
		bn_new(n);

		ep2_curve_get_ord(n);

		TEST_CASE("frobenius and scalar multiplication are consistent") {
			ep2_rand(a);
			ep2_frb(b, a, 1);
			d->used = RLC_FP_DIGS;
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_mod(d, d, n);
			ep2_mul(c, a, d);
			TEST_ASSERT(ep2_cmp(c, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	bn_free(d);
	bn_free(n);
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the EPX module", 0);

	if (ep_param_set_any_pairf() == RLC_ERR) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	if (ep2_curve_is_twist() == 0) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	ep_param_print();

	util_banner("Utilities:", 1);

	if (memory() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (util() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Arithmetic:", 1);

	if (addition() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (subtraction() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (doubling() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (multiplication() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (fixed() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (simultaneous() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (compression() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (hashing() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (frobenius() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
