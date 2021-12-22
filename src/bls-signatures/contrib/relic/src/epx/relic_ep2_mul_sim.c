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
 * Implementation of simultaneous point multiplication on a prime elliptic
 * curve over a quadratic extension.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_SIM == INTER || !defined(STRIP)

#if defined(EP_ENDOM)

/**
 * Recodes a scalar in subscalars according to Frobenius endomorphism.
 *
 * @param[out] _k			- the recoded subscalars.
 * @param[in] k				- the scalar to recode.
 */
static void ep2_glv(bn_t _k[4], const bn_t k) {
	int i, l;
	bn_t n, u[4], v[4];

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		for (i = 0; i < 4; i++) {
			bn_null(u[i]);
			bn_null(v[i]);
			bn_new(u[i]);
			bn_new(v[i]);
		}

		ep2_curve_get_ord(n);

		switch (ep_curve_is_pairf()) {
			case EP_BN:
				ep2_curve_get_vs(v);

				for (i = 0; i < 4; i++) {
					bn_mul(v[i], v[i], k);
					bn_div(v[i], v[i], n);
					if (bn_sign(v[i]) == RLC_NEG) {
						bn_add_dig(v[i], v[i], 1);
					}
					bn_zero(_k[i]);
				}

				/* u0 = x + 1, u1 = 2x + 1, u2 = 2x, u3 = x - 1. */
				fp_prime_get_par(u[0]);
				bn_dbl(u[2], u[0]);
				bn_add_dig(u[1], u[2], 1);
				bn_sub_dig(u[3], u[0], 1);
				bn_add_dig(u[0], u[0], 1);
				bn_copy(_k[0], k);
				for (i = 0; i < 4; i++) {
					bn_mul(u[i], u[i], v[i]);
					bn_mod(u[i], u[i], n);
					bn_add(_k[0], _k[0], n);
					bn_sub(_k[0], _k[0], u[i]);
					bn_mod(_k[0], _k[0], n);
				}

				/* u0 = x, u1 = -x, u2 = 2x + 1, u3 = 4x + 2. */
				fp_prime_get_par(u[0]);
				bn_neg(u[1], u[0]);
				bn_dbl(u[2], u[0]);
				bn_add_dig(u[2], u[2], 1);
				bn_dbl(u[3], u[2]);
				for (i = 0; i < 4; i++) {
					bn_mul(u[i], u[i], v[i]);
					bn_mod(u[i], u[i], n);
					bn_add(_k[1], _k[1], n);
					bn_sub(_k[1], _k[1], u[i]);
					bn_mod(_k[1], _k[1], n);
				}

				/* u0 = x, u1 = -(x + 1), u2 = 2x + 1, u3 = -(2x - 1). */
				fp_prime_get_par(u[0]);
				bn_add_dig(u[1], u[0], 1);
				bn_neg(u[1], u[1]);
				bn_dbl(u[2], u[0]);
				bn_add_dig(u[2], u[2], 1);
				bn_sub_dig(u[3], u[2], 2);
				bn_neg(u[3], u[3]);
				for (i = 0; i < 4; i++) {
					bn_mul(u[i], u[i], v[i]);
					bn_mod(u[i], u[i], n);
					bn_add(_k[2], _k[2], n);
					bn_sub(_k[2], _k[2], u[i]);
					bn_mod(_k[2], _k[2], n);
				}

				/* u0 = -2x, u1 = -x, u2 = 2x + 1, u3 = x - 1. */
				fp_prime_get_par(u[1]);
				bn_dbl(u[0], u[1]);
				bn_neg(u[0], u[0]);
				bn_dbl(u[2], u[1]);
				bn_add_dig(u[2], u[2], 1);
				bn_sub_dig(u[3], u[1], 1);
				bn_neg(u[1], u[1]);
				for (i = 0; i < 4; i++) {
					bn_mul(u[i], u[i], v[i]);
					bn_mod(u[i], u[i], n);
					bn_add(_k[3], _k[3], n);
					bn_sub(_k[3], _k[3], u[i]);
					bn_mod(_k[3], _k[3], n);
				}

				for (i = 0; i < 4; i++) {
					l = bn_bits(_k[i]);
					bn_sub(_k[i], n, _k[i]);
					if (bn_bits(_k[i]) > l) {
						bn_sub(_k[i], _k[i], n);
						_k[i]->sign = RLC_POS;
					} else {
						_k[i]->sign = RLC_NEG;
					}
				}
				break;
			default:
				bn_abs(v[0], k);
				fp_prime_get_par(u[0]);
				bn_copy(u[1], u[0]);
				if (bn_sign(u[0]) == RLC_NEG) {
					bn_neg(u[0], u[0]);
				}

				for (i = 0; i < 4; i++) {
					bn_mod(_k[i], v[0], u[0]);
					bn_div(v[0], v[0], u[0]);
					if ((bn_sign(u[1]) == RLC_NEG) && (i % 2 != 0)) {
						bn_neg(_k[i], _k[i]);
					}
					if (bn_sign(k) == RLC_NEG) {
						bn_neg(_k[i], _k[i]);
					}
				}

				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		for (i = 0; i < 4; i++) {
			bn_free(u[i]);
			bn_free(v[i]);
		}
	}
}

/**
 * Multiplies and adds two prime elliptic curve points simultaneously,
 * optionally choosing the first point as the generator depending on an optional
 * table of precomputed points.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 * @param[in] t					- the pointer to the precomputed table.
 */
static void ep2_mul_sim_endom(ep2_t r, ep2_t p, const bn_t k, ep2_t q, const bn_t m) {
	int i, j, l;
	bn_t _k[4], _m[4];
	ep2_t _p[4], _q[4];

	RLC_TRY {
		for (i = 0; i < 4; i++) {
			bn_null(_k[i]);
			bn_null(_m[i]);
			ep2_null(_p[i]);
			ep2_null(_q[i]);
			bn_new(_k[i]);
			bn_new(_m[i]);
			ep2_new(_p[i]);
			ep2_new(_q[i]);
		}

		ep2_glv(_k, k);
		ep2_glv(_m, m);

		ep2_norm(_p[0], p);
		ep2_frb(_p[1], _p[0], 1);
		ep2_frb(_p[2], _p[1], 1);
		ep2_frb(_p[3], _p[2], 1);
		ep2_norm(_q[0], q);
		ep2_frb(_q[1], _q[0], 1);
		ep2_frb(_q[2], _q[1], 1);
		ep2_frb(_q[3], _q[2], 1);

		for (i = 0; i < 4; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep2_neg(_p[i], _p[i]);
			}
			if (bn_sign(_m[i]) == RLC_NEG) {
				ep2_neg(_q[i], _q[i]);
			}
		}

		l = RLC_MAX(bn_bits(_k[0]), bn_bits(_k[1]));
		l = RLC_MAX(l, RLC_MAX(bn_bits(_k[2]), bn_bits(_k[3])));
		l = RLC_MAX(l, RLC_MAX(bn_bits(_m[0]), bn_bits(_m[1])));
		l = RLC_MAX(l, RLC_MAX(bn_bits(_m[2]), bn_bits(_m[3])));

		ep2_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep2_dbl(r, r);
			for (j = 0; j < 4; j++) {
				if (bn_get_bit(_k[j], i)) {
					ep2_add(r, r, _p[j]);
				}
				if (bn_get_bit(_m[j], i)) {
					ep2_add(r, r, _q[j]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (i = 0; i < 4; i++) {
			bn_free(_k[i]);
			bn_free(_m[i]);
			ep2_free(_p[i]);
			ep2_free(_q[i]);
		}
	}
}

#endif /* EP_ENDOM */

/**
 * Multiplies and adds two prime elliptic curve points simultaneously,
 * optionally choosing the first point as the generator depending on an optional
 * table of precomputed points.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 * @param[in] t					- the pointer to the precomputed table.
 */
static void ep2_mul_sim_plain(ep2_t r, ep2_t p, bn_t k, ep2_t q, bn_t m,
		ep2_t *t) {
	int i, l, l0, l1, n0, n1, w, gen;
	int8_t naf0[2 * RLC_FP_BITS + 1], naf1[2 * RLC_FP_BITS + 1], *_k, *_m;
	ep2_t t0[1 << (EP_WIDTH - 2)];
	ep2_t t1[1 << (EP_WIDTH - 2)];

	RLC_TRY {
		gen = (t == NULL ? 0 : 1);
		if (!gen) {
			for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
				ep2_null(t0[i]);
				ep2_new(t0[i]);
			}
			ep2_tab(t0, p, EP_WIDTH);
			t = (ep2_t *)t0;
		}

		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep2_null(t1[i]);
			ep2_new(t1[i]);
		}
		/* Compute the precomputation table. */
		ep2_tab(t1, q, EP_WIDTH);

		/* Compute the w-TNAF representation of k. */
		if (gen) {
			w = EP_DEPTH;
		} else {
			w = EP_WIDTH;
		}
		l0 = l1 = 2 * RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k, w);
		bn_rec_naf(naf1, &l1, m, EP_WIDTH);

		l = RLC_MAX(l0, l1);
		_k = naf0 + l - 1;
		_m = naf1 + l - 1;
		for (i = l0; i < l; i++) {
			naf0[i] = 0;
		}
		for (i = l1; i < l; i++) {
			naf1[i] = 0;
		}

		if (bn_sign(k) == RLC_NEG) {
			for (i =  0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(m) == RLC_NEG) {
			for (i =  0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		ep2_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--, _m--) {
			ep2_dbl(r, r);

			n0 = *_k;
			n1 = *_m;
			if (n0 > 0) {
				ep2_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ep2_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ep2_add(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				ep2_sub(r, r, t1[-n1 / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation tables. */
		if (!gen) {
			for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
				ep2_free(t0[i]);
			}
		}
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep2_free(t1[i]);
		}
	}
}

#endif /* EP_SIM == INTER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_SIM == BASIC || !defined(STRIP)

void ep2_mul_sim_basic(ep2_t r, ep2_t p, bn_t k, ep2_t q, bn_t l) {
	ep2_t t;

	ep2_null(t);

	RLC_TRY {
		ep2_new(t);
		ep2_mul(t, q, l);
		ep2_mul(r, p, k);
		ep2_add(t, t, r);
		ep2_norm(r, t);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t);
	}
}

#endif

#if EP_SIM == TRICK || !defined(STRIP)

void ep2_mul_sim_trick(ep2_t r, ep2_t p, bn_t k, ep2_t q, bn_t m) {
	ep2_t t0[1 << (EP_WIDTH / 2)];
	ep2_t t1[1 << (EP_WIDTH / 2)];
	ep2_t t[1 << EP_WIDTH];
	bn_t n;
	int l0, l1, w = EP_WIDTH / 2;
	uint8_t w0[2 * RLC_FP_BITS], w1[2 * RLC_FP_BITS];

	bn_null(n);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep2_is_infty(q)) {
		ep2_mul(r, p, k);
		return;
	}

	RLC_TRY {
		bn_new(n);

		ep2_curve_get_ord(n);

		for (int i = 0; i < (1 << w); i++) {
			ep2_null(t0[i]);
			ep2_null(t1[i]);
			ep2_new(t0[i]);
			ep2_new(t1[i]);
		}
		for (int i = 0; i < (1 << EP_WIDTH); i++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}

		ep2_set_infty(t0[0]);
		ep2_copy(t0[1], p);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(t0[1], t0[1]);
		}
		for (int i = 2; i < (1 << w); i++) {
			ep2_add(t0[i], t0[i - 1], t0[1]);
		}

		ep2_set_infty(t1[0]);
		ep2_copy(t1[1], q);
		if (bn_sign(m) == RLC_NEG) {
			ep2_neg(t1[1], t1[1]);
		}
		for (int i = 1; i < (1 << w); i++) {
			ep2_add(t1[i], t1[i - 1], t1[1]);
		}

		for (int i = 0; i < (1 << w); i++) {
			for (int j = 0; j < (1 << w); j++) {
				ep2_add(t[(i << w) + j], t0[i], t1[j]);
			}
		}

#if defined(EP_MIXED)
		ep2_norm_sim(t + 1, t + 1, (1 << (EP_WIDTH)) - 1);
#endif

		l0 = l1 = RLC_CEIL(2 * RLC_FP_BITS, w);
		bn_rec_win(w0, &l0, k, w);
		bn_rec_win(w1, &l1, m, w);

		for (int i = l0; i < l1; i++) {
			w0[i] = 0;
		}
		for (int i = l1; i < l0; i++) {
			w1[i] = 0;
		}

		ep2_set_infty(r);
		for (int i = RLC_MAX(l0, l1) - 1; i >= 0; i--) {
			for (int j = 0; j < w; j++) {
				ep2_dbl(r, r);
			}
			ep2_add(r, r, t[(w0[i] << w) + w1[i]]);
		}
		ep2_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (int i = 0; i < (1 << w); i++) {
			ep2_free(t0[i]);
			ep2_free(t1[i]);
		}
		for (int i = 0; i < (1 << EP_WIDTH); i++) {
			ep2_free(t[i]);
		}
	}
}
#endif

#if EP_SIM == INTER || !defined(STRIP)

void ep2_mul_sim_inter(ep2_t r, ep2_t p, bn_t k, ep2_t q, bn_t m) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep2_is_infty(q)) {
		ep2_mul(r, p, k);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		if (ep_curve_opt_a() == RLC_ZERO) {
			ep2_mul_sim_endom(r, p, k, q, m);
		} else {
			ep2_mul_sim_plain(r, p, k, q, m, NULL);
		}
		return;
	}
#endif

#if defined(EP_PLAIN)
	ep2_mul_sim_plain(r, p, k, q, m, NULL);
#endif
}

#endif

#if EP_SIM == JOINT || !defined(STRIP)

void ep2_mul_sim_joint(ep2_t r, ep2_t p, bn_t k, ep2_t q, bn_t m) {
	ep2_t t[5];
	int i, l, u_i, offset;
	int8_t jsf[4 * (RLC_FP_BITS + 1)];

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep2_is_infty(q)) {
		ep2_mul(r, p, k);
		return;
	}

	RLC_TRY {
		for (i = 0; i < 5; i++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}

		ep2_set_infty(t[0]);
		ep2_copy(t[1], q);
		if (bn_sign(m) == RLC_NEG) {
			ep2_neg(t[1], t[1]);
		}
		ep2_copy(t[2], p);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(t[2], t[2]);
		}
		ep2_add(t[3], t[2], t[1]);
		ep2_sub(t[4], t[2], t[1]);
#if defined(EP_MIXED)
		ep2_norm_sim(t + 3, t + 3, 2);
#endif

		l = 4 * (RLC_FP_BITS + 1);
		bn_rec_jsf(jsf, &l, k, m);

		ep2_set_infty(r);

		offset = RLC_MAX(bn_bits(k), bn_bits(m)) + 1;
		for (i = l - 1; i >= 0; i--) {
			ep2_dbl(r, r);
			if (jsf[i] != 0 && jsf[i] == -jsf[i + offset]) {
				u_i = jsf[i] * 2 + jsf[i + offset];
				if (u_i < 0) {
					ep2_sub(r, r, t[4]);
				} else {
					ep2_add(r, r, t[4]);
				}
			} else {
				u_i = jsf[i] * 2 + jsf[i + offset];
				if (u_i < 0) {
					ep2_sub(r, r, t[-u_i]);
				} else {
					ep2_add(r, r, t[u_i]);
				}
			}
		}
		ep2_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < 5; i++) {
			ep2_free(t[i]);
		}
	}
}

#endif

void ep2_mul_sim_gen(ep2_t r, bn_t k, ep2_t q, bn_t m) {
	ep2_t gen;

	ep2_null(gen);

	if (bn_is_zero(k)) {
		ep2_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep2_is_infty(q)) {
		ep2_mul_gen(r, k);
		return;
	}

	RLC_TRY {
		ep2_new(gen);

		ep2_curve_get_gen(gen);
#if EP_FIX == LWNAF && defined(EP_PRECO)
		ep2_mul_sim_plain(r, gen, k, q, m, ep2_curve_get_tab());
#else
		ep2_mul_sim(r, gen, k, q, m);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(gen);
	}
}

void ep2_mul_sim_dig(ep2_t r, ep2_t p[], dig_t k[], int len) {
	ep2_t t;
	int max;

	ep2_null(t);

	max = util_bits_dig(k[0]);
	for (int i = 1; i < len; i++) {
		max = RLC_MAX(max, util_bits_dig(k[i]));
	}

	RLC_TRY {
		ep2_new(t);

		ep2_set_infty(t);
		for (int i = max - 1; i >= 0; i--) {
			ep2_dbl(t, t);
			for (int j = 0; j < len; j++) {
				if (k[j] & ((dig_t)1 << i)) {
					ep2_add(t, t, p[j]);
				}
			}
		}

		ep2_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t);
	}
}

void ep2_mul_sim_lot(ep2_t r, ep2_t p[], const bn_t k[], int n) {
	const int len = RLC_FP_BITS + 1;
	int i, j, m, l, *_l = RLC_ALLOCA(int, 4 * n);
	bn_t _k[4];
	int8_t *naf = RLC_ALLOCA(int8_t, 4 * n * len);

	if (n <= 10) {
		ep2_t *_p = RLC_ALLOCA(ep2_t, 4 * n);

		RLC_TRY {
			for (j = 0; j < 4; j++) {
				bn_null(_k[j]);
				bn_new(_k[j]);
				for (i = 0; i < n; i++) {
					ep2_null(_p[4*i + j]);
					ep2_new(_p[4*i + j]);
				}
			}

			for (int i = 0; i < n; i++) {
				ep2_norm(_p[4*i], p[i]);
				ep2_frb(_p[4*i + 1], _p[4*i], 1);
				ep2_frb(_p[4*i + 2], _p[4*i + 1], 1);
				ep2_frb(_p[4*i + 3], _p[4*i + 2], 1);
			}

			l = 0;
			for (i = 0; i < n; i++) {
				ep2_glv(_k, k[i]);
				for (j = 0; j < 4; j++) {
					_l[4*i + j] = len;
					bn_rec_naf(&naf[(4*i + j)*len], &_l[4*i + j], _k[j], 2);
					if (bn_sign(_k[j]) == RLC_NEG) {
						ep2_neg(_p[4*i + j], _p[4*i + j]);
					}
					l = RLC_MAX(l, _l[4*i + j]);
				}
			}

			for (i = 0; i < n; i++) {
				for (j = 0; j < 4; j++) {
					for (m = _l[4*i + j]; m < l; m++) {
						naf[(4*i + j)*len + m] = 0;
					}
				}
			}

			ep2_set_infty(r);
			for (i = l - 1; i >= 0; i--) {
				ep2_dbl(r, r);
				for (j = 0; j < n; j++) {
					for (m = 0; m < 4; m++) {
						if (naf[(4*j + m)*len + i] > 0) {
							ep2_add(r, r, _p[4*j + m]);
						}
						if (naf[(4*j + m)*len + i] < 0) {
							ep2_sub(r, r, _p[4*j + m]);
						}
					}
				}
			}

			/* Convert r to affine coordinates. */
			ep2_norm(r, r);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			for (j = 0; j < 4; j++) {
				bn_free(_k[j]);
				for (i = 0; i < n; i++) {
					ep2_free(_p[4*i + j]);
				}
			}
			RLC_FREE(_l);
			RLC_FREE(_p);
			RLC_FREE(naf);
		}
	} else {
		const int w = RLC_MAX(2, util_bits_dig(n) - 2), c = (1 << (w - 2));
		ep2_t s, t, u, v, *_p = RLC_ALLOCA(ep2_t, 4 * c);
		int8_t ptr;

		RLC_TRY {
			ep2_null(s);
			ep2_null(t);
			ep2_null(u);
			ep2_null(v);
			ep2_new(s);
			ep2_new(t);
			ep2_new(u);
			ep2_new(v);
			for (i = 0; i < 4; i++) {
				bn_null(_k[i]);
				bn_new(_k[i]);
				for (j = 0; j < c; j++) {
					ep2_null(_p[i*c + j]);
					ep2_new(_p[i*c + j]);
					ep2_set_infty(_p[i*c + j]);
				}
			}

			l = 0;
			for (i = 0; i < n; i++) {
				ep2_glv(_k, k[i]);
				for (j = 0; j < 4; j++) {
					_l[4*i + j] = len;
					bn_rec_naf(&naf[(4*i + j)*len], &_l[4*i + j], _k[j], w);
					l = RLC_MAX(l, _l[4*i + j]);
				}
			}

			for (i = 0; i < n; i++) {
				for (j = 0; j < 4; j++) {
					for (m = _l[4*i + j]; m < l; m++) {
						naf[(4*i + j)*len + m] = 0;
					}
				}
			}

			ep2_set_infty(s);
			for (i = l - 1; i >= 0; i--) {
				for (j = 0; j < n; j++) {
					for (m = 0; m < 4; m++) {
						ptr = naf[(4*j + m)*len + i];
						if (ptr != 0) {
							ep2_copy(t, p[j]);
							if (ptr < 0) {
								ptr = -ptr;
								ep2_neg(t, t);
							}
							if (bn_sign(_k[m]) == RLC_NEG) {
								ep2_neg(t, t);
							}
							ep2_add(_p[m*c + (ptr >> 1)], _p[m*c + (ptr >> 1)], t);
						}
					}
				}

				ep2_set_infty(t);
				for (m = 3; m >= 0; m--) {
					ep2_frb(t, t, 1);
					ep2_set_infty(u);
					ep2_set_infty(v);
					for (j = c - 1; j >= 0; j--) {
						ep2_add(u, u, _p[m*c + j]);
						if (j == 0) {
							ep2_dbl(v, v);
						}
						ep2_add(v, v, u);
						ep2_set_infty(_p[m*c + j]);
					}
					ep2_add(t, t, v);
				}
				ep2_dbl(s, s);
				ep2_add(s, s, t);
			}

			/* Convert r to affine coordinates. */
			ep2_norm(r, s);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			ep2_free(s);
			ep2_free(t);
			ep2_free(u);
			ep2_free(v);
			for (i = 0; i < 4; i++) {
				bn_free(_k[i]);
				for (j = 0; j < c; j++) {
					ep2_free(_p[i*c + j]);
				}
			}
			RLC_FREE(_l);
			RLC_FREE(_p);
			RLC_FREE(naf);
		}
	}
}
