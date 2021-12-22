/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of the ElGamal cryptosystem.
 *
 * @ingroup cp
 */

#include <string.h>

#include "relic_core.h"
#include "relic_conf.h"
#include "relic_error.h"
#include "relic_rand.h"
#include "relic_bn.h"
#include "relic_util.h"
#include "relic_cp.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_elgamal_gen(elgamal_t pub, elgamal_t prv, int bits) {
	int result = STS_OK;

	RLC_TRY {
		/* Generate prime p. */
		bn_gen_prime(prv->q, bits);
		bn_copy(pub->q, prv->q);
		bn_rand(prv->x, 0, bits);
		bn_rand(prv->g, 0, bits);
		bn_mod_basic(prv->g, prv->g, prv->q);
		bn_copy(pub->g, prv->g);
		bn_mxp(pub->P, prv->g, prv->x, prv->q);
		bn_copy(prv->P, pub->P);
	}
	RLC_CATCH_ANY {
		result = STS_ERR;
	}
	RLC_FINALLY {
	}

	return result;
}

int cp_elgamal_enc(unsigned char *out, int *out_len, unsigned char *in,
		int in_len, elgamal_t pub) {
	bn_t m, b;
	elgamal_cipher_t c;
	int size, result = STS_OK;

	bn_null(m);
	bn_null(c->c1);
	bn_null(c->c2);
	bn_null(b);

	bn_size_bin(&size, pub->q);

	RLC_TRY {
		bn_new(m);
		bn_new(c->c1);
		bn_new(c->c2);
		bn_new(b);

		bn_zero(m);
		bn_zero(c->c1);
		bn_zero(c->c2);
		bn_zero(b);

		bn_read_bin(m, in, in_len);
		bn_add(c->c1, c->c1, m);

		bn_rand(b, 0, size);
		bn_mxp(c->c1, pub->g, b, pub->q);
		bn_mxp(c->c2, pub->P, b, pub->q);
		bn_mul(c->c2, m, c->c2);
		bn_mod_basic(c->c2, c->c2, pub->q);

		if (size <= *out_len) {
			*out_len = size;
			memset(out, 0, *out_len);
			bn_write_bin(out, size, c->c1);
			bn_write_bin(out+size, size, c->c2);
		} else {
			result = STS_ERR;
		}
	}
	RLC_CATCH_ANY {
		result = STS_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(c->c1);
		bn_free(c->c2);
		bn_free(b);

	}

	return result;
}

int cp_elgamal_dec(unsigned char *out, int *out_len, unsigned char *in,
		int in_len, elgamal_t prv) {
	bn_t m, c1, c2, r;
	int size, result = STS_OK;


	if (in_len < 0 || in_len != size) {
		return STS_ERR;
	}

	bn_null(m);
	bn_null(c1);
	bn_null(c2);
	bn_null(r);

	RLC_TRY {
		bn_new(m);
		bn_new(c1);
		bn_new(c2);
		bn_new(r);

		bn_read_bin(c1, in, size);
		bn_read_bin(c2, in+size, size);
		bn_mxp(c1, c1, prv->x, prv->q);
		bn_gcd_ext(r, c1, NULL, c1, prv->q); //TODO verificar se r = 1
		bn_mul(m, c1, c2);
		bn_mod_basic(m, m, prv->q);

		if (m->sign == BN_NEG) {
			bn_add(m, m, prv->q);
		}

		bn_size_bin(&size, m);

		if (bn_cmp(m, prv->q) != CMP_LT) {
			result = STS_ERR;
		}

		if (size <= *out_len) {
			memset(out, 0, size);
			bn_write_bin(out, size, m);
			*out_len = size;
		}
		else {
			result = STS_ERR;
		}
	}
	RLC_CATCH_ANY {
		result = STS_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(c1);
		bn_free(c2);
		bn_free(r);
	}

	return result;
}
