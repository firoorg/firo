/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the low-level multiple precision integer modular reduction
 * functions.
 *
 * @ingroup bn
 */

#include "relic_bn.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Accumulates a double precision digit in a triple register variable.
 *
 * @param[in,out] R2		- most significant word of the triple register.
 * @param[in,out] R1		- middle word of the triple register.
 * @param[in,out] R0		- lowest significant word of the triple register.
 * @param[in] A				- the first digit to multiply.
 * @param[in] B				- the second digit to multiply.
 */
#define COMBA_STEP_BN_MOD_LOW(R2, R1, R0, A, B)								\
	dbl_t r = (dbl_t)(A) * (dbl_t)(B);										\
	dig_t _r = (R1);														\
	(R0) += (dig_t)(r);														\
	(R1) += (R0) < (dig_t)(r);												\
	(R2) += (R1) < _r;														\
	(R1) += (dig_t)(r >> (dbl_t)RLC_DIG);									\
	(R2) += (R1) < (dig_t)(r >> (dbl_t)RLC_DIG);							\

/**
 * Accumulates a single precision digit in a triple register variable.
 *
 * @param[in,out] R2		- most significant word of the triple register.
 * @param[in,out] R1		- middle word of the triple register.
 * @param[in,out] R0		- lowest significant word of the triple register.
 * @param[in] A				- the first digit to accumulate.
 */
#define COMBA_ADD(R2, R1, R0, A)											\
	dig_t __r = (R1);														\
	(R0) += (A);															\
	(R1) += (R0) < (A);														\
	(R2) += (R1) < __r;														\

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_modn_low(dig_t *c, const dig_t *a, int sa, const dig_t *m, int sm, dig_t u) {
	int i, j;
	dig_t r0, r1, r2;
	dig_t *tmp, *tmpc;
	const dig_t *tmpm;

	tmpc = c;

	r0 = r1 = r2 = 0;
	for (i = 0; i < sm; i++, tmpc++, a++) {
		tmp = c;
		tmpm = m + i;
		for (j = 0; j < i; j++, tmp++, tmpm--) {
			COMBA_STEP_BN_MOD_LOW(r2, r1, r0, *tmp, *tmpm);
		}
		if (i < sa) {
			COMBA_ADD(r2, r1, r0, *a);
		}
		*tmpc = (dig_t)(r0 * u);
		COMBA_STEP_BN_MOD_LOW(r2, r1, r0, *tmpc, *m);
		r0 = r1;
		r1 = r2;
		r2 = 0;
	}
	for (i = sm; i < 2 * sm - 1; i++, a++) {
		tmp = c + (i - sm + 1);
		tmpm = m + sm - 1;
		for (j = i - sm + 1; j < sm; j++, tmp++, tmpm--) {
			COMBA_STEP_BN_MOD_LOW(r2, r1, r0, *tmp, *tmpm);
		}
		if (i < sa) {
			COMBA_ADD(r2, r1, r0, *a);
		}
		c[i - sm] = r0;
		r0 = r1;
		r1 = r2;
		r2 = 0;
	}

	if (i < sa) {
		COMBA_ADD(r2, r1, r0, *a);
	}
	c[sm - 1] = r0;
	if (r1) {
		bn_subn_low(c, c, m, sm);
	}
}
