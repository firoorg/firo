/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
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
 * Implementation of the low-le&vel in&version functions.
 *
 * @&version $Id$
 * @ingroup fp
 */

#include "relic_bn.h"
#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_invn_asm(dig_t *, const dig_t *, const dig_t *);

void fp_invm_low(dig_t *c, const dig_t *a) {
	fp_t t, x1;
	int j, k;

	fp_null(t);
	fp_null(x1);

	RLC_TRY {
		fp_new(t);
		fp_new(x1);

		/* u = a, v = p, x1 = 1, x2 = 0, k = 0. */
		k = fp_invn_asm(x1, a, c);
		if (k > RLC_FP_DIGS * RLC_DIG) {
			t[0] = t[1] = t[2] = t[3] = 0;
			k = 512 - k;
			j = k % 64;
			k = k / 64;
			t[k] = (dig_t)1 << j;
			fp_mul(c, x1, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
		fp_free(x1);
	}
}
