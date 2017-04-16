/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Merkle Tree Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Merkle Tree Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Merkle Tree Library. If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 * \brief Defines the interface between the Merkle Tree data type and actual
 * hash implementation used for computing its hashes.
 */

#ifndef MT_CRYPTO_H_
#define MT_CRYPTO_H_

#include "mt_config.h"
#include "mt_err.h"

/*!
 * \brief Compute the hash of the left input concatenated with the right input.
 *
 * This function computes the following: h(left||right),
 * where h is the hash function, left is the left subtree root hash, right is
 * the right subtree root hash, and || is the concatination operation.
 *
 * @param left[in] the root hash of the left subtree
 * @param right[in] the root hash of the right subtree
 * @param message_digest[out] the result of h(left||right)
 * @return MT_SUCCESS if computing the hash was successful;
 *         MT_ERR_ILLEGAL_PARAM if any of the incoming parameters is null;
 *         MT_ERR_ILLEGAL_STATE if the underlying hash function reports an
 *         error.
 */
mt_error_t mt_hash(const mt_hash_t left, const mt_hash_t right,
    mt_hash_t message_digest);

#endif /* MT_CRYPTO_H_ */
