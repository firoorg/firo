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
 * \brief Defines the public interface for the Merkle Tree Library.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MERKLETREE_H_
#define MERKLETREE_H_

#include "mt_config.h"
#include "mt_err.h"
#include "mt_arr_list.h"

/*!
 * \brief defines the Merkle Tree data type
 *
 * A Merkle Tree is used for ...
 */
typedef struct merkle_tree {
  uint32_t elems;
  mt_al_t *level[TREE_LEVELS];
} mt_t;

/*!
 * \brief creates a new instance of the Merkle Tree data type
 *
 * This function tries to create a new Merkle Tree data type for ...
 */
mt_t *mt_create(void);
/*!
 *
 * \brief deletes the specified Merkle Tree instance
 *
 * \param[in] mt a pointer to the Merkle Tree instance to delete
 */
void mt_delete(mt_t *mt);

/*!
 *
 * @param mt[in]
 * @param hash[in]
 * @return MT_SUCCESS if adding the element is successful;
 *         MT_ERR_ILLEGAL_PARAM if any of the incoming parameters is null;
 *         MT_ERR_OUT_OF_MEMORY if the underlying array list cannot allocate
 *         any more space to grow;
 *         MT_ERR_ILLEGAL_STATE if an integer overflow in the allocation code
 *         occurs.
 */
mt_error_t mt_add(mt_t *mt, const uint8_t *tag, const size_t len);

/*!
 * \brief returns the size of the lowest level of the Merkle Tree; in other
 * terms the number of blocks in the protected storage backend
 * @param mt[in] the Merkle tree data type instance to get the size of
 * @return the number of blocks protected by the Merkle tree
 */
uint32_t mt_get_size(const mt_t *mt);

int mt_exists(mt_t *mt, const uint32_t offset);

mt_error_t mt_update(const mt_t *mt, const uint8_t *tag, const size_t len,
    const uint32_t offset);

mt_error_t mt_verify(const mt_t *mt, const uint8_t *tag, const size_t len,
    const uint32_t offset);

mt_error_t mt_truncate(mt_t *mt, uint32_t last_valid);

mt_error_t mt_get_root(mt_t *mt, mt_hash_t root);

/*!
 * \brief Prints a human readable representation of a hash in hexadecimal notation
 *
 * @param hash the hash to print
 */
void mt_print_hash(const mt_hash_t hash);

/*!
 * Print a human readable representation of the Merkle Tree
 * @param mt a pointer to the Merkle Tree data type instance to print
 */
void mt_print(const mt_t *mt);

#endif /* MERKLETREE_H_ */
#ifdef __cplusplus
}
#endif
