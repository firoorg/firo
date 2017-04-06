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
 * \brief Global configuration and data types for the Merkle Tree Library.
 */

#ifndef MT_CONFIG_H_
#define MT_CONFIG_H_

#include <stdint.h>

#define HASH_LENGTH                      32u  /*!< The length of the hash function output in bytes */
#define TREE_LEVELS                      20u  /*!< The number of levels in the tree */
#define MT_AL_MAX_ELEMS              524288u  /*!< The maximum number of elements in a Merkle Tree array list. Essential for integer overflow protection! */

/*!
 * Hash data type.
 */
typedef uint8_t mt_hash_t[HASH_LENGTH];


#endif /* MT_CONFIG_H_ */
