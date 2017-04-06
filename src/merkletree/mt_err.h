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
 * \brief Defines the error codes used by the Merkle Tree Library functions
 * and defines macros for facilitating error detection.
 */

#ifndef MT_ERR_H_
#define MT_ERR_H_

/*!
 * \brief Used to convey error information, if an Merkle Tree operation
 * fails.
 */
typedef enum mt_error {
  MT_SUCCESS           =  0, /*!< Operation terminated successfully */
  MT_ERR_OUT_Of_MEMORY = -1, /*!< There was not enough memory to complete the operation */
  MT_ERR_ILLEGAL_PARAM = -2, /*!< At least one of the specified parameters was illegal */
  MT_ERR_ILLEGAL_STATE = -3, /*!< The operation reached an illegal state */
  MT_ERR_ROOT_MISMATCH = -4, /*!< Signals the failure of a root hash verification */
  MT_ERR_UNSPECIFIED   = -5  /*!< A general error occurred */
} mt_error_t;

/*!
 * \brief wraps a given expression (e.g. a function call) with a test if the
 * result is not MT_SUCCESS and if this is the case returns the error code
 */
#define MT_ERR_CHK(f) do {mt_error_t r = f;if (r != MT_SUCCESS) {return r;}} while (0)


#endif /* MT_ERR_H_ */
