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
 * \brief Implements the Merkle Tree hash interface using SHA-256 the hash
 * function.
 */

#include "sha.h"

#include "mt_crypto.h"

//----------------------------------------------------------------------
mt_error_t mt_hash(const mt_hash_t left, const mt_hash_t right,
    mt_hash_t message_digest) {
  if (!(left && right && message_digest)) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  SHA256Context ctx;
  if (SHA256Reset(&ctx) != shaSuccess) {
    return MT_ERR_ILLEGAL_STATE;
  }
  if (SHA256Input(&ctx, left, HASH_LENGTH) != shaSuccess) {
    return MT_ERR_ILLEGAL_STATE;
  }
  if (SHA256Input(&ctx, right, HASH_LENGTH) != shaSuccess) {
    return MT_ERR_ILLEGAL_STATE;
  }
  if (SHA256Result(&ctx, message_digest) != shaSuccess) {
    return MT_ERR_ILLEGAL_STATE;
  }
  return MT_SUCCESS;
}

