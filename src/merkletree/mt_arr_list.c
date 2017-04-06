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
 * \brief Implements a resizeable array data type. The Merkle Tree uses one
 * resizeable array per level as data store for its nodes and leafs.
 */
#include "mt_arr_list.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

/*!
 * \brief Computes the next highest power of two
 *
 * This nice little algorithm is taken from
 * http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 */
static uint32_t round_next_power_two(uint32_t v)
{
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  v += (v == 0); // handle v == 0 edge case
  return v;
}

//----------------------------------------------------------------------
static int is_power_of_two(uint32_t v)
{
  return (v != 0) && ((v & (v - 1)) == 0);
}

//----------------------------------------------------------------------
mt_al_t *mt_al_create(void)
{
  return calloc(1, sizeof(mt_al_t));
}

//----------------------------------------------------------------------
void mt_al_delete(mt_al_t *mt_al)
{
  free(mt_al->store);
  free(mt_al);
}

//----------------------------------------------------------------------
mt_error_t mt_al_add(mt_al_t *mt_al, const mt_hash_t hash)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && hash)) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  if (mt_al->elems == 0) {
    // Add first element
    mt_al->store = malloc(HASH_LENGTH);
    if (!mt_al->store) {
      return MT_ERR_OUT_Of_MEMORY;
    }
  } else if (is_power_of_two(mt_al->elems)) {
    // Need more memory
    // Prevent integer overflow during size calculation
    if (((mt_al->elems << 1) < mt_al->elems)
        || (mt_al->elems << 1 > MT_AL_MAX_ELEMS)) {
      return MT_ERR_ILLEGAL_STATE;
    }
    size_t alloc = mt_al->elems * 2 * HASH_LENGTH;
    uint8_t *tmp = realloc(mt_al->store, alloc);
    if (!tmp) {
      return MT_ERR_OUT_Of_MEMORY;
    }
//    fprintf(stderr, "Allocated memory: %x, Old: %p, New: %p\n", alloc / HASH_LENGTH,
//        mt_al->store, tmp);
    mt_al->store = tmp;
  }
  memcpy(&mt_al->store[mt_al->elems * HASH_LENGTH], hash, HASH_LENGTH);
  mt_al->elems += 1;
  return MT_SUCCESS;
}

//----------------------------------------------------------------------
mt_error_t mt_al_update(const mt_al_t *mt_al, const mt_hash_t hash,
    const uint32_t offset)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && hash && offset < mt_al->elems)) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  memcpy(&mt_al->store[offset * HASH_LENGTH], hash, HASH_LENGTH);
  return MT_SUCCESS;
}

//----------------------------------------------------------------------
mt_error_t mt_al_update_if_exists(const mt_al_t *mt_al, const mt_hash_t hash,
    const uint32_t offset)
{
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && hash)) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  if (offset >= mt_al->elems) {
    return MT_SUCCESS;
  }
  memcpy(&mt_al->store[offset * HASH_LENGTH], hash, HASH_LENGTH);
  return MT_SUCCESS;
}

//----------------------------------------------------------------------
mt_error_t mt_al_add_or_update(mt_al_t *mt_al, const mt_hash_t hash,
    const uint32_t offset)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && hash) || offset > mt_al->elems) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  if (offset == mt_al->elems) {
    return mt_al_add(mt_al, hash);
  } else {
    return mt_al_update(mt_al, hash, offset);
  }
}

//----------------------------------------------------------------------
mt_error_t mt_al_truncate(mt_al_t *mt_al, const uint32_t elems)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && elems < mt_al->elems)) {
    return MT_ERR_ILLEGAL_PARAM;
  }
  mt_al->elems = elems;
  if (elems == 0) {
    free(mt_al->store);
    return MT_SUCCESS;
  }
  uint32_t alloc = round_next_power_two(elems) * HASH_LENGTH;
  uint8_t *tmp = realloc(mt_al->store, alloc);
  if (!tmp) {
    return MT_ERR_OUT_Of_MEMORY;
  }
//  fprintf(stderr, "Allocated memory: %x, Old: %p, New: %p\n",
//      alloc / HASH_LENGTH, mt_al->store, tmp);
  mt_al->store = tmp;
  return MT_SUCCESS;
}

//----------------------------------------------------------------------
const uint8_t *mt_al_get(const mt_al_t *mt_al, const uint32_t offset)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && offset < mt_al->elems)) {
    return NULL;
  }
  return &mt_al->store[offset * HASH_LENGTH];
}

//----------------------------------------------------------------------
void mt_al_print_hex_buffer(const uint8_t *buffer, const size_t size)
{
  if (!buffer) {
    fprintf(stderr,
        "[ERROR][mt_al_print_hex_buffer]: Merkle Tree array list is NULL");
    return;
  }
  for (size_t i = 0; i < size; ++i) {
    printf("%02X", buffer[i]);
  }
}

//----------------------------------------------------------------------
char *mt_al_sprint_hex_buffer(const uint8_t *buffer, const size_t size)
{
  if (!buffer) {
    fprintf(stderr,
        "[ERROR][mt_al_sprint_hex_buffer]: Merkle Tree array list is NULL");
    return NULL;
  }
  size_t to_alloc = size * (sizeof(char) * 2) + 1;
  char *str = malloc(to_alloc);
  for (size_t i = 0; i < size; ++i) {
    snprintf((str + (i*2)), 3, "%02X", buffer[i]);
  }
  return str;
}

//----------------------------------------------------------------------
void mt_al_print(const mt_al_t *mt_al)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!mt_al) {
    fprintf(stderr, "[ERROR][mt_al_print]: Merkle Tree array list is NULL");
    return;
  }
  printf("[%08X\n", (unsigned int)mt_al->elems);
  for (uint32_t i = 0; i < mt_al->elems; ++i) {
    mt_al_print_hex_buffer(&mt_al->store[i * HASH_LENGTH], HASH_LENGTH);
    printf("\n");
  }
  printf("]\n");
}
