/*
 * ref.h
 *
 *  Created on: May 11, 2018
 *      Author: bushido
 */

#ifndef SRC_REF_H_
#define SRC_REF_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "argon2.h"
#include "core.h"

#include "blake2/blamka-round-ref.h"
#include "blake2/blake2-impl.h"
#include "blake2/blake2.h"

/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * @next_block must be initialized.
 * @param prev_block Pointer to the previous block
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */
static void fill_block_mtp(const block *prev_block, const block *ref_block,
                       block *next_block, int with_xor, uint32_t block_index, uint8_t * hash_zero) {
    block blockR, block_tmp;
    unsigned i;

    /*
    printf("\n");
    printf("h0_Ref = ");
	int xx = 0;
	for (xx = 0; xx < ARGON2_PREHASH_SEED_LENGTH; xx++) {
		printf("%02x", hash_zero[xx]);
	}
	printf("\n");
	*/

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);
    /* Now blockR = ref_block + prev_block and block_tmp = ref_block + prev_block */
    if (with_xor) {
        /* Saving the next block contents for XOR over: */
        xor_block(&block_tmp, next_block);
        /* Now blockR = ref_block + prev_block and
           block_tmp = ref_block + prev_block + next_block */
    }

    uint32_t the_index[2] = {0, block_index};
    memcpy(&blockR.v[14], the_index, sizeof(uint64_t));
    memcpy(&blockR.v[16], hash_zero, sizeof(uint64_t));
    memcpy(&blockR.v[17], hash_zero + 8, sizeof(uint64_t));
    memcpy(&blockR.v[18], hash_zero + 16, sizeof(uint64_t));
    memcpy(&blockR.v[19], hash_zero + 24, sizeof(uint64_t));

    /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
       (16,17,..31)... finally (112,113,...127) */
    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
            blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
            blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
            blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
            blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
            blockR.v[16 * i + 15]);
    }

    /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
       (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
    for (i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
            blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
            blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
            blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
            blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
            blockR.v[2 * i + 113]);
    }

    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}


#endif /* SRC_REF_H_ */
