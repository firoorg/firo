//
// Created by aizen on 4/9/17.
//

#include "mtp.h"

static const unsigned int d_mtp = 1;


unsigned int trailing_zeros(char str[64]) {
    unsigned int i, d;
    d = 0;
    for (i = 63; i > 0; i--) {
        if (str[i] == '0') {
            d++;
        }
        else {
            break;
        }
    }
    return d;
}


static void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}


void fill_block(__m128i *state, const block *ref_block, block *next_block, int with_xor) {
    __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
            block_XY[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
        }
    }
    else {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
        }
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }

    for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
    }
}


argon2_context init_argon2d_param(const char* input) {

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0
    argon2_context context;
    argon2_context *pContext = &context;

    unsigned char out[TEST_OUTLEN];
    //unsigned char pwd[TEST_PWDLEN];
    //unsigned char salt[TEST_SALTLEN];
    unsigned char secret[TEST_SECRETLEN];
    unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 1;
    unsigned m_cost = 2097152;
    unsigned lanes = 4;

    memset(pContext,0,sizeof(argon2_context));
    memset(&out[0], 0, sizeof(out));
    //memset(&pwd[0], nHeight + 1, TEST_OUTLEN);
    //memset(&salt[0], 2, TEST_SALTLEN);
    //memset(&secret[0], 3, TEST_SECRETLEN);
    //memset(&ad[0], 4, TEST_ADLEN);

    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.version = ARGON2_VERSION_NUMBER;
    context.pwd = (uint8_t*)input;
    context.pwdlen = TEST_PWDLEN;
    context.salt = (uint8_t*)input;
    context.saltlen = TEST_SALTLEN;
    context.secret = NULL;
    context.secretlen = TEST_SECRETLEN;
    context.ad = NULL;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    return context;
}


int fill_memory_blocks_mtp(argon2_instance_t *instance) {
    uint32_t r, s;
    argon2_thread_handle_t *thread = NULL;
    argon2_thread_data *thr_data = NULL;
    int rc = ARGON2_OK;

    if (instance == NULL || instance->lanes == 0) {
        rc = ARGON2_THREAD_FAIL;
        goto fail;
    }

    /* 1. Allocating space for threads */
    thread = (argon2_thread_handle_t *) calloc(instance->lanes, sizeof(argon2_thread_handle_t));
    if (thread == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    thr_data = (argon2_thread_data *) calloc(instance->lanes, sizeof(argon2_thread_data));
    if (thr_data == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            uint32_t l;

            /* 2. Calling threads */
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position;

                /* 2.1 Join a thread if limit is exceeded */
                if (l >= instance->threads) {
                    if (argon2_thread_join(thread[l - instance->threads])) {
                        rc = ARGON2_THREAD_FAIL;
                        goto fail;
                    }
                }

                /* 2.2 Create thread */
                position.pass = r;
                position.lane = l;
                position.slice = (uint8_t) s;
                position.index = 0;
                thr_data[l].instance_ptr = instance; /* preparing the thread input */
                memcpy(&(thr_data[l].pos), &position, sizeof(argon2_position_t));
                if (argon2_thread_create(&thread[l], &fill_segment_thr, (void *) &thr_data[l])) {
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }

                /* fill_segment(instance, position); */
                /*Non-thread equivalent of the lines above */
            }

            /* 3. Joining remaining threads */
            for (l = instance->lanes - instance->threads; l < instance->lanes; ++l) {
                if (argon2_thread_join(thread[l])) {
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }
            }
        }
    }
// fail to fill blocks with argon2d
fail:
    if (thread != NULL) {
        free(thread);
    }
    if (thr_data != NULL) {
        free(thr_data);
    }
    return rc;
}


int argon2_ctx(argon2_context *context, argon2_instance_t *instance) {

    printf("1. Validate all inputs \n");
    /* 1. Validate all inputs */
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    //argon2_instance_t instance;

    if (ARGON2_OK != result) {
        return result;
    }

    printf("2. Align memory size \n");
    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance->version = context->version;
    instance->memory = NULL;
    instance->passes = context->t_cost;
    instance->memory_blocks = memory_blocks;
    instance->segment_length = segment_length;
    instance->lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance->lanes = context->lanes;
    instance->threads = context->threads;
    instance->type = Argon2_d;

    printf("3. Initializatio n: Hashing inputs, allocating memory, filling first blocks\n");
    /* 3. Initialization: Hashing inputs, allocating memory, filling first blocks */
    result = initialize(instance, context);

    if (ARGON2_OK != result) {
        printf("result = %d\n", result);
        return result;
    }

    printf("4. Filling memory \n");
    /* 4. Filling memory */
    result = fill_memory_blocks_mtp(instance);

    if (ARGON2_OK != result) {
        return result;
    }
    /* 5. Finalization */
    //finalize(context, &instance);

    return ARGON2_OK;
}


int mtp_prover(CBlock *pblock, argon2_instance_t *instance, unsigned int d, char* output) {
    //internal_kat(instance, r); /* Print all memory blocks */
    printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
    // Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory
    if (instance != NULL) {
        printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
        mt_t *mt = mt_create();
        // TODO: remove 1024
        for (int i = 0; i < instance->memory_blocks / 1024; ++i) {
            block blockhash;
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            copy_block(&blockhash, &instance->memory[i]);
            store_block(&blockhash_bytes, &blockhash);
            // hash each block with sha256
            SHA256Context ctx;
            SHA256Context *pctx = &ctx;
            uint8_t hashBlock[32];
            int ret;
            ret = SHA256Reset(pctx);
            if (shaSuccess != ret) {
                return ret;
            }
            ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
            if (shaSuccess != ret) {
                return ret;
            }
            ret = SHA256Result(pctx, (uint8_t *) hashBlock);
            if (shaSuccess != ret) {
                return ret;
            }
            // add element to merkel tree
            mt_add(mt, blockhash_bytes, HASH_LENGTH);
            // add element to blockchain header
            memcpy(pblock->elementsInMerkleRoot[i], hashBlock, sizeof(uint8_t) * 32);
        }

        while (true) {
            printf("Step 3 : Select nonce N \n");
            pblock->nNonce += 1;
            uint8_t L = 70;
            uint8_t Y[L + 1][32];
            memset(&Y[0], 0, sizeof(Y));

            printf("Step 4 : Y0 = H(resultMerkelRoot, N) \n");
            mt_hash_t resultMerkleRoot;
            SHA256Context ctx;
            SHA256Context *pctx = &ctx;

            int ret;

            printf("Step 4.1 : resultMerkleRoot \n");
            ret = mt_get_root(mt, resultMerkleRoot);

            printf("Step 4.1 : resultMerkleRoot = 0x ");
            for (i = 0; i < 32; i++) {
               printf("%02x", resultMerkleRoot[i]);
            }
            printf("\n");
            if (MT_SUCCESS != ret) {
               return ret;
            }

            printf("Step 4.2 : SHA256Reset \n");
            ret = SHA256Reset(pctx);
            if (shaSuccess != ret) {
               return ret;
            }

            printf("Step 4.3 : SHA256Input resultMerkleRoot\n");
            ret = SHA256Input(pctx, resultMerkleRoot, HASH_LENGTH);
            if (shaSuccess != ret) {
               return ret;
            }

            uint8_t nNonce[2];
            memcpy(nNonce, (uint8_t * ) & pblock->nNonce, sizeof(nNonce));

            printf("Step 4.4 : SHA256Input nNonce\n");
            ret = SHA256Input(pctx, nNonce, 1);
            if (shaSuccess != ret) {
               return ret;
            }

            printf("Step 4.5 : SHA256Result\n");
            ret = SHA256Result(pctx, (uint8_t *) Y[0]);
            if (shaSuccess != ret) {
               return ret;
            }

            printf("Step 5 : For 1 <= j <= L \n");
            //I(j) = Y(j - 1) mod T;
            //Y(j) = H(Y(j - 1), X[I(j)])
            //block_with_offset blockhashInBlockchain[140];
            bool init_blocks = false;
            bool unmatch_block = false;
            for (uint8_t j = 1; j <= L; j++) {
                uint32_t ij = *Y[j - 1] % 2048;
                if (ij == 0 || ij == 1) {
                    init_blocks = true;
                    break;
                }

                // previous block
                pblock->blockhashInBlockchain[(j * 2) - 1].offset = instance->memory[ij].prev_block;
                copy_block(&pblock->blockhashInBlockchain[(j * 2) - 1].memory, &instance->memory[instance->memory[ij].prev_block]);
                pblock->blockhashInBlockchain[(j * 2) - 1].memory.prev_block = instance->memory[instance->memory[ij].prev_block].prev_block;
                pblock->blockhashInBlockchain[(j * 2) - 1].memory.ref_block = instance->memory[instance->memory[ij].prev_block].ref_block;
                // ref block
                pblock->blockhashInBlockchain[(j * 2) - 2].offset = instance->memory[ij].ref_block;
                copy_block(&pblock->blockhashInBlockchain[(j * 2) - 2].memory, &instance->memory[instance->memory[ij].ref_block]);
                pblock->blockhashInBlockchain[(j * 2) - 2].memory.prev_block = instance->memory[instance->memory[ij].ref_block].prev_block;
                pblock->blockhashInBlockchain[(j * 2) - 2].memory.ref_block = instance->memory[instance->memory[ij].ref_block].ref_block;

                block X_IJ;
                __m128i state_test[64];
                memset(state_test, 0, sizeof(state_test));
                memcpy(state_test, &pblock->blockhashInBlockchain[(j * 2) - 1].memory.v, ARGON2_BLOCK_SIZE);
                fill_block(state_test, &pblock->blockhashInBlockchain[(j * 2) - 2].memory, &X_IJ, 0);
                X_IJ.prev_block = instance->memory[ij].prev_block;
                X_IJ.ref_block = instance->memory[ij].ref_block;

                block blockhash;
                uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
                copy_block(&blockhash, &instance->memory[ij]);

                int countIndex;
                for (countIndex = 0; countIndex < 128; countIndex++) {
                   if (X_IJ.v[countIndex] != instance->memory[ij].v[countIndex]) {
                      unmatch_block = true;
                      break;
                   }
                }

                store_block(&blockhash_bytes, &blockhash);
                ret = SHA256Reset(pctx);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Input(pctx, (uint8_t *) Y[j - 1], HASH_LENGTH);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Result(pctx, (uint8_t *) Y[j]);
                if (shaSuccess != ret) {
                   return ret;
                }
            }

            if (init_blocks) {
                printf("Step 5.1 : init_blocks \n");
                continue;
            }

            if (unmatch_block) {
                printf("Step 5.2 : unmatch_block \n");
                continue;
            }

            //unsigned int d = d_mtp;

            printf("Current nBits: %s\n", CBigNum().SetCompact(pblock->nBits).getuint256().GetHex().c_str());
            printf("Current hash: ");

            char hex_tmp[64];
            int n;
            for (n = 0; n < 32; n++) {
                printf("%02x", Y[L][n]);
                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
            }
            printf("\n");

            printf("Step 6 : If Y(L) had d trailing zeros, then (resultMerkelroot, N, Y(L)) \n");
            //uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            //printf("*** hashTarget: %d %s ***\n", hashTarget, hashTarget.GetHex().c_str());
            if (trailing_zeros(hex_tmp) != d) {
                continue;
            } else {
                // Found a solution
                printf("Found a solution. Hash:");
                for (n = 0; n < 32; n++) {
                   printf("%02x", Y[L][n]);
                }
                printf("\n");
                // TODO: copy hash to output
                memcpy(output, Y[L], 32);
                return 0;
                //printf("O-2\n");
            }
            //printf("O-3\n");
        }
        //printf("O-4\n");
    }
    //printf("O-5\n");
    return 1;
}


bool mtp_verifier(unsigned int d, CBlock *pblock) {

    uint8_t L = 70;
    uint8_t Y_CLIENT[L+1][32];
    memset(&Y_CLIENT[0], 0, sizeof(Y_CLIENT));
    printf("Step 7 : Y_CLIENT(0) = H(resultMerkelRoot, N)\n");
    SHA256Context ctx_client;
    SHA256Context *pctx_client = &ctx_client;

    int ret, i, k;
    mt_hash_t resultMerkleRoot;
    mt_t *mt = mt_create();

    printf("Step 7.1 : get data from elementsInMerkleRoot[i]\n");
    for(i = 0; i < 2048; i++){
        mt_add(mt, pblock->elementsInMerkleRoot[i], HASH_LENGTH);
    }

    printf("Step 7.2 : get resultMerkleRoot\n");
    ret = mt_get_root(mt, resultMerkleRoot);
    printf("Step 7.2 : resultMerkleRoot = 0x");
    for(i = 0; i < 32; i++){
        printf("%02x", resultMerkleRoot[i]);
    }
    printf("\n");

    if(MT_SUCCESS != ret){
        return ret;
    }

    ret = SHA256Reset(pctx_client);
    if (shaSuccess != ret) {
        return ret;
    }

    ret = SHA256Input(pctx_client, resultMerkleRoot, HASH_LENGTH);
    if (shaSuccess != ret) {
        return ret;
    }

    uint8_t nNonceInBlock[2];
    memcpy(nNonceInBlock, (uint8_t*)&pblock->nNonce, sizeof(nNonceInBlock));

    ret = SHA256Input(pctx_client, nNonceInBlock, 1);
    if (shaSuccess != ret) {
        return ret;
    }

    ret = SHA256Result(pctx_client, (uint8_t*)Y_CLIENT[0]);
    if (shaSuccess != ret) {
        return ret;
    }

    printf("Y_CLIENT[0] = 0x");
    for (int n = 0; n < 32; n++) {
        printf("%02x", Y_CLIENT[0][n]);
    }
    printf("\n");

    printf("Step 8 : Verify all block\n");
    for (i = 0; i < L * 2; ++i) {
        block blockhash;
        copy_block(&blockhash, &pblock->blockhashInBlockchain[i].memory);
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
        store_block(&blockhash_bytes, &blockhash);

        // hash each block with sha256
        SHA256Context ctx;
        SHA256Context *pctx = &ctx;
        uint8_t hashBlock[32];
        int ret;
        ret = SHA256Reset(pctx);
        if (shaSuccess != ret) {
            return ret;
        }
        ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
        if (shaSuccess != ret) {
            return ret;
        }
        ret = SHA256Result(pctx, (uint8_t*)hashBlock);
        if (shaSuccess != ret) {
            return ret;
        }

        printf("hashBlock[%d] = ", i);
        for(k = 0; k < 32; k++){
            printf("%02x", hashBlock[k]);
        }
        printf(", offset = %zu", &pblock->blockhashInBlockchain[i].offset);
        printf("\n");

        if (mt_verify(mt, blockhash_bytes, HASH_LENGTH, &pblock->blockhashInBlockchain[i].offset) == MT_ERR_ROOT_MISMATCH) {
            return error("CheckProofOfWork() : Root mismatch error!");
        }
    }


    printf("Step 9 : Compute Y(L) from\n");
    for (uint8_t j = 1; j <= L; j++) {

        // X[I(j)] = F(X[i(j)-1], X[i(j)-2])
        block X_IJ;
        __m128i state_test[64];
        memcpy(state_test, &pblock->blockhashInBlockchain[(j * 2) - 1].memory.v, ARGON2_BLOCK_SIZE);
        fill_block(state_test, &pblock->blockhashInBlockchain[(j * 2) - 2].memory, &X_IJ, 0);

        //Y(j) = H(Y(j - 1), X[I(j)])
        block blockhash_client_tmp;
        uint8_t blockhash_bytes_client_tmp[ARGON2_BLOCK_SIZE];
        copy_block(&blockhash_client_tmp, &X_IJ);
        store_block(&blockhash_bytes_client_tmp, &blockhash_client_tmp);
        SHA256Context ctx_client_yl;
        SHA256Context *pctx_client_yl = &ctx_client_yl;

        ret = SHA256Reset(pctx_client_yl);
        if (shaSuccess != ret) {
            return ret;
        }
        ret = SHA256Input(pctx_client_yl, (uint8_t*)Y_CLIENT[j - 1], HASH_LENGTH);
        if (shaSuccess != ret) {
            return ret;
        }
        ret = SHA256Input(pctx_client_yl, blockhash_bytes_client_tmp, HASH_LENGTH);
        if (shaSuccess != ret) {
            return ret;
        }
        ret = SHA256Result(pctx_client_yl, (uint8_t*)Y_CLIENT[j]);
        if (shaSuccess != ret) {
            return ret;
        }
    }

    printf("Step 10 : Check Y(L) had d tralling zeros then agree\n");

    char hex_tmp[64];
    for (int n = 0; n < 32; n++) {
        sprintf(&hex_tmp[n * 2], "%02x", Y_CLIENT[L][n]);
    }
    if (trailing_zeros(hex_tmp) != d) {
        return error("CheckProofOfWork() : proof of work failed - mtp");
    } else {
        return true;
    }

}

//
void mtp_hash(char* output, const char* input, unsigned int d, CBlock *pblock) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx(&context, &instance);
    mtp_prover(pblock, &instance, d, output);
    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
}