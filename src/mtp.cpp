//
// Created by aizen on 4/9/17.
//
#include "mtp.h"
#include "libmerkletree/merkletree.h"

static const unsigned int d_mtp = 1;
static const uint8_t L = 70;
static const unsigned int memory_cost = 2097152;

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

    clear_internal_memory(block_XY, ARGON2_OWORDS_IN_BLOCK);
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
    //unsigned char secret[TEST_SECRETLEN];
    //unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 1;
    unsigned m_cost = memory_cost; // 2gb
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
                if (argon2_thread_create(&thread[l], (void *) &fill_segment_thr, (void *) &thr_data[l])) {
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
    //instance->type = Argon2_i;

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


bool mtp_prover(CBlock *pblock, argon2_instance_t *instance, uint256 hashTarget, uint256* output) {
    //internal_kat(instance, r); /* Print all memory blocks */
    //printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
    // Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory
    if (instance != NULL) {
        //printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
        //mt_t *mt = mt_create();
        vector<uint256> leaves; // 2gb
        for (long int i = 0; i < instance->memory_blocks; ++i) {
            block blockhash;
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            copy_block(&blockhash, &instance->memory[i]);
            store_block(&blockhash_bytes, &blockhash);
            // hash each block with sha256
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            uint256 hashBlock;
            SHA256_Update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
            SHA256_Final((unsigned char*)&hashBlock, &ctx);
            leaves.push_back(hashBlock);
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);            
            blockhash.prev_block = NULL;
            blockhash.ref_block = NULL;

        }

        //printf("Step 2.2 : Create merkle tree\n");
        merkletree mtree = merkletree(leaves);
        leaves.clear();
        vector<uint256>().swap(leaves);

        uint256* Y = NULL;
        Y = new uint256[L + 1];
        uint256 root = mtree.root();

        while (true) {
            //printf("Step 3 : Select nonce N \n");
            if(pblock->nNonce + 1 == UINT_MAX){
                break;
            }
            pblock->nNonce += 1;

            memset(&Y[0], 0, sizeof(Y));

            //printf("Step 4 : Y0 = H(resultMerkelRoot, N) \n");

            //printf("Merkel Root : %s\n", root.GetHex().c_str());
            SHA256_CTX ctx;
            SHA256_Init(&ctx);                        
            SHA256_Update(&ctx, &root, sizeof(uint256));            
            SHA256_Update(&ctx, &pblock->nNonce, sizeof(unsigned int));
            SHA256_Final((unsigned char*)&Y[0], &ctx);
            //printf("Y[0] = %s\n", Y[0].GetHex().c_str());

            //printf("Step 5 : For 1 <= j <= L \n");
            //I(j) = Y(j - 1) mod T;
            //Y(j) = H(Y(j - 1), X[I(j)])
            bool init_blocks = false;
            bool unmatch_block = false;
            for (uint8_t j = 1; j <= L; j++) {
                CBigNum Yij(Y[j - 1]);
                CBigNum MemCost(memory_cost);
                CBigNum result = Yij % MemCost;
                uint32_t ij = result.getuint();
                if (ij == 0 || ij == 1) {
                    init_blocks = true;
                    break;
                }

                // previous block
                copy_block(&pblock->blockhashInBlockchain[(j * 2) - 1].memory, &instance->memory[instance->memory[ij].prev_block]);
                pblock->blockhashInBlockchain[(j * 2) - 1].memory.prev_block = instance->memory[instance->memory[ij].prev_block].prev_block;
                pblock->blockhashInBlockchain[(j * 2) - 1].memory.ref_block = instance->memory[instance->memory[ij].prev_block].ref_block;

                block blockhash_previous;
                uint8_t blockhash_bytes_previous[ARGON2_BLOCK_SIZE];
                copy_block(&blockhash_previous, &instance->memory[instance->memory[ij].prev_block]);
                store_block(&blockhash_bytes_previous, &blockhash_previous);

                SHA256_CTX ctx_previous;
                SHA256_Init(&ctx_previous);
                SHA256_Update(&ctx_previous, blockhash_bytes_previous, ARGON2_BLOCK_SIZE);
                uint256 t_previous;
                SHA256_Final((unsigned char*)&t_previous, &ctx_previous);

                clear_internal_memory(blockhash_previous.v, ARGON2_BLOCK_SIZE);
                clear_internal_memory(blockhash_bytes_previous, ARGON2_BLOCK_SIZE);                
                blockhash_previous.prev_block = NULL;
                blockhash_previous.ref_block = NULL;
                vector<ProofNode> newproof = mtree.proof(t_previous);

                memcpy(pblock->blockhashInBlockchain[(j * 2) - 1].proof, serializeMTP(newproof), 4034);

                // ref block
                copy_block(&pblock->blockhashInBlockchain[(j * 2) - 2].memory, &instance->memory[instance->memory[ij].ref_block]);
                pblock->blockhashInBlockchain[(j * 2) - 2].memory.prev_block = instance->memory[instance->memory[ij].ref_block].prev_block;
                pblock->blockhashInBlockchain[(j * 2) - 2].memory.ref_block = instance->memory[instance->memory[ij].ref_block].ref_block;


                block blockhash_ref_block;
                uint8_t blockhash_bytes_ref_block[ARGON2_BLOCK_SIZE];
                copy_block(&blockhash_ref_block, &instance->memory[instance->memory[ij].ref_block]);
                store_block(&blockhash_bytes_ref_block, &blockhash_ref_block);

                SHA256_CTX ctx_ref;
                SHA256_Init(&ctx_ref);
                SHA256_Update(&ctx_ref, blockhash_bytes_ref_block, ARGON2_BLOCK_SIZE);
                uint256 t_ref_block;
                SHA256_Final((unsigned char*)&t_ref_block, &ctx_ref);
                vector<ProofNode> newproof_ref = mtree.proof(t_ref_block);
                clear_internal_memory(blockhash_ref_block.v, ARGON2_BLOCK_SIZE);
                clear_internal_memory(blockhash_bytes_ref_block, ARGON2_BLOCK_SIZE);

                blockhash_ref_block.prev_block = NULL;
                blockhash_ref_block.ref_block = NULL;

                memcpy(pblock->blockhashInBlockchain[(j * 2) - 2].proof,serializeMTP(newproof_ref),4034);


                block X_IJ;
                __m128i state_test[64];
                memset(state_test, 0, sizeof(state_test));
                memcpy(state_test, &pblock->blockhashInBlockchain[(j * 2) - 1].memory.v, ARGON2_BLOCK_SIZE);
                fill_block(state_test, &pblock->blockhashInBlockchain[(j * 2) - 2].memory, &X_IJ, 0);
                X_IJ.prev_block = instance->memory[ij].prev_block;
                X_IJ.ref_block = instance->memory[ij].ref_block;
                clear_internal_memory(state_test, sizeof(__m128i) * 64);


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

                SHA256_CTX ctx_yj;
                SHA256_Init(&ctx_yj);
                SHA256_Update(&ctx_yj, &Y[j - 1], sizeof(uint256));
                SHA256_Update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
                SHA256_Final((unsigned char*)&Y[j], &ctx_yj);
                clear_internal_memory(X_IJ.v, ARGON2_BLOCK_SIZE);
                clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
                clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

                X_IJ.prev_block = NULL;
                X_IJ.ref_block = NULL;
                blockhash.prev_block = NULL;
                blockhash.ref_block = NULL;

                newproof.clear();
                newproof_ref.clear();
                vector<ProofNode>().swap(newproof);
                vector<ProofNode>().swap(newproof_ref);
            }

            if (init_blocks) {
                //printf("Step 5.1 : init_blocks \n");
                continue;
            }

            if (unmatch_block) {
                //printf("Step 5.2 : unmatch_block \n");
                continue;
            }

            //printf("Step 6 : If Y(L) had d trailing zeros, then send (resultMerkelroot, N, Y(L)) \n");
            if (Y[L] > hashTarget) {                
                continue;
            } else {
                // Found a solution
                printf("Y[L] = %s\n", Y[L].GetHex().c_str());
                //printf("Merkel Root = %s\n", root.GetHex().c_str());
                pblock->mtpMerkleRoot = root;
                output->SetHex(Y[L].GetHex().c_str());
                mtree.tree.clear();
                vector<uint256>().swap(mtree.tree);
                delete [] Y;
                return true;
            }
        }

        delete [] Y;
        mtree.tree.clear();
        vector<uint256>().swap(mtree.tree);
    }

    return false;
}


bool mtp_verifier(uint256 hashTarget, CBlock *pblock, uint256 *yL) {

    uint256 Y_CLIENT[L + 1];

    //printf("Step 7 : Y_CLIENT(0) = H(resultMerkelRoot, N)\n");
    SHA256_CTX ctx_client;
    SHA256_Init(&ctx_client);
    SHA256_Update(&ctx_client, &pblock->mtpMerkleRoot, sizeof(uint256));
    SHA256_Update(&ctx_client, &pblock->nNonce, sizeof(unsigned int));
    SHA256_Final((unsigned char*)&Y_CLIENT[0], &ctx_client);
    //printf("mtpMerkelRoot = %s\n", pblock->mtpMerkleRoot.GetHex().c_str());
    //printf("Y_CLIENT[0] = %s\n", Y_CLIENT[0].GetHex().c_str());

    int i = 0;
    //printf("Step 8 : Verify all block\n");
    for (i = 0; i < L * 2; ++i) {
        block blockhash;
        copy_block(&blockhash, &pblock->blockhashInBlockchain[i].memory);
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
        store_block(&blockhash_bytes, &blockhash);

        // hash each block with sha256
        uint256 hashBlock;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
        SHA256_Final((unsigned char*)&hashBlock, &ctx);
        clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

        //printf("hashBlock[%d] = %s\n", i, hashBlock.GetHex().c_str());

        uint256 mtpMerkelRoot;
        mtpMerkelRoot.SetHex(pblock->mtpMerkleRoot.GetHex());
        //printf("mtpMerkelRoot = %s\n", mtpMerkelRoot.GetHex().c_str());

        //printf("pblock->blockhashInBlockchain[i].proof = %s\n", pblock->blockhashInBlockchain[i].proof);
        vector<ProofNode> result = deserializeMTP(pblock->blockhashInBlockchain[i].proof);
        if (!verifyProof(hashBlock, mtpMerkelRoot, result)) {
            return error("CheckProofOfWork() : Root mismatch error!");
        }
    }


    //printf("Step 9 : Compute Y(L) from\n");
    for (uint8_t j = 1; j <= L; j++) {

        // X[I(j)] = F(X[i(j)-1], X[i(j)-2])
        block X_IJ;
        __m128i state_test[64];
        memset(state_test, 0, sizeof(state_test));
        memcpy(state_test, &pblock->blockhashInBlockchain[(j * 2) - 1].memory.v, ARGON2_BLOCK_SIZE);
        fill_block(state_test, &pblock->blockhashInBlockchain[(j * 2) - 2].memory, &X_IJ, 0);

        //Y(j) = H(Y(j - 1), X[I(j)])
        block blockhash_client_tmp;
        uint8_t blockhash_bytes_client_tmp[ARGON2_BLOCK_SIZE];
        copy_block(&blockhash_client_tmp, &X_IJ);
        store_block(&blockhash_bytes_client_tmp, &blockhash_client_tmp);
        SHA256_CTX ctx_client_yl;
        SHA256_Init(&ctx_client_yl);
        SHA256_Update(&ctx_client_yl, &Y_CLIENT[j - 1], sizeof(uint256));
        SHA256_Update(&ctx_client_yl, blockhash_bytes_client_tmp, 1024);
        SHA256_Final((unsigned char*)&Y_CLIENT[j], &ctx_client_yl);
        clear_internal_memory(blockhash_client_tmp.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes_client_tmp, ARGON2_BLOCK_SIZE);
    }

    //printf("Step 10 : Check Y(L) had d tralling zeros then agree\n");
    printf("Y_CLIENT[L] = %s\n", Y_CLIENT[L].GetHex().c_str());

    if (Y_CLIENT[L] > hashTarget) {
        return error("CheckProofOfWork() : proof of work failed - mtp");
    } else {
        yL->SetHex(Y_CLIENT[L].GetHex());
        return true;
    }

}


bool mtp_verifier(uint256 hashTarget, uint256 mtpMerkleRoot, unsigned int nNonce,const block_with_offset blockhashInBlockchain[140], uint256 *yL) {

    uint256 Y_CLIENT[L + 1];

    //printf("Step 7 : Y_CLIENT(0) = H(resultMerkelRoot, N)\n");
    SHA256_CTX ctx_client;
    SHA256_Init(&ctx_client);
    SHA256_Update(&ctx_client, &mtpMerkleRoot, sizeof(uint256));
    SHA256_Update(&ctx_client, &nNonce, sizeof(unsigned int));
    SHA256_Final((unsigned char*)&Y_CLIENT[0], &ctx_client);
    //printf("mtpMerkelRoot = %s\n", pblock->mtpMerkleRoot.GetHex().c_str());
    //printf("Y_CLIENT[0] = %s\n", Y_CLIENT[0].GetHex().c_str());

    int i = 0;
    //printf("Step 8 : Verify all block\n");
    for (i = 0; i < L * 2; ++i) {
        block blockhash;
        copy_block(&blockhash, &blockhashInBlockchain[i].memory);
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
        store_block(&blockhash_bytes, &blockhash);

        // hash each block with sha256
        uint256 hashBlock;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
        SHA256_Final((unsigned char*)&hashBlock, &ctx);

        clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

        //printf("hashBlock[%d] = %s\n", i, hashBlock.GetHex().c_str());

        uint256 mtpMerkelRoot;
        mtpMerkelRoot.SetHex(mtpMerkleRoot.GetHex());
        //printf("mtpMerkelRoot = %s\n", mtpMerkelRoot.GetHex().c_str());

        //printf("pblock->blockhashInBlockchain[i].proof = %s\n", pblock->blockhashInBlockchain[i].proof);
        vector<ProofNode> result = deserializeMTP(blockhashInBlockchain[i].proof);
        if (!verifyProof(hashBlock, mtpMerkelRoot, result)) {
            return error("CheckProofOfWork() : Root mismatch error!");
        }
    }


    //printf("Step 9 : Compute Y(L) from\n");
    for (uint8_t j = 1; j <= L; j++) {

        // X[I(j)] = F(X[i(j)-1], X[i(j)-2])
        block X_IJ;
        __m128i state_test[64];
        memset(state_test, 0, sizeof(state_test));
        memcpy(state_test, &blockhashInBlockchain[(j * 2) - 1].memory.v, ARGON2_BLOCK_SIZE);
        fill_block(state_test, &blockhashInBlockchain[(j * 2) - 2].memory, &X_IJ, 0);

        //Y(j) = H(Y(j - 1), X[I(j)])
        block blockhash_client_tmp;
        uint8_t blockhash_bytes_client_tmp[ARGON2_BLOCK_SIZE];
        copy_block(&blockhash_client_tmp, &X_IJ);
        store_block(&blockhash_bytes_client_tmp, &blockhash_client_tmp);
        SHA256_CTX ctx_client_yl;
        SHA256_Init(&ctx_client_yl);
        SHA256_Update(&ctx_client_yl, &Y_CLIENT[j - 1], sizeof(uint256));
        SHA256_Update(&ctx_client_yl, blockhash_bytes_client_tmp, 1024);
        SHA256_Final((unsigned char*)&Y_CLIENT[j], &ctx_client_yl);
        clear_internal_memory(blockhash_client_tmp.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes_client_tmp, ARGON2_BLOCK_SIZE);

    }

    //printf("Step 10 : Check Y(L) had d tralling zeros then agree\n");
    printf("Y_CLIENT[L] = %s\n", Y_CLIENT[L].GetHex().c_str());

    if (Y_CLIENT[L] > hashTarget) {
        return error("CheckProofOfWork() : proof of work failed - mtp");
    } else {
        yL->SetHex(Y_CLIENT[L].GetHex());
        return true;
    }

}

//
bool mtp_hash(uint256* output, const char* input, uint256 hashTarget, CBlock *pblock) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx(&context, &instance);
    bool result = mtp_prover(pblock, &instance, hashTarget, output);
    finalize(&context, &instance);
    return result;
    //free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
}
