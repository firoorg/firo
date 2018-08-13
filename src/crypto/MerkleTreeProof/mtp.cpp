#include "mtp.h"
#include "util.h"
#include "arith_uint256.h"

extern "C" {
#include "blake2/blake2.h"
#include "blake2/blake2-impl.h"
#include "blake2/blamka-round-ref.h"
#include "core.h"
#include "ref.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

#include <iostream>
#include <sstream>
#include <iomanip>
#include "merkle-tree.hpp"
#include "primitives/block.h"
#include "streams.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/conversion/cast.hpp>

using boost::numeric_cast;
using boost::numeric::bad_numeric_cast;
using boost::numeric::positive_overflow;
using boost::numeric::negative_overflow;

extern int validate_inputs(const argon2_context *context);
extern void clear_internal_memory(void *v, size_t n);

namespace mtp
{

namespace {

const int8_t L = 72;
const unsigned T_COST = 1;
const unsigned M_COST = 1024 * 1024 * 4;
const unsigned LANES = 4;

void StoreBlock(void *output, const block *src)
{
    for (unsigned i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64(static_cast<uint8_t*>(output)
                + (i * sizeof(src->v[i])), src->v[i]);
    }
}

int Argon2CtxMtp(argon2_context *context, argon2_type type,
        argon2_instance_t *instance)
{
    int result = validate_inputs(context);
    if (result != ARGON2_OK) {
        return result;
    }
    if ((type != Argon2_d) && (type != Argon2_i) && (type != Argon2_id)) {
        return ARGON2_INCORRECT_TYPE;
    }
    result = initialize(instance, context);
    if (result != ARGON2_OK) {
        return result;
    }
    result = fill_memory_blocks_mtp(instance, context);
    if (result != ARGON2_OK) {
        return result;
    }
    return ARGON2_OK;
}

uint32_t IndexBeta(const argon2_instance_t *instance,
        const argon2_position_t *position, uint32_t pseudo_rand,
        int same_lane)
{
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    uint32_t reference_area_size;
    if (position->pass == 0) {
        /* First pass */
        if (position->slice == 0) {
            /* First slice */
            reference_area_size = position->index - 1; // all but the previous
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    (position->slice * instance->segment_length)
                    + position->index - 1;
            } else {
                reference_area_size =
                    (position->slice * instance->segment_length)
                    + ((position->index == 0) ? -1 : 0);
            }
        }
    } else {
        /* Second pass */
        if (same_lane) {
            reference_area_size = instance->lane_length
                - instance->segment_length + position->index - 1;
        } else {
            reference_area_size = instance->lane_length
                - instance->segment_length + ((position->index == 0) ? -1 : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    uint64_t relative_position = pseudo_rand;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1
        - ((reference_area_size * relative_position) >> 32);

    /* 1.2.5 Computing starting position */
    uint32_t start_position = 0;
    if (position->pass != 0) {
        start_position = (position->slice == (ARGON2_SYNC_POINTS - 1))
            ? 0
            : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    uint64_t absolute_position = (static_cast<uint64_t>(start_position)
            + relative_position) % static_cast<uint64_t>(instance->lane_length);
    return static_cast<uint32_t>(absolute_position);
}

void GetBlockIndex(uint32_t ij, argon2_instance_t *instance,
        uint32_t *out_ij_prev, uint32_t *out_computed_ref_block)
{
    uint32_t ij_prev = 0;
    if ((ij % instance->lane_length) == 0) {
        ij_prev = ij + instance->lane_length - 1;
    } else {
        ij_prev = ij - 1;
    }
    if ((ij % instance->lane_length) == 1) {
        ij_prev = ij - 1;
    }

    uint64_t prev_block_opening = instance->memory[ij_prev].v[0];
    uint32_t ref_lane = static_cast<uint32_t>((prev_block_opening >> 32)
            % static_cast<uint64_t>(instance->lanes));
    uint32_t pseudo_rand = static_cast<uint32_t>(prev_block_opening & 0xFFFFFFFF);
    uint32_t lane = ij / instance->lane_length;
    uint32_t slice = (ij - (lane * instance->lane_length))
        / instance->segment_length;
    uint32_t pos_index = ij - (lane * instance->lane_length)
        - (slice * instance->segment_length);
    if (slice == 0) {
        ref_lane = lane;
    }

    argon2_position_t position { 0, lane , (uint8_t)slice, pos_index };
    uint32_t ref_index = IndexBeta(instance, &position, pseudo_rand,
            ref_lane == position.lane);
    uint32_t computed_ref_block = (instance->lane_length * ref_lane) + ref_index;
    *out_ij_prev = ij_prev;
    *out_computed_ref_block = computed_ref_block;
}

/** Compute a BLAKE2B hash on a block
 *
 * \param input  [in]  Block to compute the hash on
 * \param digest [out] Computed hash
 */
void compute_blake2b(const block& input,
        uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B])
{
    block tmp_block;
    copy_block(&tmp_block, &input);
    uint8_t tmp_block_bytes[ARGON2_BLOCK_SIZE];
    StoreBlock(&tmp_block_bytes, &tmp_block);

    blake2b_state state;
    blake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
    blake2b_4r_update(&state, tmp_block_bytes, ARGON2_BLOCK_SIZE);

    blake2b_4r_final(&state, digest, MERKLE_TREE_ELEMENT_SIZE_B);
    clear_internal_memory(tmp_block.v, ARGON2_BLOCK_SIZE);
    clear_internal_memory(tmp_block_bytes, ARGON2_BLOCK_SIZE);
}

struct TargetHelper
{
    bool m_negative;
    bool m_overflow;
    arith_uint256 m_target;

    TargetHelper(uint32_t target)
    {
       m_target.SetCompact(target, &m_negative, &m_overflow);
    }
};

} // unnamed namespace

namespace impl
{

bool mtp_verify(const char* input, const uint32_t target,
        const uint8_t hash_root_mtp[16], uint32_t nonce,
        const uint64_t block_mtp[72*2][128],
        const std::deque<std::vector<uint8_t>> proof_mtp[73*3],
        uint256 pow_limit)
{
    MerkleTree::Elements proof_blocks[L * 3];
    MerkleTree::Buffer root;
    block blocks[L * 2];
    root.insert(root.begin(), &hash_root_mtp[0], &hash_root_mtp[16]);
    for (int i = 0; i < (L * 3); ++i) {
        proof_blocks[i] = proof_mtp[i];
    }
    for(int i = 0; i < (L * 2); ++i) {
        std::memcpy(blocks[i].v, block_mtp[i],
                sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
    }

    LogPrintf("START mtp_verify\n");

    LogPrintf("pblock->hash_root_mtp:\n");
    for (int i = 0; i < 16; ++i) {
        LogPrintf("%0x", root[i]);
    }
    LogPrintf("\n");
    LogPrintf("pblock->nNonce: %s\n", nonce);
    LogPrintf("pblock->nBlockMTP:\n");
    for (int i = 0; i < 1; ++i) {
        LogPrintf("%s = ", i);
        for (int j = 0; j < 10; ++j) {
            LogPrintf("%0x", blocks[i].v[j]);
        }
        LogPrintf("\n");
    }

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0

    unsigned char out[TEST_OUTLEN];
    unsigned char pwd[TEST_PWDLEN];
    std::memcpy(pwd, input, TEST_PWDLEN);
    unsigned char salt[TEST_SALTLEN];
    std::memcpy(salt, input, TEST_SALTLEN);

    argon2_context context_verify;
    context_verify.out = out;
    context_verify.outlen = TEST_OUTLEN;
    context_verify.version = ARGON2_VERSION_NUMBER;
    context_verify.pwd = pwd;
    context_verify.pwdlen = TEST_PWDLEN;
    context_verify.salt = salt;
    context_verify.saltlen = TEST_SALTLEN;
    context_verify.secret = NULL;
    context_verify.secretlen = TEST_SECRETLEN;
    context_verify.ad = NULL;
    context_verify.adlen = TEST_ADLEN;
    context_verify.t_cost = T_COST;
    context_verify.m_cost = M_COST;
    context_verify.lanes = LANES;
    context_verify.threads = LANES;
    context_verify.allocate_cbk = NULL;
    context_verify.free_cbk = NULL;
    context_verify.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    uint32_t memory_blocks = context_verify.m_cost;
    if (memory_blocks < (2 * ARGON2_SYNC_POINTS * context_verify.lanes)) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context_verify.lanes;
    }
    uint32_t segment_length = memory_blocks / (context_verify.lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context_verify.lanes * ARGON2_SYNC_POINTS);

    argon2_instance_t instance;
    instance.version = context_verify.version;
    instance.memory = NULL;
    instance.passes = context_verify.t_cost;
    instance.memory_blocks = context_verify.m_cost;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context_verify.lanes;
    instance.threads = context_verify.threads;
    instance.type = Argon2_d;
    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    // step 7
    uint256 y[L + 1];
    std::memset(&y[0], 0, sizeof(y));

    blake2b_state state_y0;
    blake2b_init(&state_y0, 32); // 256 bit
    blake2b_update(&state_y0, input, 80);
    blake2b_update(&state_y0, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
    blake2b_update(&state_y0, &nonce, sizeof(unsigned int));
    blake2b_final(&state_y0, &y[0], sizeof(uint256));

    LogPrintf("y[0] = %s\n", y[0].ToString());

    LogPrintf("input = \n");
    for (int i = 0; i < 80; ++i) {
        unsigned char x = static_cast<unsigned char>(input[i]);
        LogPrintf("%0x", x);
    }
    LogPrintf("\n");
    LogPrintf("y[0] = %s\n", y[0].ToString());

    // get hash_zero
    uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
    initial_hash(h0, &context_verify, instance.type);
    std::ostringstream ossx;
    ossx << "h0 = ";
    for (int xxx = 0; xxx < 72; ++xxx) {
        ossx << std::hex << std::setw(2) << std::setfill('0') << (int)h0[xxx];
    }
    LogPrintf("H0_Verify : %s\n", ossx.str());

    // step 8
    for (uint32_t j = 1; j <= L; ++j) {
        // compute ij
        std::string s = "0x" + y[j - 1].GetHex();
        boost::multiprecision::uint256_t t(s);
        uint32_t ij = numeric_cast<uint32_t>(t % M_COST);

        // retrieve x[ij-1] and x[phi(i)] from proof
        block prev_block, ref_block, t_prev_block, t_ref_block;
        std::memcpy(t_prev_block.v, block_mtp[(j * 2) - 2],
                sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        std::memcpy(t_ref_block.v, block_mtp[j*2 - 1],
                sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        copy_block(&prev_block , &t_prev_block);
        copy_block(&ref_block , &t_ref_block);
        clear_internal_memory(t_prev_block.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(t_ref_block.v, ARGON2_BLOCK_SIZE);

        //prev_index
        //compute
        uint32_t memory_blocks_2 = M_COST;
        if (memory_blocks_2 < (2 * ARGON2_SYNC_POINTS * LANES)) {
            memory_blocks_2 = 2 * ARGON2_SYNC_POINTS * LANES;
        }

        uint32_t segment_length_2 = memory_blocks_2 / (LANES * ARGON2_SYNC_POINTS);
        uint32_t lane_length = segment_length_2 * ARGON2_SYNC_POINTS;
        uint32_t ij_prev = 0;
        if ((ij % lane_length) == 0) {
            ij_prev = ij + lane_length - 1;
        } else {
            ij_prev = ij - 1;
        }
        if ((ij % lane_length) == 1) {
            ij_prev = ij - 1;
        }

        //hash[prev_index]
        uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
        compute_blake2b(prev_block, digest_prev);
        MerkleTree::Buffer hash_prev(digest_prev,
                digest_prev + sizeof(digest_prev));
        if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 2],
                    root, hash_prev, ij_prev + 1)) {
            LogPrintf("error : checkProofOrdered in x[ij_prev]\n");
            return false;
        }

        //compute ref_index
        uint64_t prev_block_opening = prev_block.v[0];
        uint32_t ref_lane = static_cast<uint32_t>((prev_block_opening >> 32) % LANES);
        uint32_t pseudo_rand = static_cast<uint32_t>(prev_block_opening & 0xFFFFFFFF);
        uint32_t lane = ij / lane_length;
        uint32_t slice = (ij - (lane * lane_length)) / segment_length_2;
        uint32_t pos_index = ij - (lane * lane_length)
            - (slice * segment_length_2);
        if (slice == 0) {
            ref_lane = lane;
        }

        argon2_instance_t instance;
        instance.segment_length = segment_length_2;
        instance.lane_length = lane_length;

        argon2_position_t position { 0, lane , (uint8_t)slice, pos_index };
        uint32_t ref_index = IndexBeta(&instance, &position, pseudo_rand,
                ref_lane == position.lane);

        uint32_t computed_ref_block = (lane_length * ref_lane) + ref_index;

        uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
        compute_blake2b(ref_block, digest_ref);
        MerkleTree::Buffer hash_ref(digest_ref, digest_ref + sizeof(digest_ref));
        if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 1],
                    root, hash_ref, computed_ref_block + 1)) {
            LogPrintf("error : checkProofOrdered in x[ij_ref]\n");
            return false;
        }

        // compute x[ij]
        block block_ij;
        fill_block_mtp(&blocks[(j * 2) - 2], &blocks[(j * 2) - 1],
                &block_ij, 0, computed_ref_block, h0);

        // verify opening
        // hash x[ij]
        uint8_t digest_ij[MERKLE_TREE_ELEMENT_SIZE_B];
        compute_blake2b(block_ij, digest_ij);
        MerkleTree::Buffer hash_ij(digest_ij, digest_ij + sizeof(digest_ij));

        std::ostringstream oss;
        oss << "hash_ij[" << ij << "] = 0x";
        for (MerkleTree::Buffer::const_iterator it = hash_ij.begin();
                it != hash_ij.end();
                ++it) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)*it;
        }

        if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 3], root,
                    hash_ij, ij + 1)) {
            LogPrintf("error : checkProofOrdered in x[ij]\n");
            return false;
        }

        // compute y(j)
        block blockhash;
        copy_block(&blockhash, &block_ij);
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
        StoreBlock(&blockhash_bytes, &blockhash);
        blake2b_state ctx_yj;
        blake2b_init(&ctx_yj, 32);
        blake2b_update(&ctx_yj, &y[j - 1], 32);
        blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
        blake2b_final(&ctx_yj, &y[j], 32);
        clear_internal_memory(block_ij.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
    }

    // step 9
    bool negative;
    bool overflow;
    arith_uint256 bn_target;
    bn_target.SetCompact(target, &negative, &overflow); // diff = 1

    for (int i = 0; i < (L * 2); ++i) {
        clear_internal_memory(blocks[i].v, ARGON2_BLOCK_SIZE);
    }

    if (negative || (bn_target == 0) || overflow
            || (bn_target > UintToArith256(pow_limit))
            || (UintToArith256(y[L]) > bn_target)) {
        return false;
    }
    LogPrintf("Verified :\n");
    LogPrintf("hashTarget = %s\n", ArithToUint256(bn_target).GetHex().c_str());
    LogPrintf("y[L] 	  = %s", y[L].GetHex().c_str());
    LogPrintf("nNonce 	  = %s\n", nonce);
    return true;
}

namespace {

bool mtp_hash1(const char* input, uint32_t target, uint8_t hash_root_mtp[16],
        unsigned int& nonce, uint64_t block_mtp[72*2][128],
        std::deque<std::vector<uint8_t>> proof_mtp[73*3], uint256 pow_limit,
        uint256& output)
{
    LogPrintf("START mtp_hash\n");

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0

    unsigned char out[TEST_OUTLEN];
    unsigned char pwd[TEST_PWDLEN];
    std::memcpy(pwd, input, TEST_PWDLEN);
    unsigned char salt[TEST_SALTLEN];
    std::memcpy(salt, input, TEST_SALTLEN);

    argon2_context context;
    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.version = ARGON2_VERSION_NUMBER;
    context.pwd = pwd;
    context.pwdlen = TEST_PWDLEN;
    context.salt = salt;
    context.saltlen = TEST_SALTLEN;
    context.secret = NULL;
    context.secretlen = TEST_SECRETLEN;
    context.ad = NULL;
    context.adlen = TEST_ADLEN;
    context.t_cost = T_COST;
    context.m_cost = M_COST;
    context.lanes = LANES;
    context.threads = LANES;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    uint32_t memory_blocks = context.m_cost;
    if (memory_blocks < (2 * ARGON2_SYNC_POINTS * context.lanes)) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context.lanes;
    }
    uint32_t segment_length = memory_blocks / (context.lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context.lanes * ARGON2_SYNC_POINTS);

    argon2_instance_t instance;
    instance.version = context.version;
    instance.memory = NULL;
    instance.passes = context.t_cost;
    instance.memory_blocks = context.m_cost;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context.lanes;
    instance.threads = context.threads;
    instance.type = Argon2_d;
    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    // step 1
    Argon2CtxMtp(&context, Argon2_d, &instance);

    // step 2
    MerkleTree::Elements elements;
    for (long int i = 0; i < instance.memory_blocks; ++i) {
        uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
        compute_blake2b(instance.memory[i], digest);
        elements.emplace_back(digest, digest + sizeof(digest));
    }

    MerkleTree ordered_tree(elements, true);
    MerkleTree::Buffer root = ordered_tree.getRoot();
    std::copy(root.begin(), root.end(), hash_root_mtp);

    // step 3
    unsigned int n_nonce_internal = 0;
    TargetHelper const bn_target(target);

    // step 4
    uint256 y[L + 1];
    block blocks[L * 2];
    MerkleTree::Elements proof_blocks[L * 3];
    while (true) {
        if (n_nonce_internal == UINT_MAX) {
            // go to create a new merkle tree
            return false;
        }

        std::memset(&y[0], 0, sizeof(y));
        std::memset(&blocks[0], 0, sizeof(sizeof(block) * L * 2));

        blake2b_state state;
        blake2b_init(&state, 32); // 256 bit
        blake2b_update(&state, input, 80);
        blake2b_update(&state, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
        blake2b_update(&state, &n_nonce_internal, sizeof(unsigned int));
        blake2b_final(&state, &y[0], sizeof(uint256));

        // step 5
        bool init_blocks = false;
        for (uint32_t j = 1; j <= L; ++j) {
            std::string s = "0x" + y[j - 1].GetHex();
            boost::multiprecision::uint256_t t(s);
            uint32_t ij = numeric_cast<uint32_t>(t % M_COST);
            uint32_t except_index = numeric_cast<uint32_t>(M_COST / LANES);
            if (((ij % except_index) == 0) || ((ij % except_index) == 1)) {
                init_blocks = true;
                break;
            }

            block blockhash;
            copy_block(&blockhash, &instance.memory[ij]);
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            StoreBlock(&blockhash_bytes, &blockhash);
            blake2b_state ctx_yj;
            blake2b_init(&ctx_yj, 32);
            blake2b_update(&ctx_yj, &y[j - 1], 32);
            blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
            blake2b_final(&ctx_yj, &y[j], 32);
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

            //storing blocks
            uint32_t prev_index;
            uint32_t ref_index;
            GetBlockIndex(ij, &instance, &prev_index, &ref_index);
            //previous block
            copy_block(&blocks[(j * 2) - 2], &instance.memory[prev_index]);
            //ref block
            copy_block(&blocks[(j * 2) - 1], &instance.memory[ref_index]);

            //storing proof
            //TODO : make it as function please
            //current proof
            uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(instance.memory[ij], digest_curr);
            MerkleTree::Buffer hash_curr(digest_curr,
                    digest_curr + sizeof(digest_curr));
            MerkleTree::Elements proof_curr = ordered_tree.getProofOrdered(
                    hash_curr, ij + 1);
            proof_blocks[(j * 3) - 3] = proof_curr;

            //prev proof
            uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(instance.memory[prev_index], digest_prev);
            MerkleTree::Buffer hash_prev(digest_prev,
                    digest_prev + sizeof(digest_prev));
            MerkleTree::Elements proof_prev = ordered_tree.getProofOrdered(
                    hash_prev, prev_index + 1);
            proof_blocks[(j * 3) - 2] = proof_prev;

            //ref proof
            uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(instance.memory[ref_index], digest_ref);
            MerkleTree::Buffer hash_ref(digest_ref,
                    digest_ref + sizeof(digest_ref));
            MerkleTree::Elements proof_ref = ordered_tree.getProofOrdered(
                    hash_ref, ref_index + 1);
            proof_blocks[(j * 3) - 1] = proof_ref;
        }

        if (init_blocks) {
            n_nonce_internal++;
            continue;
        }

        // step 6
        if (bn_target.m_negative || (bn_target.m_target == 0) || bn_target.m_overflow
                || (bn_target.m_target > UintToArith256(pow_limit))
                || (UintToArith256(y[L]) > bn_target.m_target)) {
            n_nonce_internal++;
            continue;
        }

        LogPrintf("Found a MTP solution :\n");
        LogPrintf("hashTarget = %s\n", ArithToUint256(bn_target.m_target).GetHex().c_str());
        LogPrintf("Y[L] 	  = %s", y[L].GetHex().c_str());
        LogPrintf("nNonce 	  = %s\n", n_nonce_internal);
        break;
    }

    // step 7
    LogPrintf("END mtp_hash\n");
    std::copy(root.begin(), root.end(), hash_root_mtp);

    nonce = n_nonce_internal;
    for (int i = 0; i < L * 2; ++i) {
        std::memcpy(block_mtp[i], &blocks[i],
                sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
    }
    for (int i = 0; i < L * 3; ++i) {
        proof_mtp[i] = proof_blocks[i];
    }
    std::memcpy(&output, &y[L], sizeof(uint256));

    LogPrintf("pblock->hashRootMTP:\n");
    for (int i = 0; i < 16; ++i) {
        LogPrintf("%0x", hash_root_mtp[i]);
    }
    LogPrintf("\n");
    LogPrintf("pblock->nNonce: %s\n", nonce);
    LogPrintf("pblock->nBlockMTP:\n");
    for (int i = 0; i < 1; ++i) {
        LogPrintf("%s = ", i);
        for (int j = 0; j < 10; j++) {
            LogPrintf("%0x", block_mtp[i][j]);
        }
        LogPrintf("\n");
    }
    LogPrintf("input = \n");
    for (int i = 0; i < 80; ++i) {
        unsigned char x;
        std::memcpy(&x, &input[i], sizeof(unsigned char));
        LogPrintf("%0x", x);
    }
    LogPrintf("\n");
    LogPrintf("Y[0] = %s\n", y[0].ToString());

    uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
    std::memcpy(h0, instance.hash_zero,
            sizeof(uint8_t) * ARGON2_PREHASH_SEED_LENGTH);

    std::ostringstream ossx;
    ossx << "h0 = ";
    for (int xxx = 0; xxx < 72; ++xxx) {
        ossx << std::hex << std::setw(2) << std::setfill('0')
            << (int)h0[xxx];
    }
    LogPrintf("H0_Proof : %s\n", ossx.str());

    // get hash_zero
    uint8_t h0_computed[ARGON2_PREHASH_SEED_LENGTH];
    initial_hash(h0_computed, &context, instance.type);
    std::ostringstream ossxxx;
    ossxxx << "h0 = ";
    for (int xxx = 0; xxx < 72; ++xxx) {
        ossxxx << std::hex << std::setw(2) << std::setfill('0')
            << (int)h0_computed[xxx];
    }

    LogPrintf("H0_Proof_Computed : %s\n", ossx.str());
    LogPrintf("RETURN mtp_hash\n");
    LogPrintf("FREE memory\n");
    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
    return true;
}

} // unnamed namespace

void mtp_hash(const char* input, uint32_t target, uint8_t hash_root_mtp[16],
        unsigned int& nonce, uint64_t block_mtp[72*2][128],
        std::deque<std::vector<uint8_t>> proof_mtp[73*3], uint256 pow_limit,
        uint256& output)
{
    bool done = false;
    while (!done) {
        done = mtp_hash1(input, target, hash_root_mtp, nonce, block_mtp,
                proof_mtp, pow_limit, output);
    }
}

}

namespace 
{
void serializeMtpHeader(CDataStream & stream, CBlockHeader const & header)
{
    static_assert(
                80 == sizeof(header.nVersion) + sizeof(header.hashPrevBlock)+ sizeof(header.hashMerkleRoot) 
                    + sizeof(header.nTime) + sizeof(header.nBits) + sizeof(header.mtpHashData->nVersionMTP)
                , "The header data size for MTP hashing should be 80 bytes long."
            );

    stream << header.nVersion;
    stream << header.hashPrevBlock;
    stream << header.hashMerkleRoot;
    stream << header.nTime;
    stream << header.nBits;
    stream << header.mtpHashData->nVersionMTP;
}
}

uint256 hash(CBlockHeader & blockHeader, uint256 const & powLimit)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    serializeMtpHeader(ss, blockHeader);
    
    blockHeader.mtpHashData = std::make_shared<CMTPHashData>();
    
    uint256 result;
    impl::mtp_hash(reinterpret_cast<char*>(&ss[0]), blockHeader.nBits, blockHeader.mtpHashData->hashRootMTP
            , blockHeader.nNonce, blockHeader.mtpHashData->nBlockMTP, blockHeader.mtpHashData->nProofMTP, powLimit, result);
    
    return result;
}


bool verify(uint32_t nonce, CBlockHeader const & blockHeader, uint256 const & powLimit)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    serializeMtpHeader(ss, blockHeader);

    return impl::mtp_verify(reinterpret_cast<char*>(&ss[0]), blockHeader.nBits, blockHeader.mtpHashData->hashRootMTP
            , nonce, blockHeader.mtpHashData->nBlockMTP, blockHeader.mtpHashData->nProofMTP, powLimit);
}

}