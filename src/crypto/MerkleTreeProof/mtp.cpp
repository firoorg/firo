#include "mtp.h"

using namespace std;
using namespace boost::multiprecision;
using boost::numeric_cast;
using boost::numeric::bad_numeric_cast;
using boost::numeric::positive_overflow;
using boost::numeric::negative_overflow;

extern int validate_inputs(const argon2_context *context);
extern void clear_internal_memory(void *v, size_t n);


const int8_t L = 72;
const unsigned t_cost = 1;
const unsigned m_cost = 1024 * 2;
const unsigned lanes = 4;


static void store_block(void *output, const block *src) {
	unsigned i;
	for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
		store64((uint8_t *) output + i * sizeof(src->v[i]), src->v[i]);
	}
}

int argon2_ctx_mtp(argon2_context *context, argon2_type type,
		argon2_instance_t *instance) {
	int result = validate_inputs(context);

	if (ARGON2_OK != result) {
		return result;
	}
	if (Argon2_d != type && Argon2_i != type && Argon2_id != type) {
		return ARGON2_INCORRECT_TYPE;
	}
	result = initialize(instance, context);
	if (ARGON2_OK != result) {
		return result;
	}

	result = fill_memory_blocks_mtp(instance, context);
	if (ARGON2_OK != result) {
		return result;
	}
	return ARGON2_OK;
}

uint32_t index_beta(const argon2_instance_t *instance,
	const argon2_position_t *position, uint32_t pseudo_rand,
	int same_lane) {
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
	uint64_t relative_position;
	uint32_t start_position, absolute_position;

	if (0 == position->pass) {
		/* First pass */
		if (0 == position->slice) {
			/* First slice */
			reference_area_size =
				position->index - 1; /* all but the previous */
		}
		else {
			if (same_lane) {
				/* The same lane => add current segment */
				reference_area_size =
					position->slice * instance->segment_length +
					position->index - 1;
			}
			else {
				reference_area_size =
					position->slice * instance->segment_length +
					((position->index == 0) ? (-1) : 0);
			}
		}
	}
	else {
		/* Second pass */
		if (same_lane) {
			reference_area_size = instance->lane_length -
				instance->segment_length + position->index -
				1;
		}
		else {
			reference_area_size = instance->lane_length -
				instance->segment_length +
				((position->index == 0) ? (-1) : 0);
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	* relative position */
	relative_position = pseudo_rand;
	relative_position = relative_position * relative_position >> 32;
	relative_position = reference_area_size - 1 -
		(reference_area_size * relative_position >> 32);

	/* 1.2.5 Computing starting position */
	start_position = 0;

	if (0 != position->pass) {
		start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (position->slice + 1) * instance->segment_length;
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + relative_position) %
		instance->lane_length; /* absolute position */
	return absolute_position;
}

void getblockindex(uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_block)
{
	uint32_t ij_prev = 0;
	if (ij%instance->lane_length == 0)
		ij_prev = ij + instance->lane_length - 1;
	else
		ij_prev = ij - 1;

	if (ij % instance->lane_length == 1)
		ij_prev = ij - 1;

	uint64_t prev_block_opening = instance->memory[ij_prev].v[0];
	uint32_t ref_lane = (uint32_t)((prev_block_opening >> 32) % instance->lanes);

	uint32_t pseudo_rand = (uint32_t)(prev_block_opening & 0xFFFFFFFF);

	uint32_t Lane = ((ij) / instance->lane_length);
	uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
	uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


	uint32_t rec_ij = Slice*instance->segment_length + Lane *instance->lane_length + (ij % instance->segment_length);

	if (Slice == 0)
		ref_lane = Lane;


	argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };

	uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

	uint32_t computed_ref_block = instance->lane_length * ref_lane + ref_index;

	*out_ij_prev = ij_prev;
	*out_computed_ref_block = computed_ref_block;
}




bool mtp_verify(const char* input, const uint32_t target,
		const uint256 * hashRootMTP, const unsigned int * nNonce,
		const uint64_t nBlockMTP[72*2][128], const std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output){


	MerkleTree::Elements proof_blocks[L*3];
	MerkleTree::Buffer root;
	block blocks[L*2];
	for(int i = 0; i < L*3; i++){
		proof_blocks[i] = nProofMTP[i];
	}
	memcpy(&root, hashRootMTP, sizeof(uint256));
	for(int i = 0; i < L*2; i++){
		memcpy(blocks[i].v, nBlockMTP[i], sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
	}


#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0

	argon2_context context;
	argon2_instance_t instance;
	uint32_t memory_blocks, segment_length;

	unsigned char out[TEST_OUTLEN];
	unsigned char pwd[TEST_PWDLEN];
	unsigned char salt[TEST_SALTLEN];
	unsigned char secret[TEST_SECRETLEN];
	unsigned char ad[TEST_ADLEN];
	const allocate_fptr myown_allocator = NULL;
	const deallocate_fptr myown_deallocator = NULL;

	memset(pwd, 0, TEST_OUTLEN);
	memset(salt, 0, TEST_SALTLEN);
	//memset(secret, 3, TEST_SECRETLEN);
	//memset(ad, 4, TEST_ADLEN);

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

	cout << "verifying ..." << endl;
	// step 7
	uint256 Y[L + 1];

	memset(&Y[0], 0, sizeof(Y));

	blake2b_state state_y0;
	blake2b_init(&state_y0, 32); // 256 bit
	blake2b_update(&state_y0, input, 80);
	blake2b_update(&state_y0, hashRootMTP, MERKLE_TREE_ELEMENT_SIZE_B);
	blake2b_update(&state_y0, nNonce, sizeof(unsigned int));
	blake2b_final(&state_y0, &Y[0], sizeof(uint256));


	// step 8
	for (uint32_t j = 1; j <= L; j++) {
		// compute ij
		string s = "0x" + Y[j - 1].GetHex();
		uint256_t t(s);
		uint32_t ij = numeric_cast<uint32_t>(t % m_cost);

		// retrieve x[ij-1] and x[phi(i)) from proof
		block prev_block, ref_block, t_prev_block, t_ref_block;
		memcpy(t_prev_block.v, nBlockMTP[j*2 - 2], sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
		memcpy(t_ref_block.v, nBlockMTP[j*2 - 1], sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
		copy_block(&prev_block , &t_prev_block);
		copy_block(&ref_block , &t_ref_block);

		//prev_index
		//compute
		uint32_t memory_blocks, segment_length;
		memory_blocks = m_cost;

		if (memory_blocks < 2 * ARGON2_SYNC_POINTS * lanes) {
			memory_blocks = 2 * ARGON2_SYNC_POINTS * lanes;
		}

		segment_length = memory_blocks / (lanes * ARGON2_SYNC_POINTS);
		uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
		uint32_t ij_prev = 0;
		if (ij%lane_length == 0)
			ij_prev = ij + lane_length - 1;
		else
			ij_prev = ij - 1;

		if (ij % lane_length == 1)
			ij_prev = ij - 1;

		//hash[prev_index]
		block blockhash_prev;
		uint8_t blockhash_prev_bytes[ARGON2_BLOCK_SIZE];
		copy_block(&blockhash_prev, &prev_block);
		store_block(&blockhash_prev_bytes, &blockhash_prev);
		blake2b_state state_prev;
		blake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
		blake2b_update(&state_prev, blockhash_prev_bytes,
				ARGON2_BLOCK_SIZE);
		uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
		blake2b_final(&state_prev, digest_prev, sizeof(digest_prev));
		MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev,
				digest_prev + sizeof(digest_prev));
		clear_internal_memory(blockhash_prev.v, ARGON2_BLOCK_SIZE);
		clear_internal_memory(blockhash_prev_bytes, ARGON2_BLOCK_SIZE);
		if(!MerkleTree::checkProofOrdered(proof_blocks[j*3 - 2], root, hash_prev, ij_prev + 1)){
			cout << "error : checkProofOrdered in x[ij_prev]" << endl;
			return false;
		}else{
			cout << "success : checkProofOrdered in x[ij_prev]" << endl;
		}

		//hash[ref_index]
		//compute ref_index
		uint64_t prev_block_opening = prev_block.v[0];
		uint32_t ref_lane = (uint32_t)((prev_block_opening >> 32) % lanes);

		uint32_t pseudo_rand = (uint32_t)(prev_block_opening & 0xFFFFFFFF);

		uint32_t Lane = ((ij) / lane_length);
		uint32_t Slice = (ij - (Lane * lane_length)) / segment_length;
		uint32_t posIndex = ij - Lane * lane_length - Slice * segment_length;


		uint32_t rec_ij = Slice*segment_length + Lane *lane_length + (ij % segment_length);

		if (Slice == 0)
			ref_lane = Lane;


		argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };
		argon2_instance_t instance;
		instance.segment_length = segment_length;
		instance.lane_length = lane_length;

		uint32_t ref_index = index_beta(&instance, &position, pseudo_rand, ref_lane == position.lane);

		uint32_t computed_ref_block = lane_length * ref_lane + ref_index;

		block blockhash_ref;
		uint8_t blockhash_ref_bytes[ARGON2_BLOCK_SIZE];
		copy_block(&blockhash_ref, &ref_block);
		store_block(&blockhash_ref_bytes, &blockhash_ref);
		blake2b_state state_ref;
		blake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
		blake2b_update(&state_ref, blockhash_ref_bytes,
				ARGON2_BLOCK_SIZE);
		uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
		blake2b_final(&state_ref, digest_ref, sizeof(digest_ref));
		MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref,
				digest_ref + sizeof(digest_ref));
		clear_internal_memory(blockhash_ref.v, ARGON2_BLOCK_SIZE);
		clear_internal_memory(blockhash_ref_bytes, ARGON2_BLOCK_SIZE);
		if(!MerkleTree::checkProofOrdered(proof_blocks[j*3 - 1], root, hash_ref, computed_ref_block + 1)){
			cout << "error : checkProofOrdered in x[ij_ref]" << endl;
			return false;
		}else{
			cout << "success : checkProofOrdered in x[ij_ref]" << endl;
		}

		// compute x[ij]
		block block_ij;
		// get hash_zero
		uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
		initial_hash(h0, &context,  instance.type);
		std::ostringstream ossx;
		ossx << "h0 = ";
		for (int xxx = 0; xxx < 80; xxx++) {
			ossx << std::hex << std::setw(2) << std::setfill('0')
					<< (int) h0[xxx];
		}
		cout << ossx.str() << endl;

		fill_block_mtp(&blocks[j*2 - 2], &blocks[j*2 - 1], &block_ij, 0, computed_ref_block, h0);

		printf("\ncurr_block_verify = ");
		int index = 0;
		for (index = 0; index < 10; index++) {
			printf("%016llx",
					(unsigned long long) block_ij.v[index]);
		}

		printf("\nprev_block_verify = ");
		index = 0;
		for (index = 0; index < 10; index++) {
			printf("%016llx",
					(unsigned long long) blocks[j*2 - 2].v[index]);
		}

		printf("\nref_block_verify = ");
		index = 0;
		for (index = 0; index < 10; index++) {
			printf("%016llx",
					(unsigned long long) blocks[j*2 - 1].v[index]);
		}

		// verify opening
		// hash x[ij]
		block blockhash_ij;
		uint8_t blockhash_ij_bytes[ARGON2_BLOCK_SIZE];
		copy_block(&blockhash_ij, &block_ij);
		store_block(&blockhash_ij_bytes, &blockhash_ij);
		blake2b_state state_ij;
		blake2b_init(&state_ij, MERKLE_TREE_ELEMENT_SIZE_B);
		blake2b_update(&state_ij, blockhash_ij_bytes, ARGON2_BLOCK_SIZE);
		uint8_t digest_ij[MERKLE_TREE_ELEMENT_SIZE_B];
		blake2b_final(&state_ij, digest_ij, sizeof(digest_ij));
		MerkleTree::Buffer hash_ij = MerkleTree::Buffer(digest_ij,
				digest_ij + sizeof(digest_ij));
		clear_internal_memory(blockhash_ij.v, ARGON2_BLOCK_SIZE);
		clear_internal_memory(blockhash_ij_bytes, ARGON2_BLOCK_SIZE);
		cout <<endl << "curr_offset = " << ij << " prev_offset = " << ij_prev << " ref_block = " << computed_ref_block << endl;
		std::ostringstream oss;
		oss << "hash_ij[" << ij << "] = 0x";
		for (MerkleTree::Buffer::const_iterator it = hash_ij.begin();
				it != hash_ij.end(); ++it) {
			oss << std::hex << std::setw(2) << std::setfill('0') << (int) *it;
		}
		cout << oss.str() << endl;

		if (!MerkleTree::checkProofOrdered(proof_blocks[j * 3 - 3], root,
				hash_ij, ij + 1)) {
			cout << "error : checkProofOrdered in x[ij]" << endl;
			return false;
		}else{
			cout << "success : checkProofOrdered in x[ij]" << endl;
		}

		// compute Y(j)
		block blockhash;
		uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
		copy_block(&blockhash, &block_ij);
		store_block(&blockhash_bytes, &blockhash);
		blake2b_state ctx_yj;
		blake2b_init(&ctx_yj, 32);
		blake2b_update(&ctx_yj, &Y[j - 1], 32);
		blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
		blake2b_final(&ctx_yj, &Y[j], 32);
		clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
		clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

	}

	// step 9
	bool fNegative;
	bool fOverflow;
	arith_uint256 bnTarget;
	bnTarget.SetCompact(target, &fNegative, &fOverflow); // diff = 1
	//uint256 powLimit = uint256S(
	//		"00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	if (fNegative || bnTarget == 0 || fOverflow
			|| bnTarget > UintToArith256(powLimit)
			|| UintToArith256(Y[L]) > bnTarget) {
		cout << "hashTarget = " << ArithToUint256(bnTarget).GetHex().c_str()
				<< endl;
		cout << "Y[L] 		= " << Y[L].GetHex().c_str() << " nNonce = " << *nNonce
				<< endl;
		return false;
	} else {
		cout << "Verified :" << endl;
		cout << "hashTarget = " << ArithToUint256(bnTarget).GetHex().c_str()
				<< endl;
		cout << "Y[L]       = " << Y[L].GetHex().c_str() << endl;
		cout << "nNonce     = " << *nNonce << endl;
		return true;
	}

	return false;
}


void mtp_hash(const char* input, uint32_t target,
		uint256 * hashRootMTP, unsigned int * nNonce,
		uint64_t nBlockMTP[72*2][128], std::deque<std::vector<uint8_t>> * nProofMTP, uint256 powLimit,
		uint256 * output) {

BEGIN:




#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0

	argon2_context context;
	argon2_instance_t instance;
	uint32_t memory_blocks, segment_length;

	unsigned char out[TEST_OUTLEN];
	unsigned char pwd[TEST_PWDLEN];
	unsigned char salt[TEST_SALTLEN];
	unsigned char secret[TEST_SECRETLEN];
	unsigned char ad[TEST_ADLEN];
	const allocate_fptr myown_allocator = NULL;
	const deallocate_fptr myown_deallocator = NULL;

	memset(pwd, 0, TEST_OUTLEN);
	memset(salt, 0, TEST_SALTLEN);
	//memset(secret, 3, TEST_SECRETLEN);
	//memset(ad, 4, TEST_ADLEN);

	context.out = out;
	context.outlen = TEST_OUTLEN;
	context.version = ARGON2_VERSION_NUMBER;
	//context.pwd = &input;
	memcpy(context.pwd, input, TEST_PWDLEN);
	context.pwdlen = TEST_PWDLEN;
	//context.salt = &input;
	memcpy(context.salt, input, TEST_SALTLEN);
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


	memory_blocks = context.m_cost;

	if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context.lanes) {
		memory_blocks = 2 * ARGON2_SYNC_POINTS * context.lanes;
	}

	segment_length = memory_blocks / (context.lanes * ARGON2_SYNC_POINTS);
	memory_blocks = segment_length * (context.lanes * ARGON2_SYNC_POINTS);

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
	argon2_ctx_mtp(&context, Argon2_d, &instance);

	// step 2
	MerkleTree::Elements elements;
	if (&instance != NULL) {

		for (long int i = 0; i < instance.memory_blocks; ++i) {
			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance.memory[i]);
			store_block(&blockhash_bytes, &blockhash);
			blake2b_state state;
			blake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
			blake2b_update(&state, blockhash_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
			blake2b_final(&state, digest, sizeof(digest));
			MerkleTree::Buffer hash_digest = MerkleTree::Buffer(digest, digest + sizeof(digest));
			elements.push_back(hash_digest);
			clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
		}
	}

	MerkleTree ordered_tree(elements, true);
	MerkleTree::Buffer root = ordered_tree.getRoot();
	/*std::ostringstream oss;
	oss << "0x";
	for (MerkleTree::Buffer::const_iterator it = root.begin(); it != root.end();
			++it) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int) *it;
	}
	cout << oss.str() << endl;*/

	// step 3
	unsigned int nNonceInternal = 0;

	// step 4
	uint256 Y[L + 1];
	uint8_t input[80] = { 1 };
	block blocks[L*2];
	MerkleTree::Elements proof_blocks[L*3];
	while (true) {

		if(nNonceInternal == UINT_MAX){
			// go to create a new merkle tree
			goto BEGIN;
		}

		memset(&Y[0], 0, sizeof(Y));
		memset(&blocks[0], 0, sizeof(sizeof(block) * L * 2));

		blake2b_state state;
		blake2b_init(&state, 32); // 256 bit
		blake2b_update(&state, &input, 80);
		blake2b_update(&state, &root, MERKLE_TREE_ELEMENT_SIZE_B);
		blake2b_update(&state, &nNonceInternal, sizeof(unsigned int));
		blake2b_final(&state, &Y[0], sizeof(uint256));


		// step 5
		bool init_blocks = false;
		bool unmatch_block = false;
		for (uint32_t j = 1; j <= L; j++) {
			string s = "0x" + Y[j - 1].GetHex();
			uint256_t t(s);
			uint32_t ij = numeric_cast<uint32_t>(t % m_cost);
			uint32_t except_index = numeric_cast<uint32_t>(m_cost / lanes);
			if (ij % except_index == 0 || ij % except_index == 1) {
				init_blocks = true;
				break;
			}

			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance.memory[ij]);
			store_block(&blockhash_bytes, &blockhash);
			blake2b_state ctx_yj;
			blake2b_init(&ctx_yj, 32);
			blake2b_update(&ctx_yj, &Y[j - 1], 32);
			blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
			blake2b_final(&ctx_yj, &Y[j], 32);
			clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

			//storing blocks
			uint32_t prev_index;
			uint32_t ref_index;
			getblockindex(ij, &instance, &prev_index, &ref_index);
			//cout << endl << "++++" << endl << "curr_index = " << ij << " prev_index = " << prev_index << " ref_index = " << ref_index << endl;
			//previous block
			copy_block(&blocks[j*2 - 2], &instance.memory[prev_index]);
			//ref block
			copy_block(&blocks[j*2 - 1], &instance.memory[ref_index]);

			//storing proof
			//TODO : make it as function please
			//current proof
			block blockhash_curr;
			uint8_t blockhash_curr_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_curr, &instance.memory[ij]);
			store_block(&blockhash_curr_bytes, &blockhash_curr);
			blake2b_state state_curr;
			blake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
			blake2b_update(&state_curr, blockhash_curr_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
			blake2b_final(&state_curr, digest_curr, sizeof(digest_curr));
			MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
			clear_internal_memory(blockhash_curr.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_curr_bytes, ARGON2_BLOCK_SIZE);
			MerkleTree::Elements proof_curr = ordered_tree.getProofOrdered(hash_curr, ij + 1);
			proof_blocks[j*3 - 3] = proof_curr;
			/*std::ostringstream oss;
			oss << "hash_curr[" << ij << "] = 0x";
			for (MerkleTree::Buffer::const_iterator it = hash_curr.begin();
					it != hash_curr.end(); ++it) {
				oss << std::hex << std::setw(2) << std::setfill('0')
						<< (int) *it;
			}
			cout << oss.str() << endl;*/

			/*
			printf("\ncurr_block_ij = ");
			int index = 0;
			for (index = 0; index < 10; index++) {
				printf("%016llx", (unsigned long long)instance.memory[ij].v[index]);
			}

			printf("\nprev_block_ij = ");
			index = 0;
			for (index = 0; index < 10; index++) {
				printf("%016llx",
						(unsigned long long) instance.memory[prev_index].v[index]);
			}

			printf("\nref_block_ij = ");
			index = 0;
			for (index = 0; index < 10; index++) {
				printf("%016llx",
						(unsigned long long) instance.memory[ref_index].v[index]);
			}

			cout << endl << "----" << endl;
			*/

			//prev proof
			block blockhash_prev;
			uint8_t blockhash_prev_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_prev, &instance.memory[prev_index]);
			store_block(&blockhash_prev_bytes, &blockhash_prev);
			blake2b_state state_prev;
			blake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
			blake2b_update(&state_prev, blockhash_prev_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
			blake2b_final(&state_prev, digest_prev, sizeof(digest_prev));
			MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
			clear_internal_memory(blockhash_prev.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_prev_bytes, ARGON2_BLOCK_SIZE);
			MerkleTree::Elements proof_prev = ordered_tree.getProofOrdered(hash_prev, prev_index + 1);
			proof_blocks[j*3 - 2] = proof_prev;



			//ref proof
			block blockhash_ref;
			uint8_t blockhash_ref_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_ref, &instance.memory[ref_index]);
			store_block(&blockhash_ref_bytes, &blockhash_ref);
			blake2b_state state_ref;
			blake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
			blake2b_update(&state_ref, blockhash_ref_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
			blake2b_final(&state_ref, digest_ref, sizeof(digest_ref));
			MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
			clear_internal_memory(blockhash_ref.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_ref_bytes, ARGON2_BLOCK_SIZE);
			MerkleTree::Elements proof_ref = ordered_tree.getProofOrdered(hash_ref, ref_index + 1);
			proof_blocks[j*3 - 1] = proof_ref;

			//cout << "Y[" << dec << j << "] = " << Y[j].GetHex().c_str() << endl;

		}

		if (init_blocks) {
			nNonceInternal++;
		    continue;
		}


		// step 6
	    bool fNegative;
	    bool fOverflow;
		arith_uint256 bnTarget;
		bnTarget.SetCompact(target, &fNegative, &fOverflow); // diff = 1
		//uint256 powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(powLimit) || UintToArith256(Y[L]) > bnTarget) {
			/*cout << "hashTarget = " << ArithToUint256(bnTarget).GetHex().c_str() << endl;
			cout << "Y[L] = " << Y[L].GetHex().c_str() << " nNonce = " << nNonce << endl;*/
			nNonceInternal++;
			continue;
		} else {
			/*cout << endl << "Found a solution :" << endl;
			cout << "hashTarget = " << ArithToUint256(bnTarget).GetHex().c_str() << endl;
			cout << "Y[L]       = " << Y[L].GetHex().c_str() << endl;
			cout << "nNonce     = " << nNonce << endl;*/

			/*std::ostringstream ossx;
					ossx << "input = ";
					for (int xxx = 0; xxx < 80; xxx++) {
						ossx << std::hex << std::setw(2) << std::setfill('0') << (int) input[xxx];
					}
					cout << ossx.str() << endl;
			std::ostringstream oss;
				oss << "root = 0x";
				for (MerkleTree::Buffer::const_iterator it = root.begin(); it != root.end();
						++it) {
					oss << std::hex << std::setw(2) << std::setfill('0') << (int) *it;
				}
				cout << oss.str() << endl;
			*/
			// step 7
			//return mtp_verify(input, &root, &nNonce, blocks, proof_blocks);

			/*MerkleTree::Elements proof_blocks[L*3];
				//MerkleTree::Buffer root;
				block blocks[L*2];
				for(int i = 0; i < L*3; i++){
					proof_blocks[i] = nProofMTP[i];
				}
				//memcpy(&root, hashRootMTP, sizeof(uint256));
				for(int i = 0; i < L*2; i++){
					memcpy(blocks[i].v, nBlockMTP[i], sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
				}
			*/
			memcpy(hashRootMTP, &root, sizeof(uint256));

			*nNonce = nNonceInternal;
			for (int i = 0; i < L * 2; i++) {
				memcpy(nBlockMTP[i], &blocks[i],
						sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
			}
			for (int i = 0; i < L * 3; i++) {
				nProofMTP[i] = proof_blocks[i];
			}
			memcpy(output, &Y[L], sizeof(uint256));
			return ;

		}

	}

	return ;
}
