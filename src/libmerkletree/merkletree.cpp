#include "merkletree.hpp"

// buff 

char* serializeMTP(vector<ProofNode>& proof) // Writes the given OBJECT data to the given file name.
{
	char* result = (char*)malloc(proof.size() * SHA256_LENGTH * 3 + 1);
	result[proof.size() * SHA256_LENGTH * 3 + 1] = 0;
	for (int i = 0; i < proof.size(); i++) {
		memcpy(result + SHA256_LENGTH*(3 * i), proof.at(i).left.GetHex().c_str(), SHA256_LENGTH);
		memcpy(result + SHA256_LENGTH*(3 * i + 1), proof.at(i).right.GetHex().c_str(), SHA256_LENGTH);
		memcpy(result + SHA256_LENGTH*(3 * i + 2), proof.at(i).parent.GetHex().c_str(), SHA256_LENGTH);
	}
	return result;
};

vector<ProofNode> deserializeMTP(const char* strdata) // Reads the given file and assigns the data to the given OBJECT.
{
	size_t datalen = strlen(strdata);
	vector<ProofNode> proof(datalen / 3 / SHA256_LENGTH);

	for (int i = 0; i<proof.size(); i++) {
		char *left = new char[SHA256_LENGTH + 1],
			*right = new char[SHA256_LENGTH + 1],
			*parent = new char[SHA256_LENGTH + 1];
		left[SHA256_LENGTH] = 0;
		right[SHA256_LENGTH] = 0;
		parent[SHA256_LENGTH] = 0;
		memcpy(left, strdata + SHA256_LENGTH*(3 * i), SHA256_LENGTH);
		memcpy(right, strdata + SHA256_LENGTH*(3 * i + 1), SHA256_LENGTH);
		memcpy(parent, strdata + SHA256_LENGTH*(3 * i + 2), SHA256_LENGTH);
		uint256 v_left(left);
		uint256 v_right(right);
		uint256 v_parent(parent);
		proof[i] = ProofNode(v_left, v_right, v_parent);
	}

	return proof;
};



// combin and hash by sha256

uint256 combine(uint256 leftData, uint256 rightData) {
	uint256 hash1;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &leftData, sizeof(uint256));
	SHA256_Update(&sha256, &rightData, sizeof(uint256));
	SHA256_Final((unsigned char*)&hash1, &sha256);

	uint256 hash2;
	SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
//	printf("hash = %s\n", hash2.GetHex().c_str());
	return hash2;
}


bool verifyProof(uint256 leaf, uint256 expectedMerkleRoot, vector<ProofNode> proofArr) {
	if (proofArr.size() == 0) {
		if (leaf != expectedMerkleRoot)
			return true;
		return false;
	}

	// the merkle root should be the parent of the last part
	uint256 actualMekleRoot = proofArr[proofArr.size() - 1].parent;

	if (actualMekleRoot != expectedMerkleRoot)
		return false;

	uint256 prevParent = leaf;
	for (int pIdx = 0; pIdx < proofArr.size(); pIdx++) {
		ProofNode part = proofArr[pIdx];

		if ((part.left != prevParent) && (part.right != prevParent))
			return false;
		uint256 parentData;
		parentData = combine(part.left, part.right);


		// Parent in proof is incorrect
		if (parentData != part.parent)
			return false;

		prevParent = parentData;
	}
/*
	printf("prevParent = %s\n", prevParent.GetHex().c_str());
	printf("expectedMerkleRoot = %s\n", expectedMerkleRoot.GetHex().c_str());
*/
	if (prevParent == expectedMerkleRoot) {
		return true;
	}
	else {
		return false;
	}

}

