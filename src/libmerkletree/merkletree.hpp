#include "binarytree.hpp"
#include "../uint256.h"
//#include "../script.h"
#include <string.h>
#include <iostream>
#include <openssl/sha.h>

#define SHA256_LENGTH 64
using namespace std;


struct ProofNode{
  uint256 left, right, parent;
  ProofNode():left(""),right(""),parent(""){}
  ProofNode(uint256 _left,uint256 _right,uint256 _parent):left(_left),right(_right),parent(_parent){}
};

// buff 
char* serializeMTP(vector<ProofNode>& proof); // Writes the given OBJECT data to the given file name.

vector<ProofNode> deserializeMTP(char* strdata); // Reads the given file and assigns the data to the given OBJECT.

// combin and hash by sha256
uint256 combine(uint256 leftData,uint256 rightData); 

bool verifyProof(uint256 leaf,uint256 expectedMerkleRoot,vector<ProofNode> proofArr);



class merkletree{
public:
  vector<uint256> tree;

  // declare function
  //vector<char*> computeTree(void (*combineFn)(char*,char*,char*),vector<char*> leaves);

  merkletree(){}

  merkletree(vector<uint256> leaves){
    tree = computeTree(combine,leaves);
  }

  size_t size(){return tree.size();}
  uint256 root(){return tree[0];} 

  void calSHA256(char* inp,char out_buff[65]){
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inp, strlen(inp));
    SHA256_Final(hash, &sha256);

    //char buffx[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(&out_buff[i * 2], "%02x", hash[i]);
    }
    out_buff[64] = 0;
    //memcpy(out_buff,buffx,65);
  }

  vector<uint256> computeTree(uint256 (*combineFn)(uint256, uint256),vector<uint256> leaves){
    // compute nodeCount and create vector<T> tree
    int nodeCount = leafCountToNodeCount(leaves.size());
    int delta = nodeCount - leaves.size();
    vector<uint256> tree(nodeCount);


    for(int i = 0 ;i < leaves.size();i++){
        tree[delta + i] = leaves[i];
//        printf("tree[%d + %d] = %s\n", delta , i, leaves.at(i).GetHex().c_str());
    }


    int idx = nodeCount-1;
    while(idx > 0){
      int parent = (idx -1)/2;
//      printf("parent = %d\n", parent);
      uint256 hash1;
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256,&tree[idx-1], sizeof(uint256));
      SHA256_Update(&sha256,&tree[idx],sizeof(uint256));
      SHA256_Final((unsigned char*)&hash1, &sha256);
      SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&tree[parent]);
//      printf("hash return : %s\n", tree[parent].GetHex().c_str());
      idx-=2;
//      printf("idx = %d\n", idx);
    }

    return tree;
  }




  vector<ProofNode> proof(uint256 leafData){
    int idx = findLeaf(tree, leafData);
    //printf("idx %d\n",idx);
    if(idx == -1)
      return vector<ProofNode>();
    int proofArrSize = floor( log(tree.size())/ log(2) );

//    printf("proofArrSize : %d\n",proofArrSize);
    vector<ProofNode> proof(proofArrSize);
    int proofIdx = 0;
    while(idx > 0 ){
      idx = getParent(tree,idx);
      int left = getLeft(tree,idx);
      int right = getRight(tree,idx);

      proof[proofIdx++] = ProofNode(tree[left],tree[right],tree[idx]);
    }

//	printf("prooffIdx :%d \n",proofIdx);

	proof.resize(proofIdx);

//	vector<ProofNode> proof;
    return proof;
  }
    void pushleaf(uint256 leaf){
        pushleafworker(combine,leaf);
	}


    void pushleafworker(uint256 (*combineFn)(uint256,uint256),uint256 leaf){

		// push two
        tree.push_back(uint256());
        tree.push_back(uint256());

		int pidx = getParent(tree,tree.size()-1);

		// push parent and newleaf
        tree[tree.size()-2] = tree[pidx];
        tree[tree.size()-1] = leaf;

		// climb up and compute
		int idx = tree.size()-1;
		while(idx > 0){
			idx = getParent(tree,idx);
			//cout<<&combineFn<<'\n';
            uint256 buff = combineFn(tree[getLeft(tree,idx)],tree[getRight(tree,idx)]);
            tree[idx] = buff;
		}

		// done!
	}


};
