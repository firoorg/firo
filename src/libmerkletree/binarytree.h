#include <cstdio>
#include <math.h>
#include <stdexcept>
#include <string.h>
#include <vector>

using namespace std;

void printVect(vector<int> v){
  for(int i =0;i<v.size();i++)
    printf("%d " ,v[i]);
  printf("\n");
}

// leafCount => nodeCount
int leafCountToNodeCount(const int leftCount){
  return leftCount*2 -1;
}

// nodeCount => leafCount
int nodeCountToLeafCount(const int nodeCount){
  return (nodeCount +1 )/2;
}

// isn't leaf
bool isInteriorNode(int idx,int nodeCount){
  int leftCount = nodeCountToLeafCount(nodeCount);
  return idx>=0 && idx< (nodeCount - leftCount);
}

// leaves => tree
template <typename T>
vector<T> buildFromLeaves(const vector<T>& leaves){
  int leafCount = leaves.size();
  int nodeCount = leafCountToNodeCount(leafCount);
  int delta = nodeCount - leafCount;
  vector<T> tree(nodeCount);
  //tree.assign();
  //memcpy(tree,leaves,delta);
  copy(leaves.begin(),leaves.end(),tree.begin()+delta);
  return tree;
}

// tree => leaves
template <typename T>
vector<T> leaves(const vector<T>& tree){
  int leafCount = nodeCountToLeafCount(tree.size());
  vector<T> leaves(tree.end()-leafCount,tree.end());
  //memcpy(leaves,tree + sizeof(tree)-leafCount,leafCount);
  return leaves;
}

// get root
template <typename T>
T root(vector<T> tree){
  return tree[0];
}

template <typename T>
vector<int> levelOrder(const vector<T>& tree){
  vector<int> order(tree.size());
  for(int i =tree.size() ;i--;)
    order[i] = i;
  return order;
}

// throw if it's out of length
// get tree,idx,cal_idx and return cal_idx or throw error
template <typename T>
int guardRange(const vector<T>& tree,int idx,int cal_idx){
  if( !( idx>=0 && idx < tree.size()  && cal_idx >= 0 && cal_idx < tree.size()  ) ){
    throw std::out_of_range("i is out of range");
  }
  return cal_idx;
}

template <typename T>
int getParent(const vector<T>& tree,int idx){
  int parent_idx = floor((idx - 1) / 2);
  return guardRange<T>(tree,idx,parent_idx);
}

template <typename T>
int getLeft(const vector<T>& tree,int idx){
  int left_idx = 2*idx +1;
  return guardRange<T>(tree,idx,left_idx);
}

template <typename T>
int getRight(const vector<T>& tree,int idx){
  int right_idx = 2*idx +2;
  return guardRange<T>(tree,idx,right_idx);
}

// pass by ref *******************************************************
template <typename T>
void climb(vector<T>& tree,int idx,void (*fn)(T&, int)){
  while(idx > 0){
    //printf("sadada\n" );
    int parent_idx = getParent<T>(tree,idx);
    fn(tree[parent_idx],parent_idx);
    //printVect(tree);
    idx = parent_idx;
  }
}

// get index of leaf
template <typename T>
int findLeaf(const vector<T>& tree,const T& leaf){
  int leafCount = nodeCountToLeafCount(tree.size());
  for(int i =0;i<leafCount;i++){
    int idx = tree.size() -1 -i;
    if(strcmp(tree[idx],leaf)==0 )
      return idx;
  }
  return -1;
}

// test
void fnx(int& t,int idx){
  //tree[idx]+= idx*10;
  t += idx*idx;
  //printf("%d\n", t);
  return;
}
