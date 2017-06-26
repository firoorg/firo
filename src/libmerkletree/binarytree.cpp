#include "binarytree.hpp"


void printVect(vector<int> v) {
	for (int i = 0; i<v.size(); i++)
		printf("%d ", v[i]);
	printf("\n");
}

// leafCount => nodeCount
int leafCountToNodeCount(const int leftCount) {
	return leftCount * 2 - 1;
}

// nodeCount => leafCount
int nodeCountToLeafCount(const int nodeCount) {
	return (nodeCount + 1) / 2;
}

// isn't leaf
bool isInteriorNode(int idx, int nodeCount) {
	int leftCount = nodeCountToLeafCount(nodeCount);
	return idx >= 0 && idx< (nodeCount - leftCount);
}

// test
void fnx(int& t, int idx) {
	//tree[idx]+= idx*10;
	t += idx*idx;
	//printf("%d\n", t);
	return;
}
