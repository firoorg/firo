#ifndef BLOCKFILTERINDEX_H
#define BLOCKFILTERINDEX_H

#include <vector>

#include "uint256.h"

class CBlock;
class CBlockUndo;

class BlockFilterIndex {
public:
    BlockFilterIndex(CBlock const & block, CBlockUndo const & blockUndo, uint256 prevHeader);

    std::vector<unsigned char> GetEncoded() const;
    uint256 GetHeader() const;
private:
    std::vector<unsigned char> encoded;
    uint256 header;
};

#endif /* BLOCKFILTERINDEX_H */

