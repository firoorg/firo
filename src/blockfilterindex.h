#ifndef BLOCKFILTERINDEX_H
#define BLOCKFILTERINDEX_H

#include <vector>

#include "uint256.h"
#include "blockfilter.h"

class CBlock;
class CBlockIndex;
class CBlockUndo;

static constexpr int CFCHECKPT_INTERVAL = 1000;

class BlockFilterIndex {
public:
    BlockFilterIndex();
    BlockFilterIndex(CBlock const & block, CBlockUndo const & blockUndo, uint256 prevHeader);

    std::vector<unsigned char> GetEncoded() const;
    uint256 GetHeader() const;

/** Get a single filter by block. */
    bool LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const;

    /** Get a single filter header by block. */
    bool LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out) const;

    /** Get a range of filters between two heights on a chain. */
    bool LookupFilterRange(int start_height, const CBlockIndex* stop_index,
                           std::vector<BlockFilter>& filters_out) const;

    /** Get a range of filter hashes between two heights on a chain. */
    bool LookupFilterHashRange(int start_height, const CBlockIndex* stop_index,
                               std::vector<uint256>& hashes_out) const;

private:
    std::vector<unsigned char> encoded;
    uint256 header;
};

BlockFilterIndex * GetBlockFilterIndex(BlockFilterType filterType);

#endif /* BLOCKFILTERINDEX_H */

