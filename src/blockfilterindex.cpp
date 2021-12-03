#include "blockfilterindex.h"

#include "primitives/block.h"
#include "blockfilter.h"

BlockFilterIndex::BlockFilterIndex()
{}

BlockFilterIndex::BlockFilterIndex(CBlock const & block, CBlockUndo const & blockUndo, uint256 prevHeader)
{
    BlockFilter bf(BlockFilterType::Basic, block, blockUndo);
    encoded = bf.GetEncodedFilter();
    header = bf.ComputeHeader(prevHeader);
}

std::vector<unsigned char> BlockFilterIndex::GetEncoded() const
{
    return encoded;
}

uint256 BlockFilterIndex::GetHeader() const
{
    return header;
}

bool BlockFilterIndex::LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const
{
    return false;
}

bool BlockFilterIndex::LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out)
{
    return false;
}

bool BlockFilterIndex::LookupFilterRange(int start_height, const CBlockIndex* stop_index, std::vector<BlockFilter>& filters_out) const
{
    return false;
}


bool BlockFilterIndex::LookupFilterHashRange(int start_height, const CBlockIndex* stop_index, std::vector<uint256>& hashes_out) const
{
    return false;
}


BlockFilterIndex * GetBlockFilterIndex(BlockFilterType filterType)
{
    static BlockFilterIndex inst;
    return &inst;
}