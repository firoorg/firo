#include "blockfilterindex.h"

#include "primitives/block.h"
#include "blockfilter.h"


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

