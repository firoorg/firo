#include "blockfilterindex.h"

#include "primitives/block.h"
#include "blockfilter.h"
#include "chain.h"
#include "txdb.h"
#include "batchproof_container.h"


extern CBlockTreeDB *pblocktree;
extern CCriticalSection cs_main;


BlockFilterIndex::BlockFilterIndex()
{}

BlockFilterIndex::BlockFilterIndex(CBlock const & block, CBlockUndo const & blockUndo, uint256 prevHeader)
{
    BlockFilter bf(BlockFilterType::Basic, block, blockUndo);
    encoded = bf.GetEncodedFilter();
    hash = bf.GetHash();
    header = bf.ComputeHeader(prevHeader);
}

std::vector<unsigned char> BlockFilterIndex::GetEncoded() const
{
    return encoded;
}

uint256 BlockFilterIndex::GetHash() const
{
    return hash;
}

uint256 BlockFilterIndex::GetHeader() const
{
    return header;
}

bool BlockFilterIndex::LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const
{
    std::tuple<std::vector<unsigned char>, uint256, uint256> rawFilter =
        pblocktree->ReadBlockFilterIndex(block_index->GetBlockHash());
    if (std::get<0>(rawFilter).empty())
        return false;
    filter_out = BlockFilter{BlockFilterType::Basic, block_index->GetBlockHash(), std::get<0>(rawFilter)};
    return true;
}

bool BlockFilterIndex::LookupFilterHash(const CBlockIndex* block_index, uint256& header_out) const
{
    std::tuple<std::vector<unsigned char>, uint256, uint256> rawFilter =
        pblocktree->ReadBlockFilterIndex(block_index->GetBlockHash());
    if (std::get<0>(rawFilter).empty())
        return false;
    header_out = std::get<1>(rawFilter);
    return true;
}

bool BlockFilterIndex::LookupHeaderHash(const CBlockIndex* block_index, uint256& header_out) const
{
    std::tuple<std::vector<unsigned char>, uint256, uint256> rawFilter =
        pblocktree->ReadBlockFilterIndex(block_index->GetBlockHash());
    if (std::get<0>(rawFilter).empty())
        return false;
    header_out = std::get<2>(rawFilter);
    return true;
}

bool BlockFilterIndex::LookupFilterRange(int start_height, const CBlockIndex* stop_index, std::vector<BlockFilter>& filters_out) const
{
    bool result = true;
    while (stop_index->nHeight >= start_height) {
        BlockFilter out;
        if (LookupFilter(stop_index, out)) {
            filters_out.emplace_back(std::move(out));
        } else {
            result = false;
            break;
        }
        if (stop_index->nHeight == start_height)
            break;
        {
            LOCK(cs_main);
            if (!stop_index->pprev) {
                result = false;
                break;
            }
            stop_index = stop_index->pprev;
        }
    }
    std::reverse(filters_out.begin(), filters_out.end());
    return result;
}


bool BlockFilterIndex::LookupHeaderHashRange(int start_height, const CBlockIndex* stop_index, std::vector<uint256>& hashes_out) const
{
    bool result = true;
    while (stop_index->nHeight >= start_height) {
        uint256 out;
        if (LookupFilterHash(stop_index, out)) {
            hashes_out.emplace_back(std::move(out));
        } else {
            result = false;
            break;
        }
        if (stop_index->nHeight == start_height)
            break;
        {
            LOCK(cs_main);
            if (!stop_index->pprev) {
                result = false;
                break;
            }
            stop_index = stop_index->pprev;
        }
    }
    std::reverse(hashes_out.begin(), hashes_out.end());
    return result;
}


BlockFilterIndex * GetBlockFilterIndex(BlockFilterType filterType)
{
    static BlockFilterIndex inst;
    return &inst;
}

bool UpdateGenesisBlockFilterIndex(CBlock const & block)
{
    BlockFilterIndex bfidx(block, CBlockUndo{}, uint256{});
    if (!pblocktree->UpdateBlockFilterIndex(block.GetHash(), bfidx.GetEncoded(), bfidx.GetHash(), bfidx.GetHeader()))
        return error("Failed to write block filter index");
    return true;
}
