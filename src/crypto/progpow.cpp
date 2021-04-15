// Copyright (c) 2021 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/progpow.h>

#include <chainparams.h>
#include <crypto/progpow/helpers.hpp>
#include <crypto/progpow/include/ethash/ethash.hpp>
#include <hash.h>
#include <primitives/block.h>

#include <sstream>

ethash::epoch_context_ptr epochContext{nullptr,nullptr};

void safe_tohash256(std::string& input, ethash::hash256& hash)
{
    int inSize = input.size();

    //! trim leading 0x..
    if (inSize == 66) {
        std::stringstream temptrunc;
        temptrunc << input.substr(2, 64);
        input = temptrunc.str();
    }

    hash = to_hash256(input);
}

void header_hash(const CBlockHeader& header, uint256& hash)
{
    hash = header.hashPrevBlock;
}

void header_hash(const CBlockHeader& header, ethash::hash256& hash)
{
    uint256 sat_hash = header.hashPrevBlock;
    hash = to_hash256(sat_hash.ToString());
}

void progpow_hash(const CBlockHeader& header, uint256& hash, int height)
{
    ethash::hash256 headerhash;
    header_hash(header, headerhash);
    if (!epochContext || epochContext->epoch_number != ethash::get_epoch_number(height))
    {
        epochContext.reset(ethash::create_epoch_context(ethash::get_epoch_number(height)));
    }
    
    const auto result = progpow::hash(*epochContext, height, headerhash, header.nNonce64);
    hash = uint256S(to_hex(result.final_hash));
}
