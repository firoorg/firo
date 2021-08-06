// Copyright (c) 2021 Andrea Lanfranchi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "progpow.h"

#include <chainparams.h>
#include <crypto/progpow/helpers.hpp>
#include <crypto/progpow/include/ethash/ethash.hpp>
#include <hash.h>
#include <primitives/block.h>

#include <sstream>

uint256 progpow_hash_full(const CBlockHeader& header, uint256& mix_hash)
{
    static ethash::epoch_context_ptr epochContext{nullptr,nullptr};

    auto input = header.GetProgPowHeaderHash();
    auto header_hash {ethash::hash256_from_bytes(input.begin())};

    if (!epochContext || epochContext->epoch_number != ethash::get_epoch_number(header.nHeight))
    {
        epochContext.reset();
        epochContext = ethash::create_epoch_context(ethash::get_epoch_number(header.nHeight));
    }
    
    const auto result = progpow::hash(*epochContext, header.nHeight, header_hash, header.nNonce64);
    mix_hash = uint256(std::vector<unsigned char>(&result.mix_hash.bytes[0], &result.mix_hash.bytes[32]));
    return uint256(std::vector<unsigned char>(&result.final_hash.bytes[0], &result.final_hash.bytes[32]));
}

uint256 progpow_hash_light(const CBlockHeader& header) 
{
    assert(!header.mix_hash.IsNull());

    auto input{header.GetProgPowHeaderHash()};
    auto header_hash{ethash::hash256_from_bytes(input.begin())};
    auto seed_hash{progpow::hash_seed(header_hash, header.nNonce64)};
    auto mix_hash{ethash::hash256_from_bytes(header.mix_hash.begin())};
    auto hash_final = progpow::hash_final(seed_hash, mix_hash);
    return uint256(std::vector<unsigned char>(&hash_final.bytes[0], &hash_final.bytes[32]));
}