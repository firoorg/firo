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
    if (!epochContext || epochContext->epoch_number != ethash::get_epoch_number(header.nHeight))
    {
        epochContext.reset();
        epochContext = ethash::create_epoch_context(ethash::get_epoch_number(header.nHeight));
    }

    const auto header_hex = header.GetProgPowHeaderHash().GetHex();
    const auto header_h256 = to_hash256(header_hex);
    const auto result = progpow::hash(*epochContext, header.nHeight, header_h256, header.nNonce64);
    mix_hash.SetHex(to_hex(result.mix_hash));
    return uint256S(to_hex(result.final_hash));
}

uint256 progpow_hash_light(const CBlockHeader& header) 
{
    assert(!header.mix_hash.IsNull());

    const auto header_hex = header.GetProgPowHeaderHash().GetHex();
    const auto mix_hex = header.mix_hash.GetHex();
    const auto header_h256 = to_hash256(header_hex);
    const auto mix_h256 = to_hash256(mix_hex);

    const auto seed_h256{progpow::hash_seed(header_h256, header.nNonce64)};
    const auto final_h256{progpow::hash_final(seed_h256, mix_h256)};
    return uint256S(to_hex(final_h256));

}