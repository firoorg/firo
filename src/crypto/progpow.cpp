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

void progpow_hash(const CBlockHeader& header, uint256& hash, int height)
{
    static ethash::epoch_context_ptr epochContext{nullptr,nullptr};

    auto input = header.GetProgPowHeaderHash();
    ethash::hash256 headerhash{to_hash256(input.GetHex())};

    if (!epochContext || epochContext->epoch_number != ethash::get_epoch_number(height))
    {
        epochContext.reset();
        epochContext = ethash::create_epoch_context(ethash::get_epoch_number(height));
    }
    
    const auto result = progpow::hash(*epochContext, height, headerhash, header.nNonce64);
    hash = uint256S(to_hex(result.final_hash));
}
