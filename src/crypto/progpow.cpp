// Copyright (c) 2021 Andrea Lanfranchi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "progpow.h"

#include <chainparams.h>
#include <crypto/progpow/helpers.hpp>
#include <crypto/progpow/lib/ethash/endianness.hpp>
#include <crypto/progpow/include/ethash/ethash.hpp>
#include <hash.h>
#include <primitives/block.h>

#include <sstream>

static inline ethash::hash256 U256ToH256(const uint256& in) {

    ethash::hash256 ret{};
    auto in_data{reinterpret_cast<const uint64_t*>(in.begin())};
    uint32_t x{0};
    uint32_t y{3};
    for (; x < 4; x++, y--)
    {
        ret.word64s[x] = ethash::be::uint64(in_data[y]);
    }
    return ret;
}

static inline uint256 H256ToU256(const ethash::hash256& in) {
    uint256 ret{};
    auto out_data{reinterpret_cast<uint64_t*>(ret.begin())};
    uint32_t x{0};
    uint32_t y{3};
    for (; x < 4; x++, y--)
    {
        out_data[x] = ethash::be::uint64(in.word64s[y]);
    }
    return ret;
}

uint256 progpow_hash_full(const CProgPowHeader& header, uint256& mix_hash)
{
    static ethash::epoch_context_ptr epochContext{nullptr,nullptr};
    if (!epochContext || epochContext->epoch_number != ethash::get_epoch_number(header.nHeight))
    {
        epochContext.reset();
        epochContext = ethash::create_epoch_context(ethash::get_epoch_number(header.nHeight));
    }

    const auto header_h256{U256ToH256(SerializeHash(header))};
    const auto result = progpow::hash(*epochContext, header.nHeight, header_h256, header.nNonce64);
    mix_hash = H256ToU256(result.mix_hash);
    return H256ToU256(result.final_hash);
}

uint256 progpow_hash_light(const CProgPowHeader& header) 
{
    assert(!header.mix_hash.IsNull());

    const auto header_h256{U256ToH256(SerializeHash(header))};
    const auto mix_h256{U256ToH256(header.mix_hash)};

    const auto seed_h256{progpow::hash_seed(header_h256, header.nNonce64)};
    const auto final_h256{progpow::hash_final(seed_h256, mix_h256)};
    return H256ToU256(final_h256);
}