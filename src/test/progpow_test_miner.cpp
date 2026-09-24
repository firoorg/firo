// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/progpow/helpers.hpp>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <utilstrencodings.h>

#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv)
{
    try {
        if (argc != 4)
            throw std::invalid_argument("usage: progpow_test_miner HEIGHT HEADER TARGET");
        int height;
        // These RPC tests mine below height 1300, entirely within epoch zero.
        if (!ParseInt32(argv[1], &height) || height < 0 || height >= ethash::epoch_length)
            throw std::invalid_argument("test height must be in epoch zero");
        for (int i : {2, 3}) {
            const std::string hex = argv[i];
            if (hex.size() != 64 || hex.find_first_not_of("0123456789abcdef") != std::string::npos)
                throw std::invalid_argument("expected 32-byte lowercase hex");
        }
        const auto context = ethash::create_epoch_context(0);
        if (!context)
            throw std::runtime_error("could not allocate epoch context");
        const auto solution = progpow::search_light(*context, height, to_hash256(argv[2]), to_hash256(argv[3]), 0, 1000);
        if (!solution.solution_found)
            throw std::runtime_error("no solution within 1000 nonces");
        std::cout << solution.nonce << ' ' << to_hex(solution.mix_hash) << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
