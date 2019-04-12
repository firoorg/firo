// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DENOMINATIONS_H_
#define DENOMINATIONS_H_

#include <cstdint>
#include <string>
#include <vector>

namespace libzerocoin {

enum  CoinDenomination {
    ZQ_ERROR = 0,
    ZQ_LOVELACE = 1,
    ZQ_GOLDWASSER = 10,
    ZQ_RACKOFF = 25,
    ZQ_PEDERSEN = 50,
    ZQ_WILLIAMSON = 100
};

// Order is with the Smallest Denomination first and is important for a particular routine that this order is maintained
const std::vector<CoinDenomination> zerocoinDenomList = {ZQ_LOVELACE, ZQ_GOLDWASSER, ZQ_RACKOFF, ZQ_PEDERSEN, ZQ_WILLIAMSON};

// These are the max number you'd need at any one Denomination before moving to the higher denomination. Last number is 4, since it's the max number of
// possible spends at the moment    /
// const std::vector<int> maxCoinsAtDenom   = {4, 1, 4, 1, 4, 1, 4, 4};

int64_t ZerocoinDenominationToInt(const CoinDenomination& denomination);
int64_t ZerocoinDenominationToAmount(const CoinDenomination& denomination);
CoinDenomination IntToZerocoinDenomination(int64_t amount);
CoinDenomination AmountToZerocoinDenomination(int64_t amount);
CoinDenomination AmountToClosestDenomination(int64_t nAmount, int64_t& nRemaining);
CoinDenomination get_denomination(std::string denomAmount);
int64_t get_amount(std::string denomAmount);

} /* namespace libzerocoin */
#endif /* DENOMINATIONS_H_ */