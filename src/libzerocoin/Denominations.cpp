// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Denominations.h"
#include "amount.h"

namespace libzerocoin {
// All denomination values should only exist in these routines for consistency.
// For serialization/unserialization enums are converted to int (denoted enumvalue in function name)

CoinDenomination IntToZerocoinDenomination(int64_t amount)
{
    CoinDenomination denomination;
    switch (amount) {
    case 1:   denomination = CoinDenomination::ZQ_LOVELACE; break;
    case 10:  denomination = CoinDenomination::ZQ_GOLDWASSER; break;
    case 25:  denomination = CoinDenomination::ZQ_RACKOFF; break;
    case 50:  denomination = CoinDenomination::ZQ_PEDERSEN; break;
    case 100: denomination = CoinDenomination::ZQ_WILLIAMSON; break;
    default:
        //not a valid denomination
        denomination = CoinDenomination::ZQ_ERROR; break;
    }

    return denomination;
}

int64_t ZerocoinDenominationToInt(const CoinDenomination& denomination)
{
    int64_t Value = 0;
    switch (denomination) {

    case CoinDenomination::ZQ_LOVELACE: Value = 1; break;
    case CoinDenomination::ZQ_GOLDWASSER: Value = 10; break;
    case CoinDenomination::ZQ_RACKOFF: Value = 25; break;
    case CoinDenomination::ZQ_PEDERSEN: Value = 50; break;
    case CoinDenomination::ZQ_WILLIAMSON: Value = 100; break;
    default:
        // Error Case
        Value = 0; break;
    }
    return Value;
}

CoinDenomination AmountToZerocoinDenomination(CAmount amount)
{
    // Check to make sure amount is an exact integer number of COINS
    CAmount residual_amount = amount - COIN * (amount / COIN);
    if (residual_amount == 0) {
        return IntToZerocoinDenomination(amount/COIN);
    } else {
        return CoinDenomination::ZQ_ERROR;
    }
}

// return the highest denomination that is less than or equal to the amount given
// use case: converting zcoin to zerocoin without user worrying about denomination math themselves
CoinDenomination AmountToClosestDenomination(CAmount nAmount, CAmount& nRemaining)
{
    if (nAmount < 1 * COIN)
        return ZQ_ERROR;

    CAmount nConvert = nAmount / COIN;
    CoinDenomination denomination = ZQ_ERROR;
    for (unsigned int i = 0; i < zerocoinDenomList.size(); i++) {
        denomination = zerocoinDenomList[i];

        //exact match
        if (nConvert == denomination) {
            nRemaining = 0;
            return denomination;
        }

        //we are beyond the value, use previous denomination
        if (denomination > nConvert && i) {
            CoinDenomination d = zerocoinDenomList[i - 1];
            nRemaining = nConvert - d;
            return d;
        }
    }
    //last denomination, the highest value possible
    nRemaining = nConvert - denomination;
    return denomination;
}

CAmount ZerocoinDenominationToAmount(const CoinDenomination& denomination)
{
    CAmount nValue = COIN * ZerocoinDenominationToInt(denomination);
    return nValue;
}


CoinDenomination get_denomination(std::string denomAmount) {
    int64_t val = std::stoi(denomAmount);
    return IntToZerocoinDenomination(val);
}


int64_t get_amount(std::string denomAmount) {
    int64_t nAmount = 0;
    CoinDenomination denom = get_denomination(denomAmount);
    if (denom == ZQ_ERROR) {
        // SHOULD WE THROW EXCEPTION or Something?
        nAmount = 0;
    } else {
        nAmount = ZerocoinDenominationToAmount(denom);
    }
    return nAmount;
}

} /* namespace libzerocoin */