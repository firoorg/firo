// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRIMITIVES_ZEROCOIN_H
#define PRIMITIVES_ZEROCOIN_H

#include <amount.h>
#include <streams.h>
#include <boost/optional.hpp>
#include <limits.h>
#include "libzerocoin/bitcoin_bignum/bignum.h"
#include "libzerocoin/Zerocoin.h"
#include "key.h"
#include "sigma/coin.h"
#include "serialize.h"
#include "zerocoin_params.h"

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
struct CMintMeta
{
    int nHeight;
    int nId;
    GroupElement const & GetPubCoinValue() const;
    void SetPubCoinValue(GroupElement const & other);
    uint256 GetPubCoinValueHash() const;
    uint256 hashSerial;
    uint8_t nVersion;
    sigma::CoinDenomination denom;
    uint256 txid;
    bool isUsed;
    bool isArchived;
    bool isDeterministic;
    bool isSeedCorrect;
private:
    GroupElement pubCoinValue;
    mutable boost::optional<uint256> pubCoinValueHash;
};

class CZerocoinEntry
{
private:
    template <typename Stream>
    auto is_eof_helper(Stream &s, bool) -> decltype(s.eof()) {
        return s.eof();
    }

    template <typename Stream>
    bool is_eof_helper(Stream &s, int) {
        return false;
    }

    template<typename Stream>
    bool is_eof(Stream &s) {
        return is_eof_helper(s, true);
    }

public:
    //public
    Bignum value;
    int denomination;
    //private
    Bignum randomness;
    Bignum serialNumber;
    vector<unsigned char> ecdsaSecretKey;

    bool IsUsed;
    int nHeight;
    int id;

    // used for reminting to sigma
    bool IsUsedForRemint;

    CZerocoinEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        IsUsed = IsUsedForRemint = false;
        randomness = 0;
        serialNumber = 0;
        value = 0;
        denomination = -1;
        nHeight = -1;
        id = -1;
    }

    bool IsCorrectV2Mint() const {
        return value > 0 && randomness > 0 && serialNumber > 0 && serialNumber.bitSize() <= 160 &&
                ecdsaSecretKey.size() >= 32;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(IsUsed);
        READWRITE(randomness);
        READWRITE(serialNumber);
        READWRITE(value);
        READWRITE(denomination);
        READWRITE(nHeight);
        READWRITE(id);
        if (ser_action.ForRead()) {
            IsUsedForRemint = false;
            if (!is_eof(s)) {
                int nStoredVersion = 0;
                READWRITE(nStoredVersion);
                if (nStoredVersion >= ZC_ADVANCED_WALLETDB_MINT_VERSION) {
                    READWRITE(ecdsaSecretKey);
                    if (!is_eof(s))
                        READWRITE(IsUsedForRemint);
                }
            }
        }
        else {
            READWRITE(nVersion);
            READWRITE(ecdsaSecretKey);
            READWRITE(IsUsedForRemint);
        }
    }

};


class CSigmaEntry
{
public:
    void set_denomination(sigma::CoinDenomination denom) {
        DenominationToInteger(denom, denomination);
    }
    void set_denomination_value(int64_t new_denomination) {
        denomination = new_denomination;
    }
    int64_t get_denomination_value() const {
        return denomination;
    }
    sigma::CoinDenomination get_denomination() const {
        sigma::CoinDenomination result;
        IntegerToDenomination(denomination, result);
        return result;
    }

    std::string get_string_denomination() const {
        return DenominationToString(get_denomination());
    }

    //public
    GroupElement value;

    //private
    Scalar randomness;
    Scalar serialNumber;

    // Signature over partial transaction
    // to make sure the outputs are not changed by attacker.
    std::vector<unsigned char> ecdsaSecretKey;

    bool IsUsed;
    int nHeight;
    int id;

private:
    // NOTE(martun): made this one private to make sure people don't
    // misuse it and try to assign a value of type sigma::CoinDenomination
    // to it. In these cases the value is automatically converted to int,
    // which is not what we want.
    // Starting from Version 3 == sigma, this number is coin value * COIN,
    // I.E. it is set to 100.000.000 for 1 zcoin.
    int64_t denomination;

public:

    CSigmaEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        IsUsed = false;
        randomness = Scalar(uint64_t(0));
        serialNumber = Scalar(uint64_t(0));
        value = GroupElement();
        denomination = -1;
        nHeight = -1;
        id = -1;
    }

    bool IsCorrectSigmaMint() const {
        return randomness.isMember() && serialNumber.isMember();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(IsUsed);
        READWRITE(randomness);
        READWRITE(serialNumber);
        READWRITE(value);
        READWRITE(denomination);
        READWRITE(nHeight);
        READWRITE(id);
        if (ser_action.ForRead()) {
            if (!is_eof(s)) {
                int nStoredVersion = 0;
                READWRITE(nStoredVersion);
                READWRITE(ecdsaSecretKey);
            }
        }
        else {
            READWRITE(nVersion);
            READWRITE(ecdsaSecretKey);
        }
    }
private:
    template <typename Stream>
    auto is_eof_helper(Stream &s, bool) -> decltype(s.eof()) {
        return s.eof();
    }

    template <typename Stream>
    bool is_eof_helper(Stream &s, int) {
        return false;
    }

    template<typename Stream>
    bool is_eof(Stream &s) {
        return is_eof_helper(s, true);
    }
};


class CZerocoinSpendEntry
{
public:
    Bignum coinSerial;
    uint256 hashTx;
    Bignum pubCoin;
    int denomination;
    int id;

    CZerocoinSpendEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        coinSerial = 0;
//        hashTx =
        pubCoin = 0;
        denomination = 0;
        id = 0;
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(coinSerial);
        READWRITE(hashTx);
        READWRITE(pubCoin);
        READWRITE(denomination);
        READWRITE(id);
    }
};

class CSigmaSpendEntry
{
public:
    Scalar coinSerial;
    uint256 hashTx;
    GroupElement pubCoin;
    int id;

    void set_denomination(sigma::CoinDenomination denom) {
        DenominationToInteger(denom, denomination);
    }

    void set_denomination_value(int64_t new_denomination) {
        denomination = new_denomination;
    }

    int64_t get_denomination_value() const {
        return denomination;
    }

    sigma::CoinDenomination get_denomination() const {
        sigma::CoinDenomination result;
        IntegerToDenomination(denomination, result);
        return result;
    }

    CSigmaSpendEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        coinSerial = Scalar(uint64_t(0));
//        hashTx =
        pubCoin = GroupElement();
        denomination = 0;
        id = 0;
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(coinSerial);
        READWRITE(hashTx);
        READWRITE(pubCoin);
        READWRITE(denomination);
        READWRITE(id);
    }
private:
    // NOTE(martun): made this one private to make sure people don't
    // misuse it and try to assign a value of type sigma::CoinDenomination
    // to it. In these cases the value is automatically converted to int,
    // which is not what we want.
    // Starting from Version 3 == sigma, this number is coin value * COIN,
    // I.E. it is set to 100.000.000 for 1 zcoin.
    int64_t denomination;
};

namespace primitives {
uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue);
}

#endif //PRIMITIVES_ZEROCOIN_H
