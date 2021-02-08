// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRIMITIVES_ZEROCOIN_H
#define PRIMITIVES_ZEROCOIN_H

#include <amount.h>
#include <streams.h>
#include <boost/optional.hpp>
#include <limits.h>
#include "key.h"
#include "sigma/coin.h"
#include "serialize.h"
#include "zerocoin_params.h"

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
struct MintMeta
{
    int nHeight;
    int nId;
    GroupElement const & GetPubCoinValue() const;
    void SetPubCoinValue(GroupElement const & other);
    uint256 GetPubCoinValueHash() const ;
    uint256 hashSerial;
    uint8_t nVersion;
    uint256 txid;
    bool isUsed;
    bool isArchived;
    bool isSeedCorrect;
protected:
    GroupElement pubCoinValue;
    mutable boost::optional<uint256> pubCoinValueHash;
};

struct CMintMeta : MintMeta
{
    bool isDeterministic;
    sigma::CoinDenomination denom;
};

struct CLelantusMintMeta : MintMeta
{
    uint64_t amount;
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
    // I.E. it is set to 100.000.000 for 1 firo.
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
    inline void SerializationOp(Stream& s, Operation ser_action) {
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
            int streamVersion = s.GetVersion();
            READWRITE(streamVersion);
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

struct CLelantusEntry {
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

    // Starting from Version 3 == sigma, this number is coin value * COIN,
    // I.E. it is set to 100.000.000 for 1 firo.
    int64_t amount;
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
    inline void SerializationOp(Stream& s, Operation ser_action) {
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
    // I.E. it is set to 100.000.000 for 1 firo.
    int64_t denomination;
};

class CLelantusSpendEntry
{
public:
    Scalar coinSerial;
    uint256 hashTx;
    GroupElement pubCoin;
    int id;
    int64_t amount;

    CLelantusSpendEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        coinSerial = Scalar(uint64_t(0));
        pubCoin = GroupElement();
        id = 0;
        amount = 0;
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(coinSerial);
        READWRITE(hashTx);
        READWRITE(pubCoin);
        READWRITE(id);
        READWRITE(amount);
    }
};

namespace primitives {
uint256 GetSerialHash(const secp_primitives::Scalar& bnSerial);
uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue);
}

#endif //PRIMITIVES_ZEROCOIN_H
