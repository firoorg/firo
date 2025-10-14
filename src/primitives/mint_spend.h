// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRIMITIVES_MINT_SPEND_H
#define PRIMITIVES_MINT_SPEND_H

#include <amount.h>
#include <streams.h>
#include <boost/optional.hpp>
#include <limits.h>
#include "key.h"
#include "liblelantus/coin.h"
#include "serialize.h"
#include "firo_params.h"

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

struct CLelantusMintMeta : MintMeta
{
    uint64_t amount;
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

#endif //PRIMITIVES_MINT_SPEND_H
