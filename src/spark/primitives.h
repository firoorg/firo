#ifndef FIRO_PRIMITIVES_H
#define FIRO_PRIMITIVES_H

#include "libspark/coin.h"
#include "serialize.h"
#include "../uint256.h"

struct CSparkMintMeta
{
    int nHeight;
    int nId;
    bool isUsed;
    uint256 txid;
    uint64_t i; // diversifier
    std::vector<unsigned char> d; // encrypted diversifier
    uint64_t v; // value
    Scalar k; // nonce
    std::string memo; // memo
    std::vector<unsigned char> serial_context;
    char type;
    spark::Coin coin;
    mutable boost::optional<uint256> nonceHash;
    Scalar a;
    Scalar iota;

    uint256 GetNonceHash() const;

    std::uint64_t GetValue() const noexcept { return v; }

    bool IsUsed() const noexcept { return isUsed; }

    // TODO what does 1 fall under - confirmed or unconfirmed or neither?
    bool IsConfirmed() const noexcept { return nHeight > 1; }
    bool IsUnconfirmed() const noexcept { return nHeight < 1; }

    // TODO any need to check `type` as well? Perhaps just for better performance?
    bool IsSpats() const noexcept { return !coin.a.isZero(); }

    bool operator==(const CSparkMintMeta& other) const
    {
        return this->k == other.k;
    }

    bool operator!=(const CSparkMintMeta& other) const
    {
        return this->k != other.k;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nHeight);
        READWRITE(nId);
        READWRITE(isUsed);
        READWRITE(txid);
        READWRITE(i);
        READWRITE(d);
        READWRITE(v);
        READWRITE(k);
        READWRITE(memo);
        READWRITE(serial_context);
        READWRITE(type);
        READWRITE(coin);
        if (type > spark::COIN_TYPE_SPEND) {
            READWRITE(a);
            READWRITE(iota);
        }
    };
};

class CSparkSpendEntry
{
public:
    GroupElement lTag;
    uint256 lTagHash;
    uint256 hashTx;
    int64_t amount;

    CSparkSpendEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        lTag = GroupElement();
        lTagHash = uint256();
        amount = 0;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(lTag);
        READWRITE(lTagHash);
        READWRITE(hashTx);
        READWRITE(amount);
    }
};

class CSparkOutputTx
{
public:
    std::string address;
    std::string memo;
    int64_t amount;

    CSparkOutputTx()
    {
        SetNull();
    }

    void SetNull()
    {
        address = "";
        memo = "";
        amount = 0;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(address);
        READWRITE(amount);
        if (ser_action.ForRead()) {
            if (!s.empty()) {
                READWRITE(memo);
            } else {
                memo = "";
            }
        } else {
            READWRITE(memo);
        }
    }
};

namespace primitives {
    uint256 GetNonceHash(const secp_primitives::Scalar& nonce);
    uint256 GetLTagHash(const secp_primitives::GroupElement& tag);
    uint256 GetSparkCoinHash(const spark::Coin& coin);
}

namespace spark {
// Custom hash for the spark coin. norte. THIS IS NOT SECURE HASH FUNCTION
struct CoinHash {
    std::size_t operator()(const spark::Coin& coin) const noexcept;
};

// Custom hash for the linking tag. THIS IS NOT SECURE HASH FUNCTION
struct CLTagHash {
    std::size_t operator()(const secp_primitives::GroupElement& tag) const noexcept;
};

struct CMintedCoinInfo {
    int coinGroupId;
    int nHeight;

    static CMintedCoinInfo make(int coinGroupId, int nHeight);
};

}


#endif //FIRO_PRIMITIVES_H
