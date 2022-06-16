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
    mutable boost::optional<uint256> nonceHash;

    uint256 GetNonceHash() const;

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
    };
};


namespace primitives {
    uint256 GetNonceHash(const secp_primitives::Scalar& nonce);
}


#endif //FIRO_PRIMITIVES_H
