#ifndef ZCOIN_EXODUS_WALLETDB_H
#define ZCOIN_EXODUS_WALLETDB_H

#include "../serialize.h"
#include "../wallet/walletdb.h"

#include "sigma.h"

#include <string>

namespace exodus {

class SigmaMintId
{
public:
    SigmaMintId()
        : propertyId(0), denomination(0)
    {
    }

    SigmaMintId(const SigmaPublicKey& publicKey, uint32_t propertyId, uint8_t denomination)
        : propertyId(propertyId), denomination(denomination), publicKey(publicKey)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(propertyId);
        READWRITE(denomination);
        READWRITE(publicKey);
    }

    uint32_t propertyId;
    uint8_t denomination;
    SigmaPublicKey publicKey;
};

class SigmaEntry
{
public:
    SigmaPrivateKey privateKey;

    bool isUsed;

    uint32_t propertyId;
    uint8_t denomination;

    uint32_t groupId;
    uint16_t index;
    int32_t block;

    SigmaEntry()
        : isUsed(false), block(-1)
    {
    }

    SigmaMintId GetId() {
        return SigmaMintId(SigmaPublicKey(privateKey), propertyId, denomination);
    }

    bool operator==(const SigmaEntry& other) const;
    bool operator!=(const SigmaEntry& other) const
    {
        return !(*this == other);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(privateKey);

        READWRITE(isUsed);

        READWRITE(propertyId);
        READWRITE(denomination);

        READWRITE(groupId);
        READWRITE(index);
        READWRITE(block);
    }
};

};

#endif // ZCOIN_EXODUS_WALLETDB_H
