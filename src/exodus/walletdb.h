#ifndef EXODUS_WALLET_DB_H
#define EXODUS_WALLET_DB_H

#include "wallet/walletdb.h"
#include "secp256k1/include/GroupElement.h"
#include "serialize.h"

#include "sigma.h"

#include <string>

namespace exodus {

class SigmaMintId
{
public:
    SigmaMintId()
        : commitment(GroupElement()), propertyId(0), denomination(0)
    {
    }
    SigmaMintId(const secp_primitives::GroupElement& commitment, uint32_t propertyId, uint8_t denomination)
        : commitment(commitment), propertyId(propertyId), denomination(denomination)
    {
    }

    secp_primitives::GroupElement commitment;
    uint32_t propertyId;
    uint8_t denomination;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(propertyId);
        READWRITE(denomination);
        READWRITE(commitment);
    }
};

class SigmaEntry
{
public:
    secp_primitives::Scalar randomness;
    secp_primitives::Scalar serialNumber;

    bool isUsed;

    uint32_t propertyId;
    uint8_t denomination;

    uint32_t groupId;
    uint16_t index;
    int32_t block;

    SigmaEntry()
    {
        SetNull();
    }

    SigmaPrivateKey getPrivateKey() {
        SigmaPrivateKey key;
        key.SetSerial(serialNumber);
        key.SetRandomness(randomness);
        return key;
    }

    SigmaPublicKey getPublicKey() {
        return SigmaPublicKey(getPrivateKey());
    }

    SigmaMintId GetId() {
        return SigmaMintId(getPublicKey().GetCommitment(), propertyId, denomination);
    }

    bool operator==(const SigmaEntry& other) const
    {
        return randomness == other.randomness
            && serialNumber == other.serialNumber
            && isUsed == other.isUsed
            && propertyId == other.propertyId
            && denomination == other.denomination
            && groupId == other.groupId
            && index == other.index
            && block == other.block;
    }

    bool operator!=(const SigmaEntry& other) const
    {
        return !(*this == other);
    }

    void SetNull()
    {
        randomness = secp_primitives::Scalar();
        serialNumber = secp_primitives::Scalar();

        isUsed = false;

        propertyId = 0;
        denomination = 0;

        groupId = 0;
        index = 0;
        block = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(randomness);
        READWRITE(serialNumber);

        READWRITE(isUsed);

        READWRITE(propertyId);
        READWRITE(denomination);

        READWRITE(groupId);
        READWRITE(index);
        READWRITE(block);
    }
};

};

#endif // EXODUS_WALLET_DB_H
