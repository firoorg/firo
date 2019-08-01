#ifndef EXODUS_WALLET_DB_H
#define EXODUS_WALLET_DB_H

#include "wallet/walletdb.h"
#include "secp256k1/include/GroupElement.h"
#include "serialize.h"

#include "sigma.h"

#include <string>

namespace exodus {

class CSigmaEntry
{
public:
    secp_primitives::GroupElement value;

    secp_primitives::Scalar randomness;
    secp_primitives::Scalar serialNumber;

    bool isUsed;

    uint32_t propertyID;
    uint32_t denomination;

    uint32_t groupID;
    uint32_t index;
    int nBlock;

    CSigmaEntry()
    {
        SetNull();
    }

    bool operator==(const CSigmaEntry& other) const
    {
        return value == other.value && randomness == other.randomness
            && serialNumber == other.serialNumber
            && isUsed == other.isUsed
            && propertyID == other.propertyID
            && denomination == other.denomination
            && groupID == other.groupID
            && index == other.index
            && nBlock == other.nBlock;
    }

    bool operator!=(const CSigmaEntry& other) const
    {
        return !(*this == other);
    }

    void SetNull()
    {
        value = secp_primitives::GroupElement();
        randomness = secp_primitives::Scalar();
        serialNumber = secp_primitives::Scalar();

        isUsed = false;

        propertyID = 0;
        denomination = 0;

        groupID = 0;
        index = 0;
        nBlock = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(value);
        READWRITE(randomness);
        READWRITE(serialNumber);

        READWRITE(isUsed);

        READWRITE(propertyID);
        READWRITE(denomination);

        READWRITE(groupID);
        READWRITE(index);
        READWRITE(nBlock);
    }
};

};

#endif // EXODUS_WALLET_DB_H
