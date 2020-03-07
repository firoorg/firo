#ifndef ZCOIN_LIBLELANTUS_COIN_H
#define ZCOIN_LIBLELANTUS_COIN_H

#include "lelantus_primitives.h"
#include "params.h"

#include "../libzerocoin/Zerocoin.h"

namespace lelantus {

class PublicCoin {
public:
    PublicCoin();

    PublicCoin(const GroupElement& coin);

    const GroupElement& getValue() const;
    uint256 getValueHash() const;
    bool operator==(const PublicCoin& other) const;
    bool operator!=(const PublicCoin& other) const;
    bool validate() const;
    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size =  GetSerializeSize(nType, nVersion);
        unsigned char buffer[size];
        value.serialize(buffer);
        char* b = (char*)buffer;
        s.write(b, size);
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size =  GetSerializeSize(nType, nVersion);
        unsigned char buffer[size];
        char* b = (char*)buffer;
        s.read(b, size);
        value.deserialize(buffer);
        s.read(b, size);
    }

private:
    GroupElement value;
};

class PrivateCoin {
public:

    PrivateCoin(const Params* p, const Scalar& v);
    PrivateCoin(const Params* p,const Scalar& serial, const Scalar& v, const Scalar& random, int version_);
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    const Scalar& getV() const;
    unsigned int getVersion() const;
    void setPublicCoin(const PublicCoin& p);
    void setRandomness(const Scalar& n);
    void setSerialNumber(const Scalar& n);
    void setV(const Scalar& n);
    void setVersion(unsigned int nVersion);

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar serialNumber;
    Scalar value;
    Scalar randomness;
    unsigned int version = 0;

private:
    void mintCoin(const Scalar& v);
};

}// namespace lelantus

#endif //ZCOIN_LIBLELANTUS_COIN_H
