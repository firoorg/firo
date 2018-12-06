#ifndef ZCOIN_NEXTGEN_COIN_H
#define ZCOIN_NEXTGEN_COIN_H

#include "NextGenPrimitives.h"
#include "../serialize.h"
#include <libzerocoin/Zerocoin.h>
#include "Params.h"

namespace nextgen {

class PublicCoin{
public:
//    template<typename Stream>
//    PublicCoin(Stream& strm){
//        strm >> *this;
//    }

    PublicCoin();

    PublicCoin(const GroupElement& coin, const Scalar& d);

    const GroupElement& getValue() const;
    const Scalar& get_v() const;
    bool operator==(const PublicCoin& other) const;
    bool operator!=(const PublicCoin& other) const;
    bool validate() const;
    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size = value.memoryRequired() + v.memoryRequired();
        unsigned char buffer[size];
        unsigned char* current = value.serialize(buffer);
        v.serialize(current);
        char* b = (char*)buffer;
        s.write(b, size);
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = value.memoryRequired() + + v.memoryRequired();
        unsigned char buffer[size];
        char* b = (char*)buffer;
        unsigned char* current = value.deserialize(buffer);
        v.deserialize(current);
        s.read(b, size);
    }

private:
    GroupElement value;
    Scalar v;
};

class PrivateCoin{
public:
//    PrivateCoin(const Params* p, CDataStream& strm): params(p), publicCoin() {
//        strm >> *this;
//    }

    PrivateCoin(const Params* p, const Scalar& v);
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(PublicCoin p);
    void setRandomness(Scalar n);
    void setSerialNumber(Scalar n);
    void setVersion(unsigned int nVersion);

    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size = randomness.memoryRequired() * 2;
        publicCoin.Serialize(s, nType, nVersion);
        unsigned char buffer[size];
        unsigned char* current = randomness.serialize(current);
        current = serialNumber.serialize(current);
        char* b = (char*)buffer;
        s.write(b, size);
        s << version;
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = randomness.memoryRequired() * 2;
        publicCoin.Unserialize(s, nType, nVersion);
        unsigned char buffer[size];
        unsigned char* current = randomness.deserialize(current);
        current = serialNumber.deserialize(current);
        char* b = (char*)buffer;
        s.read(b, size);
        s >> version;
    }

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;

private:
    void mintCoin(const Scalar& v);
};

}// namespace nextgen

#endif //ZCOIN_NEXTGEN_COIN_H
