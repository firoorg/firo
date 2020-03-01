#ifndef ZCOIN_LELANTUS_COIN_H
#define ZCOIN_LELANTUS_COIN_H

#include "lelantus_primitives.h"
#include "params.h"



namespace lelantus {

class PublicCoin {
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

class PrivateCoin {
public:

    PrivateCoin(const Params* p, const Scalar& v);
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(PublicCoin p);
    void setRandomness(Scalar n);
    void setSerialNumber(Scalar n);
    void setVersion(unsigned int nVersion);

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;

private:
    void mintCoin(const Scalar& v);
};

}// namespace lelantus

#endif //ZCOIN_LELANTUS_COIN_H
