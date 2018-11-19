#ifndef ZCOIN_SIGMA_COIN_H
#define ZCOIN_SIGMA_COIN_H

#include "SigmaPrimitives.h"
#include <libzerocoin/Zerocoin.h>
#include "Params.h"

namespace sigma {

enum  V3CoinDenomination {
    ZQ_LOVELACE = 1,
    ZQ_GOLDWASSER = 10,
    ZQ_RACKOFF = 25,
    ZQ_PEDERSEN = 50,
    ZQ_WILLIAMSON = 100 // Malcolm J. Williamson,
                    // the scientist who actually invented
                    // Public key cryptography
};

class V3PublicCoin{
public:
    template<typename Stream>
    V3PublicCoin(Stream& strm){
        strm >> *this;
    }

    V3PublicCoin();

    V3PublicCoin(const GroupElement& coin, const V3CoinDenomination d);

    const GroupElement& getValue() const;
    bool operator==(const V3PublicCoin& other) const;
    bool operator!=(const V3PublicCoin& other) const;
    bool validate() const;
    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size = value.memoryRequired();
        unsigned char buffer[size];
        value.serialize(buffer);
        char* b = (char*)buffer;
        s.write(b, size);
        s << denomination;
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = value.memoryRequired();
        unsigned char buffer[size];
        char* b = (char*)buffer;
        value.deserialize(buffer);
        s.read(b, size);
        s >> denomination;
    }

private:
    GroupElement value;
    int denomination;
};

class V3PrivateCoin{
public:
    template<typename Stream>
    V3PrivateCoin(const V3Params* p, Stream& strm): params(p), publicCoin() {
        strm >> *this;
    }

    V3PrivateCoin(const V3Params* p,V3CoinDenomination denomination = ZQ_LOVELACE, int version = ZEROCOIN_TX_VERSION_3);
    const V3PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(V3PublicCoin p);
    void setRandomness(Scalar n);
    void setSerialNumber(Scalar n);
    void setVersion(unsigned int nVersion);

private:
    const V3Params* params;
    V3PublicCoin publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;

    void mintCoin(const V3CoinDenomination denomination);
};

}// namespace sigma

#endif //ZCOIN_SIGMA_COIN_H
