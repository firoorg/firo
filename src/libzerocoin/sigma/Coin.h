#ifndef ZCOIN_SIGMA_COIN_H
#define ZCOIN_SIGMA_COIN_H

#include "SigmaPrimitives.h"
#include <libzerocoin/Zerocoin.h>
#include "Params.h"

namespace sigma {

enum CoinDenominationV3 {
    ZQ_LOVELACE = 1,
    ZQ_GOLDWASSER = 10,
    ZQ_RACKOFF = 25,
    ZQ_PEDERSEN = 50,
    ZQ_WILLIAMSON = 100
};

class PublicCoinV3 {
public:
    // Better just use it as is, with "operator>>".
    //template<typename Stream>
    //PublicCoinV3(Stream& strm) {
    //    strm >> *this;
    //}

    PublicCoinV3();

    PublicCoinV3(const GroupElement& coin, const CoinDenominationV3 d);

    const GroupElement& getValue() const;
    CoinDenominationV3 getDenomination() const;

    bool operator==(const PublicCoinV3& other) const;
    bool operator!=(const PublicCoinV3& other) const;
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
        s.read(b, size);
        value.deserialize(buffer);
        s >> denomination;
    }

// private: TODO: change back to private
    GroupElement value;
    int denomination;
};

class PrivateCoinV3{
public:
    template<typename Stream>
    PrivateCoinV3(const ParamsV3* p, Stream& strm): params(p), publicCoin() {
        strm >> *this;
    }

    PrivateCoinV3(const ParamsV3* p,CoinDenominationV3 denomination = ZQ_LOVELACE, int version = ZEROCOIN_TX_VERSION_3);
    const PublicCoinV3& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(PublicCoinV3 p);
    void setRandomness(Scalar n);
    void setSerialNumber(Scalar n);
    void setVersion(unsigned int nVersion);

private:
    const ParamsV3* params;
    PublicCoinV3 publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;

    void mintCoin(const CoinDenominationV3 denomination);
};

}// namespace sigma

#endif //ZCOIN_SIGMA_COIN_H
