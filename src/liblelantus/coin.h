#ifndef ZCOIN_LIBLELANTUS_COIN_H
#define ZCOIN_LIBLELANTUS_COIN_H

#include "lelantus_primitives.h"
#include "params.h"
#include "../sigma/openssl_context.h"


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
    size_t GetSerializeSize() const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size =  GetSerializeSize();
        unsigned char buffer[size];
        value.serialize(buffer);
        char* b = (char*)buffer;
        s.write(b, size);
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size =  GetSerializeSize();
        unsigned char buffer[size];
        char* b = (char*)buffer;
        s.read(b, size);
        value.deserialize(buffer);
    }

private:
    GroupElement value;
};

class PrivateCoin {
public:

    PrivateCoin(const Params* p, uint64_t v);
    PrivateCoin(const Params* p,
            const Scalar& serial,
            uint64_t v,
            const Scalar& random,
            const std::vector<unsigned char>& seckey,
            int version_);

    const Params * getParams() const;
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    uint64_t getV() const;
    Scalar getVScalar() const;
    unsigned int getVersion() const;
    void setPublicCoin(const PublicCoin& p);
    void setRandomness(const Scalar& n);
    void setSerialNumber(const Scalar& n);
    void setV(uint64_t n);
    void setVersion(unsigned int nVersion);
    const unsigned char* getEcdsaSeckey() const;

    void setEcdsaSeckey(const std::vector<unsigned char> &seckey);
    void setEcdsaSeckey(const uint256& seckey);

    static Scalar serialNumberFromSerializedPublicKey(
            const secp256k1_context *context,
            secp256k1_pubkey *pubkey);

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar serialNumber;
    uint64_t value;
    Scalar randomness;
    unsigned int version = 0;
    unsigned char ecdsaSeckey[32];

private:
    void randomize();
    void mintCoin(uint64_t v);
};

}// namespace lelantus

#endif //ZCOIN_LIBLELANTUS_COIN_H
