#ifndef FIRO_LIBLELANTUS_COIN_H
#define FIRO_LIBLELANTUS_COIN_H

#include "params.h"
#include "../firo_params.h"
#include "../uint256.h"
#include "openssl_context.h"

// keep this just to not break old index
namespace sigma {
class PublicCoin {
public:
    PublicCoin() {}
    template<typename Stream>
    inline void Serialize(Stream& s) const {
        constexpr int size = GroupElement::memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        value.serialize(buffer);
        std::memcpy(buffer + size, &denomination, sizeof(denomination));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(int32_t));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        constexpr int size = GroupElement::memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        char* b = (char*)buffer;
        s.read(b, size + sizeof(int32_t));
        value.deserialize(buffer);
        std::memcpy(&denomination, buffer + size, sizeof(denomination));
    }

private:
    GroupElement value;
    std::uint8_t denomination;
};

struct CSpendCoinInfo {
    std::uint8_t denomination;
    int coinGroupId;

    template<typename Stream>
    void Serialize(Stream& s) const {
        int64_t tmp = uint8_t(denomination);
        s << tmp;
        tmp = coinGroupId;
        s << tmp;
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        int64_t tmp;
        s >> tmp; denomination = uint8_t(tmp);
        s >> tmp; coinGroupId = int(tmp);
    }

};
}

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
    inline void Serialize(Stream& s) const {
        std::vector<unsigned char> buffer(GetSerializeSize());
        value.serialize(buffer.data());
        s.write((const char *)buffer.data(), buffer.size());
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        std::vector<unsigned char> buffer(GetSerializeSize());
        s.read((char *)buffer.data(), buffer.size());
        value.deserialize(buffer.data());
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

#endif //FIRO_LIBLELANTUS_COIN_H
