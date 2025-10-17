#ifndef FIRO_LIBLELANTUS_COIN_H
#define FIRO_LIBLELANTUS_COIN_H

#include "params.h"
#include "../firo_params.h"
#include "../uint256.h"
#include "openssl_context.h"
#include "crypto/sha256.h"

// keep this just to not break old index
namespace sigma {
enum class CoinDenomination : std::uint8_t {
    SIGMA_DENOM_0_05 = 5,
    SIGMA_DENOM_0_1 = 0,
    SIGMA_DENOM_0_5 = 1,
    SIGMA_DENOM_1 = 2,
    SIGMA_DENOM_10 = 3,
    SIGMA_DENOM_25 = 6,
    SIGMA_DENOM_100 = 4
};
// Serialization support for CoinDenomination

template<typename Stream>
void Serialize(Stream& os, CoinDenomination d)
{
    Serialize(os, static_cast<std::uint8_t>(d));
}

template<typename Stream>
void Unserialize(Stream& is, CoinDenomination& d)
{
    std::uint8_t v;
    Unserialize(is, v);
    d = static_cast<CoinDenomination>(v);
}

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
    CoinDenomination denomination;
};

struct CSpendCoinInfo {
    CoinDenomination denomination;
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
        s >> tmp; denomination = CoinDenomination(tmp);
        s >> tmp; coinGroupId = int(tmp);
    }

};

struct CScalarHash {
    std::size_t operator ()(const Scalar& bn) const noexcept {
        std::vector<unsigned char> bnData(bn.memoryRequired());
        bn.serialize(&bnData[0]);
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(&bnData[0], bnData.size()).Finalize(hash);
        // take the first bytes of "hash".
        std::size_t result;
        std::memcpy(&result, hash, sizeof(std::size_t));
        return result;
    }
};

using spend_info_container = std::unordered_map<Scalar, CSpendCoinInfo, CScalarHash>;

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
