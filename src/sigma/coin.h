#ifndef ZCOIN_SIGMA_COIN_H
#define ZCOIN_SIGMA_COIN_H

#include "params.h"
#include "sigma_primitives.h"

#include "../consensus/validation.h"
#include "../libzerocoin/Zerocoin.h"

#include <cinttypes>

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

// for LogPrintf.
std::ostream& operator<<(std::ostream& stream, CoinDenomination denomination);

// Functions to convert denominations to/from an integer value.
bool DenominationToInteger(CoinDenomination denom, int64_t& denom_out, CValidationState &state);
bool IntegerToDenomination(int64_t value, CoinDenomination& denom_out, CValidationState &state);
bool DenominationToInteger(CoinDenomination denom, int64_t& denom_out);
bool IntegerToDenomination(int64_t value, CoinDenomination& denom_out);
bool StringToDenomination(const std::string& str, CoinDenomination& denom_out);
std::string DenominationToString(const CoinDenomination& denom);
bool RealNumberToDenomination(const double& value, CoinDenomination& denom_out);

/// \brief Returns a list of all possible denominations in descending order of value.
void GetAllDenoms(std::vector<sigma::CoinDenomination>& denominations_out);

class PublicCoin {
public:
    PublicCoin();

    PublicCoin(const GroupElement& coin, const CoinDenomination d);

    const GroupElement& getValue() const;
    CoinDenomination getDenomination() const;
    uint256 const & getValueHash() const;

    bool operator==(const PublicCoin& other) const;
    bool operator!=(const PublicCoin& other) const;
    bool validate() const;
    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s) const {
        int size = value.memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        value.serialize(buffer);
        std::memcpy(buffer + size, &denomination, sizeof(denomination));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(int32_t));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        int size = value.memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        char* b = (char*)buffer;
        s.read(b, size + sizeof(int32_t));
        value.deserialize(buffer);
        std::memcpy(&denomination, buffer + size, sizeof(denomination));
    }

private:
    GroupElement value;
    CoinDenomination denomination;
    mutable uint256 valueHash;
};

class PrivateCoin {
public:
    template<typename Stream>
    PrivateCoin(const Params* p, Stream& strm): params(p), publicCoin() {
        strm >> *this;
    }

    PrivateCoin(const Params* p,
        CoinDenomination denomination,
        int version = ZEROCOIN_TX_VERSION_3);

    const Params * getParams() const;
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(const PublicCoin& p);
    void setRandomness(const Scalar& n);
    void setSerialNumber(const Scalar& n);
    void setVersion(unsigned int nVersion);
    const unsigned char* getEcdsaSeckey() const;

    void setEcdsaSeckey(const std::vector<unsigned char> &seckey);
    void setEcdsaSeckey(uint256 &seckey);

    static Scalar serialNumberFromSerializedPublicKey(
        const secp256k1_context *context,
        secp256k1_pubkey *pubkey);

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;
    unsigned char ecdsaSeckey[32];

    void mintCoin(const CoinDenomination denomination);

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

}// namespace sigma

namespace std {

string to_string(::sigma::CoinDenomination denom);

template<> struct hash<sigma::CoinDenomination> {
    std::size_t operator()(const sigma::CoinDenomination &f) const {
        return std::hash<int>{}(static_cast<int>(f));
    }
};

}// namespace std

#endif // ZCOIN_SIGMA_COIN_H
