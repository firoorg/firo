#ifndef ZCOIN_SIGMA_COIN_H
#define ZCOIN_SIGMA_COIN_H

#include "params.h"
#include "sigma_primitives.h"

#include "../consensus/validation.h"
#include "../libzerocoin/Zerocoin.h"

#include <cinttypes>

namespace sigma {


enum class CoinDenominationV3 : std::uint8_t {
    SIGMA_DENOM_0_1 = 0,
    SIGMA_DENOM_0_5 = 1,
    SIGMA_DENOM_1 = 2,
    SIGMA_DENOM_10 = 3,
    SIGMA_DENOM_100 = 4,
    SIGMA_ERROR = 5
};

// for LogPrintf.
std::ostream& operator<<(std::ostream& stream, CoinDenominationV3 denomination);

// Functions to convert denominations to/from an integer value.
bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out, CValidationState &state);
bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out, CValidationState &state);
bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out);
bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out);
bool StringToDenomination(const std::string& str, CoinDenominationV3& denom_out);
bool RealNumberToDenomination(const double& value, CoinDenominationV3& denom_out);

/// \brief Returns a list of all possible denominations in descending order of value.
void GetAllDenoms(std::vector<sigma::CoinDenominationV3>& denominations_out);

class PublicCoinV3 {
public:
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
        unsigned char buffer[size + sizeof(int32_t)];
        value.serialize(buffer);
        std::memcpy(buffer + size, &denomination, sizeof(denomination));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(int32_t));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = value.memoryRequired();
        unsigned char buffer[size + sizeof(int32_t)];
        char* b = (char*)buffer;
        s.read(b, size + sizeof(int32_t));
        value.deserialize(buffer);
        std::memcpy(&denomination, buffer + size, sizeof(denomination));
    }

// private: TODO(martun): change back to private
    GroupElement value;
    CoinDenominationV3 denomination;
};

class PrivateCoinV3 {
public:
    template<typename Stream>
    PrivateCoinV3(const ParamsV3* p, Stream& strm): params(p), publicCoin() {
        strm >> *this;
    }

    PrivateCoinV3(const ParamsV3* p,
        CoinDenominationV3 denomination,
        int version = ZEROCOIN_TX_VERSION_3);

    const ParamsV3 * getParams() const;
    const PublicCoinV3& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(const PublicCoinV3& p);
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
    const ParamsV3* params;
    PublicCoinV3 publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;
    unsigned char ecdsaSeckey[32];

    void mintCoin(const CoinDenominationV3 denomination);

};


// Serialization support for CoinDenominationV3

inline unsigned int GetSerializeSize(CoinDenominationV3 d, int nType, int nVersion)
{
    return sizeof(d);
}

template<typename Stream>
void Serialize(Stream& os, CoinDenominationV3 d, int nType, int nVersion)
{
    Serialize(os, static_cast<std::uint8_t>(d), nType, nVersion);
}

template<typename Stream>
void Unserialize(Stream& is, CoinDenominationV3& d, int nType, int nVersion)
{
    std::uint8_t v;
    Unserialize(is, v, nType, nVersion);
    d = static_cast<CoinDenominationV3>(v);
}

}// namespace sigma

namespace std {

string to_string(::sigma::CoinDenominationV3 denom);

template<> struct hash<sigma::CoinDenominationV3> {
    std::size_t operator()(const sigma::CoinDenominationV3 &f) const {
        return std::hash<int>{}(static_cast<int>(f));
    }
};

}// namespace std

#endif // ZCOIN_SIGMA_COIN_H
