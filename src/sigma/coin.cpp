#include "coin.h"
#include "util.h"
#include "amount.h"

#include <openssl/rand.h>
#include <sstream>
#include "openssl_context.h"

namespace sigma {

std::ostream& operator<<(std::ostream& stream, CoinDenominationV3 denomination) {
    int64_t denom_value;
    DenominationToInteger(denomination, denom_value);
    stream << denom_value;
    return stream;
}

bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out) {
    CValidationState dummy_state;
    return DenominationToInteger(denom, denom_out, dummy_state);
}

bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out, CValidationState &state) {
    // static const CAmount COIN = 100000000; in amount.h

    switch (denom) {
        default:
            return state.DoS(100, error("CheckZerocoinTransaction : invalid denomination value, unable to convert to integer"));
        case CoinDenominationV3::SIGMA_DENOM_0_1:
            denom_out = COIN / 10;
            break;
        case CoinDenominationV3::SIGMA_DENOM_0_5:
            denom_out = COIN / 2;
            break;
        case CoinDenominationV3::SIGMA_DENOM_1:
            denom_out = COIN;
            break;
        case CoinDenominationV3::SIGMA_DENOM_10:
            denom_out = 10 * COIN;
            break;
        case CoinDenominationV3::SIGMA_DENOM_100:
            denom_out = 100 * COIN;
            break;
    }
return true;
}

bool RealNumberToDenomination(const double& value, CoinDenominationV3& denom_out) {
    return IntegerToDenomination(value * COIN, denom_out);
}

bool StringToDenomination(const std::string& str, CoinDenominationV3& denom_out) {
    if (str == "0.1") {
        denom_out = CoinDenominationV3::SIGMA_DENOM_0_1;
        return true;
    }
    if (str == "0.5") {
        denom_out = CoinDenominationV3::SIGMA_DENOM_0_5;
        return true;
    }
    if (str == "1") {
        denom_out = CoinDenominationV3::SIGMA_DENOM_1;
        return true;
    }
    if (str == "10") {
        denom_out = CoinDenominationV3::SIGMA_DENOM_10;
        return true;
    }
    if (str == "100") {
        denom_out = CoinDenominationV3::SIGMA_DENOM_100;
        return true;
    }
    return false;
}

bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out) {
    CValidationState dummy_state;
    return IntegerToDenomination(value, denom_out, dummy_state);
}

bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out, CValidationState &state) {
    switch (value) {
        default:
            return state.DoS(100, error("CheckZerocoinTransaction : invalid denomination value, unable to convert to enum"));
        case COIN / 10:
            denom_out = CoinDenominationV3::SIGMA_DENOM_0_1;
            break;
        case COIN / 2:
            denom_out = CoinDenominationV3::SIGMA_DENOM_0_5;
            break;
        case 1 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_1;
            break;
        case 10 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_10;
            break;
        case 100 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_100;
            break;
    }
return true;
}

void GetAllDenoms(std::vector<sigma::CoinDenominationV3>& denominations_out) {
    denominations_out.push_back(CoinDenominationV3::SIGMA_DENOM_100);
    denominations_out.push_back(CoinDenominationV3::SIGMA_DENOM_10);
    denominations_out.push_back(CoinDenominationV3::SIGMA_DENOM_1);
    denominations_out.push_back(CoinDenominationV3::SIGMA_DENOM_0_5);
    denominations_out.push_back(CoinDenominationV3::SIGMA_DENOM_0_1);
}

//class PublicCoin
PublicCoinV3::PublicCoinV3()
    : denomination(CoinDenominationV3::SIGMA_DENOM_1)
{

}

PublicCoinV3::PublicCoinV3(const GroupElement& coin, const CoinDenominationV3 d)
    : value(coin)
    , denomination(d)
{
}

const GroupElement& PublicCoinV3::getValue() const{
    return this->value;
}

CoinDenominationV3 PublicCoinV3::getDenomination() const {
    return denomination;
}

bool PublicCoinV3::operator==(const PublicCoinV3& other) const{
    return (*this).value == other.value;
}

bool PublicCoinV3::operator!=(const PublicCoinV3& other) const{
    return (*this).value != other.value;
}

bool PublicCoinV3::validate() const{
    return this->value.isMember();
}

size_t PublicCoinV3::GetSerializeSize(int nType, int nVersion) const{
    return value.memoryRequired() + sizeof(int);
}

//class PrivateCoin
PrivateCoinV3::PrivateCoinV3(const ParamsV3* p, CoinDenominationV3 denomination, int version)
    : params(p)
{
        this->version = version;
        this->mintCoin(denomination);
}

const ParamsV3 * PrivateCoinV3::getParams() const {
    return this->params;
}

const PublicCoinV3& PrivateCoinV3::getPublicCoin() const{
    return this->publicCoin;
}

const Scalar& PrivateCoinV3::getSerialNumber() const{
    return this->serialNumber;
}

const Scalar& PrivateCoinV3::getRandomness() const{
    return this->randomness;
}

const unsigned char* PrivateCoinV3::getEcdsaSeckey() const {
     return this->ecdsaSeckey;
}

void PrivateCoinV3::setEcdsaSeckey(const std::vector<unsigned char> &seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.cbegin(), seckey.cend(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

void PrivateCoinV3::setEcdsaSeckey(uint256 &seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.begin(), seckey.end(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

unsigned int PrivateCoinV3::getVersion() const {
    return this->version;
}

void PrivateCoinV3::setPublicCoin(const PublicCoinV3& p) {
    publicCoin = p;
}

void PrivateCoinV3::setRandomness(const Scalar& n) {
    randomness = n;
}

void PrivateCoinV3::setSerialNumber(const Scalar& n) {
    serialNumber = n;
}

void PrivateCoinV3::setVersion(unsigned int nVersion){
    version = nVersion;
}

void PrivateCoinV3::mintCoin(const CoinDenominationV3 denomination){
    // Create a key pair
    secp256k1_pubkey pubkey;
    do {
        if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey)) != 1) {
            throw ZerocoinException("Unable to generate randomness");
        }
    } while (!secp256k1_ec_pubkey_create(
        OpenSSLContext::get_context(), &pubkey, this->ecdsaSeckey));

    // Hash the public key in the group to obtain a serial number
    serialNumber = serialNumberFromSerializedPublicKey(
        OpenSSLContext::get_context(), &pubkey);

    randomness.randomize();
    GroupElement commit = SigmaPrimitives<Scalar, GroupElement>::commit(
            params->get_g(), serialNumber, params->get_h0(), randomness);
    publicCoin = PublicCoinV3(commit, denomination);
}

Scalar PrivateCoinV3::serialNumberFromSerializedPublicKey(
        const secp256k1_context *context,
        secp256k1_pubkey *pubkey) {
    std::vector<unsigned char> pubkey_hash(32, 0);

    static const unsigned char one[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    if (1 != secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0])) {
        throw ZerocoinException("Unable to compute public key hash with secp256k1_ecdh.");
    }

	std::string zpts(ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER);
	std::vector<unsigned char> pre(zpts.begin(), zpts.end());
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), std::back_inserter(pre));

	unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pre.data(), pre.size()).Finalize(hash);

    // Use 32 bytes of hash as coin serial.
    return Scalar(hash);
}

} // namespace sigma

namespace std {

string to_string(::sigma::CoinDenominationV3 denom)
{
    switch (denom) {
    case ::sigma::CoinDenominationV3::SIGMA_DENOM_0_1:
        return "0.1";
    case ::sigma::CoinDenominationV3::SIGMA_DENOM_0_5:
        return "0.5";
    case ::sigma::CoinDenominationV3::SIGMA_DENOM_1:
        return "1";
    case ::sigma::CoinDenominationV3::SIGMA_DENOM_10:
        return "10";
    case ::sigma::CoinDenominationV3::SIGMA_DENOM_100:
        return "100";
    default:
        throw invalid_argument("the specified denomination is not valid");
    }
}

} // namespace std
