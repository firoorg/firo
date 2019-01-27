#include "Coin.h"
#include "util.h"
#include "amount.h"

#include <sstream>

namespace sigma {

bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out) {
    CValidationState dummy_state;
    return DenominationToInteger(denom, denom_out, dummy_state);
}

bool DenominationToInteger(CoinDenominationV3 denom, int64_t& denom_out, CValidationState &state) {
    // static const CAmount COIN = 100000000; in amount.h

    switch (denom) {
        default:
            return state.DoS(100, error("CheckZerocoinTransaction : invalid denomination value, unable to convert to integer"));
        case CoinDenominationV3::SIGMA_DENOM_1 :
            denom_out = 1 * COIN;
            break;
        case CoinDenominationV3::SIGMA_DENOM_10:
            denom_out = 10 * COIN;
            break;
        case CoinDenominationV3::SIGMA_DENOM_25:
            denom_out = 25 * COIN;
            break;
        case CoinDenominationV3::SIGMA_DENOM_50:
            denom_out = 50 * COIN;
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
    std::istringstream iss(str);
    int64_t denom_number;
    iss >> denom_number;
    return IntegerToDenomination(denom_number * COIN, denom_out);
}

bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out) {
    CValidationState dummy_state;
    return IntegerToDenomination(value, denom_out, dummy_state);
}

bool IntegerToDenomination(int64_t value, CoinDenominationV3& denom_out, CValidationState &state) {
    switch (value) {
        default:
            return state.DoS(100, error("CheckZerocoinTransaction : invalid denomination value, unable to convert to enum"));
        case 1 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_1 ;
            break;
        case 10 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_10;
            break;
        case 25 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_25;
            break;
        case 50 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_50;
            break;
        case 100 * COIN:
            denom_out = CoinDenominationV3::SIGMA_DENOM_100;
            break;
    }
return true;
}

//class PublicCoin
PublicCoinV3::PublicCoinV3()
    : denomination(SIGMA_DENOM_1 ) 
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
    return static_cast<CoinDenominationV3>(this->denomination);
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
PrivateCoinV3::PrivateCoinV3(const ParamsV3* p,CoinDenominationV3 denomination, int version):
    params(p) {
        this->version = version;
        this->mintCoin(denomination);
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

unsigned int PrivateCoinV3::getVersion() const{
    return this->version;
}

void PrivateCoinV3::setPublicCoin(PublicCoinV3 p){
    publicCoin = p;
}

void PrivateCoinV3::setRandomness(Scalar n){
    randomness = n;
}

void PrivateCoinV3::setSerialNumber(Scalar n){
    serialNumber = n;
}

void PrivateCoinV3::setVersion(unsigned int nVersion){
    version = nVersion;
}

void PrivateCoinV3::mintCoin(const CoinDenominationV3 denomination){
    serialNumber.randomize();
    randomness.randomize();
    GroupElement commit = SigmaPrimitives<Scalar, GroupElement>::commit(
            params->get_g(), serialNumber, params->get_h0(), randomness);
    publicCoin = PublicCoinV3(commit, denomination);
}

} // namespace sigma
