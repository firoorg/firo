#include "Coin.h"
namespace sigma{

//class PublicCoin
PublicCoinV3::PublicCoinV3()
    : denomination(ZQ_LOVELACE) 
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

}//namespace sigma
