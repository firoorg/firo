#include "Coin.h"
namespace sigma{

//class PublicCoin
V3PublicCoin::V3PublicCoin(): denomination(ZQ_LOVELACE) {
}

V3PublicCoin::V3PublicCoin(const GroupElement& coin, const V3CoinDenomination d):
    value(coin), denomination(d) {
}

const GroupElement& V3PublicCoin::getValue() const{
    return this->value;
}

bool V3PublicCoin::operator==(const V3PublicCoin& other) const{
    return (*this).value == other.value;
}

bool V3PublicCoin::operator!=(const V3PublicCoin& other) const{
    return (*this).value != other.value;
}

bool V3PublicCoin::validate() const{
    return this->value.isMember();
}

size_t V3PublicCoin::GetSerializeSize(int nType, int nVersion) const{
    return value.memoryRequired() + sizeof(int);
}

//class PrivateCoin
V3PrivateCoin::V3PrivateCoin(const V3Params* p,V3CoinDenomination denomination, int version):
    params(p) {
        this->version = version;
        this->mintCoin(denomination);
}

const V3PublicCoin& V3PrivateCoin::getPublicCoin() const{
    return this->publicCoin;
}

const Scalar& V3PrivateCoin::getSerialNumber() const{
    return this->serialNumber;
}

const Scalar& V3PrivateCoin::getRandomness() const{
    return this->randomness;
}

unsigned int V3PrivateCoin::getVersion() const{
    return this->version;
}

void V3PrivateCoin::setPublicCoin(V3PublicCoin p){
    publicCoin = p;
}

void V3PrivateCoin::setRandomness(Scalar n){
    randomness = n;
}

void V3PrivateCoin::setSerialNumber(Scalar n){
    serialNumber = n;
}

void V3PrivateCoin::setVersion(unsigned int nVersion){
    version = nVersion;
}

void V3PrivateCoin::mintCoin(const V3CoinDenomination denomination){
    serialNumber.randomize();
    randomness.randomize();
    GroupElement commit = SigmaPrimitives<Scalar, GroupElement>::commit(
            params->get_g(), serialNumber, params->get_h0(), randomness);
    publicCoin = V3PublicCoin(commit, denomination);
}

}//namespace sigma