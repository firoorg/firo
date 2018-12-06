#include "Coin.h"
namespace nextgen {

//class PublicCoin
PublicCoin::PublicCoin() {
}

PublicCoin::PublicCoin(const GroupElement& coin, const Scalar& v):
    value(coin), v(v) {
}

const GroupElement& PublicCoin::getValue() const{
    return this->value;
}

const Scalar& PublicCoin::get_v() const {
    return this->v;
}

bool PublicCoin::operator==(const PublicCoin& other) const{
    return (*this).value == other.value;
}

bool PublicCoin::operator!=(const PublicCoin& other) const{
    return (*this).value != other.value;
}

bool PublicCoin::validate() const{
    return this->value.isMember();
}

size_t PublicCoin::GetSerializeSize(int nType, int nVersion) const{
    return value.memoryRequired() + v.memoryRequired();
}

//class PrivateCoin
PrivateCoin::PrivateCoin(const Params* p, const Scalar& v):
    params(p) {
        this->mintCoin(v);
}

const PublicCoin& PrivateCoin::getPublicCoin() const{
    return this->publicCoin;
}

const Scalar& PrivateCoin::getSerialNumber() const{
    return this->serialNumber;
}

const Scalar& PrivateCoin::getRandomness() const{
    return this->randomness;
}

unsigned int PrivateCoin::getVersion() const{
    return this->version;
}

void PrivateCoin::setPublicCoin(PublicCoin p){
    publicCoin = p;
}

void PrivateCoin::setRandomness(Scalar n){
    randomness = n;
}

void PrivateCoin::setSerialNumber(Scalar n){
    serialNumber = n;
}

void PrivateCoin::setVersion(unsigned int nVersion){
    version = nVersion;
}

void PrivateCoin::mintCoin(const Scalar& v){
    serialNumber.randomize();
    randomness.randomize();
    GroupElement commit = NextGenPrimitives<Scalar, GroupElement>::double_commit(
            params->get_g(), serialNumber, params->get_h0(), v, params->get_h1(), randomness);
    publicCoin = PublicCoin(commit, v);
}

size_t PrivateCoin::GetSerializeSize(int nType, int nVersion) const{
    return publicCoin.GetSerializeSize(nType, nVersion) + randomness.memoryRequired()*2 +  sizeof(unsigned int);
}

}//namespace nextgen