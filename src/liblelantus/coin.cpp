#include "coin.h"
#include "primitives/zerocoin.h"

namespace lelantus {

//class PublicCoin
PublicCoin::PublicCoin() {
}

PublicCoin::PublicCoin(const GroupElement& coin):
    value(coin) {
}

const GroupElement& PublicCoin::getValue() const {
    return this->value;
}

uint256 PublicCoin::getValueHash() const {
    return primitives::GetPubCoinValueHash(value);
}

bool PublicCoin::operator==(const PublicCoin& other) const {
    return (*this).value == other.value;
}

bool PublicCoin::operator!=(const PublicCoin& other) const {
    return (*this).value != other.value;
}

bool PublicCoin::validate() const {
    return this->value.isMember() && !this->value.isInfinity();
}

size_t PublicCoin::GetSerializeSize(int nType, int nVersion) const {
    return value.memoryRequired();
}

//class PrivateCoin
PrivateCoin::PrivateCoin(const Params* p, const Scalar& v):
    params(p) {
        this->mintCoin(v);
}

PrivateCoin::PrivateCoin(const Params* p,const Scalar& serial, const Scalar& v, const Scalar& random, int version_) :
        params(p),
        serialNumber(serial),
        value(v),
        randomness(random),
        version(version_) {
    publicCoin = LelantusPrimitives<Scalar, GroupElement>::double_commit(
            params->get_g(), serialNumber, params->get_h0(), v, params->get_h1(), randomness);
}

const PublicCoin& PrivateCoin::getPublicCoin() const {
    return this->publicCoin;
}

const Scalar& PrivateCoin::getSerialNumber() const {
    return this->serialNumber;
}

const Scalar& PrivateCoin::getRandomness() const {
    return this->randomness;
}

const Scalar& PrivateCoin::getV() const {
    return this->value;
}

unsigned int PrivateCoin::getVersion() const {
    return this->version;
}

void PrivateCoin::setPublicCoin(const PublicCoin& p){
    publicCoin = p;
}

void PrivateCoin::setRandomness(const Scalar& n){
    randomness = n;
}

void PrivateCoin::setSerialNumber(const Scalar& n){
    serialNumber = n;
}

void PrivateCoin::setV(const Scalar& n){
    value = n;
}

void PrivateCoin::setVersion(unsigned int nVersion){
    version = nVersion;
}

void PrivateCoin::mintCoin(const Scalar& v){
    serialNumber.randomize();
    randomness.randomize();
    value = v;
    GroupElement commit = LelantusPrimitives<Scalar, GroupElement>::double_commit(
            params->get_g(), serialNumber, params->get_h0(), v, params->get_h1(), randomness);
    publicCoin = PublicCoin(commit);
}

}//namespace lelantus