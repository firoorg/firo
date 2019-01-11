#ifndef ZCOIN_SIGMA_COINSPEND_H
#define ZCOIN_SIGMA_COINSPEND_H

#include "Coin.h"
#include "SigmaPlusProof.h"
#include "SigmaPlusProver.h"
#include "SigmaPlusVerifier.h"

using namespace secp_primitives;
namespace sigma{

class CoinSpendV3 {
public:
    template<typename Stream>
    CoinSpendV3(const ParamsV3* p,  Stream& strm):
        params(p),
        denomination(ZQ_LOVELACE),
        sigmaProof(p) {

            strm >> * this;
        }


    CoinSpendV3(const ParamsV3* p,
              const PrivateCoinV3& coin,
              const std::vector<PublicCoinV3>& anonymity_set,
              uint256 _accumulatorBlockHash=uint256());

    const Scalar& getCoinSerialNumber();

    CoinDenominationV3 getDenomination() const;

    void setVersion(unsigned int nVersion){
        version = nVersion;
    }

    int getVersion() const {
        return version;
    }

    uint256 getAccumulatorBlockHash() const {
        return accumulatorBlockHash;
    }

    bool HasValidSerial() const;

    bool Verify(const std::vector<PublicCoinV3>& anonymity_set) const;

    size_t GetSerializeSize(int nType, int nVersion) const;

    template<typename Stream>
    inline void Serialize(Stream& s, int nType, int nVersion) const {
        int size = sigmaProof.memoryRequired() + coinSerialNumber.memoryRequired();
        unsigned char buffer[size + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256)];
        unsigned char* current = coinSerialNumber.serialize(buffer);
        current = sigmaProof.serialize(current);
        std::memcpy(current, &version, sizeof(version));
        std::memcpy(current + sizeof(uint32_t), &denomination, sizeof(denomination));
        std::memcpy(current + sizeof(uint32_t) + sizeof(int32_t), &accumulatorBlockHash, sizeof(accumulatorBlockHash));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s, int nType, int nVersion) {
        int size = sigmaProof.memoryRequired() + coinSerialNumber.memoryRequired();
        unsigned char buffer[size + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256)];
        char* b = (char*)buffer;
        s.read(b, size + + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256));
        unsigned char* current = coinSerialNumber.deserialize(buffer);
        current = sigmaProof.deserialize(current);
        std::memcpy(&version, current, sizeof(version));
        std::memcpy(&denomination, current + sizeof(uint32_t), sizeof(denomination));
        std::memcpy(&accumulatorBlockHash, current + sizeof(uint32_t) + sizeof(int32_t), sizeof(accumulatorBlockHash));
    }

private:
    const ParamsV3* params;
    unsigned int version = 0;
    int denomination;
    uint256 accumulatorBlockHash;
    Scalar coinSerialNumber;
    SigmaPlusProof<Scalar, GroupElement> sigmaProof;

};
}//namespace sigma
#endif //ZCOIN_SIGMA_COINSPEND_H
