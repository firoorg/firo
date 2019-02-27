#ifndef ZCOIN_SIGMA_COINSPEND_H
#define ZCOIN_SIGMA_COINSPEND_H

#include "Coin.h"
#include "SigmaPlusProof.h"
#include "SigmaPlusProver.h"
#include "SigmaPlusVerifier.h"
#include "SpendMetaDataV3.h"

using namespace secp_primitives;

namespace sigma {

class CoinSpendV3 {
public:
    template<typename Stream>
    CoinSpendV3(const ParamsV3* p,  Stream& strm):
        params(p),
        denomination(CoinDenominationV3::SIGMA_DENOM_1),
        sigmaProof(p) {
            strm >> * this;
        }


    CoinSpendV3(const ParamsV3* p,
              const PrivateCoinV3& coin,
              const std::vector<PublicCoinV3>& anonymity_set,
              const SpendMetaDataV3& m);

    const Scalar& getCoinSerialNumber();

    CoinDenominationV3 getDenomination() const;

    int64_t getIntDenomination() const;

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

    bool Verify(const std::vector<PublicCoinV3>& anonymity_set, const SpendMetaDataV3 &m) const;

    // size_t GetSerializeSize(int nType, int nVersion) const;

/*
    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const {
        int size = sigmaProof.memoryRequired() + coinSerialNumber.memoryRequired();
        std::vector<unsigned char> buffer;
        buffer.resize(size + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256));

        unsigned char* current = coinSerialNumber.serialize(buffer);
        current = sigmaProof.serialize(current);
        std::memcpy(current, &version, sizeof(version));
        std::memcpy(current + sizeof(uint32_t), &denomination, sizeof(denomination));
        std::memcpy(current + sizeof(uint32_t) + sizeof(int32_t), &accumulatorBlockHash, sizeof(accumulatorBlockHash));
        char* b = (char*)buffer;

        // Write size of ecdsaPubkey followed by ecdsaPubkey itself,
        uint32_t size_of_ecdsaPubkey = ecdsaPubkey.size();
        uint32_t size_of_b = b.size();
        b.resize(size_of_b + sizeof(size_of_ecdsaPubkey));
        std::memcpy(&b[size_of_b], &size_of_ecdsaPubkey, sizeof(size_of_ecdsaPubkey));
        b.insert(b.end(), ecdsaPubkey.begin(), ecdsaPubkey.end());

        // Write size of ecdsaSignature, followed by ecdsaSignature itself.
        uint32_t size_of_ecdsaSignature = ecdsaSignature.size();
        size_of_b = b.size();
        b.resize(size_of_b + sizeof(size_of_ecdsaSignature));
        std::memcpy(&b[size_of_b], &size_of_ecdsaSignature, sizeof(size_of_ecdsaSignature));
        b.insert(b.end(), size_of_ecdsaSignature.begin(), size_of_ecdsaSignature.end());

        s.write(&b[0], b.size());
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion) {
        int size = sigmaProof.memoryRequired() + coinSerialNumber.memoryRequired();
        std::vector<unsigned char> buffer;
        buffer.resize(size + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256));

        char* b = (char*)buffer;
        s.read(b, size + + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint256));
        unsigned char* current = coinSerialNumber.deserialize(buffer);
        current = sigmaProof.deserialize(current);
        std::memcpy(&version, current, sizeof(version));
        std::memcpy(&denomination, current + sizeof(uint32_t), sizeof(denomination));
        std::memcpy(&accumulatorBlockHash, current + sizeof(uint32_t) + sizeof(int32_t), sizeof(accumulatorBlockHash));

        // Read size of ecdsaPubkey followed by ecdsaPubkey itself,
        uint32_t size_of_ecdsaPubkey = ecdsaPubkey.size();
        uint32_t size_of_b = b.size();
        b.resize(size_of_b + sizeof(size_of_ecdsaPubkey));
        std::memcpy(&b[size_of_b], &size_of_ecdsaPubkey, sizeof(size_of_ecdsaPubkey));
        b.insert(b.end(), ecdsaPubkey.begin(), ecdsaPubkey.end());

        // Read size of ecdsaSignature, followed by ecdsaSignature itself.
        uint32_t size_of_ecdsaSignature = ecdsaSignature.size();
        size_of_b = b.size();
        b.resize(size_of_b + sizeof(size_of_ecdsaSignature));
        std::memcpy(&b[size_of_b], &size_of_ecdsaSignature, sizeof(size_of_ecdsaSignature));
        b.insert(b.end(), size_of_ecdsaSignature.begin(), size_of_ecdsaSignature.end());
    }
*/

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(sigmaProof);
        READWRITE(coinSerialNumber);
        READWRITE(version);

        int64_t denomination_value;
        if (ser_action.ForRead()) {
            READWRITE(denomination_value);
            IntegerToDenomination(denomination_value, this->denomination);
        } else {
            DenominationToInteger(this->denomination, denomination_value);
            READWRITE(denomination_value);
        }
        READWRITE(accumulatorBlockHash);
        READWRITE(ecdsaPubkey);
        READWRITE(ecdsaSignature);
    }
    
    uint256 signatureHash(const SpendMetaDataV3& m) const;

private:
    const ParamsV3* params;
    unsigned int version = 0;
    CoinDenominationV3 denomination;
    uint256 accumulatorBlockHash;
    Scalar coinSerialNumber;
    std::vector<unsigned char> ecdsaSignature;
    std::vector<unsigned char> ecdsaPubkey;
    SigmaPlusProof<Scalar, GroupElement> sigmaProof;

};
}//namespace sigma
#endif //ZCOIN_SIGMA_COINSPEND_H
