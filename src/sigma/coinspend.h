#ifndef ZCOIN_SIGMA_COINSPEND_H
#define ZCOIN_SIGMA_COINSPEND_H

#include "coin.h"
#include "sigmaplusproof.h"
#include "sigmaplusprover.h"
#include "sigmaplusverifier.h"
#include "spendmetadatav3.h"

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
