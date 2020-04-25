#ifndef ZCOIN_LIBLELANTUS_JOINSPLIT_H
#define ZCOIN_LIBLELANTUS_JOINSPLIT_H

#include "coin.h"
#include "lelantus_proof.h"
#include "spend_metadata.h"

namespace lelantus {

class JoinSplit {
public:
    template<typename Stream>
    JoinSplit(const Params* p,  Stream& strm):
            params(p) {
        strm >> *this;
    }

    JoinSplit(const Params* p,
              const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
              const std::unordered_map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
              const Scalar& Vout,
              const std::vector<PrivateCoin>& Cout,
              const Scalar& fee,
              const std::vector<uint256>& groupBlockHashs,
              const uint256& txHash);

    bool Verify(const std::unordered_map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
                const std::vector<PublicCoin>& Cout,
                const Scalar& Vout,
                const Scalar& fee,
                const uint256& txHash) const;

    void updateMetaData(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin, const SpendMetaData& m, size_t coutSize);

    uint256 signatureHash(const SpendMetaData& m, size_t coutSize) const;

    void setVersion(unsigned int nVersion) {
        version = nVersion;
    }

    const std::vector<Scalar>& getCoinSerialNumbers();

    const std::vector<uint32_t>& getCoinGroupIds();

    const std::vector<std::pair<uint32_t, uint256>>& getIdAndBlockHashes();

    int getVersion() const {
        return version;
    }

    bool getIndex(const PublicCoin& coin, const std::vector<PublicCoin>& anonymity_set, size_t& index);

    bool HasValidSerials() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(lelantusProof);
        READWRITE(serialNumbers);
        READWRITE(groupIds);
        READWRITE(ecdsaSignatures);
        READWRITE(ecdsaPubkeys);
        READWRITE(coinGroupIdAndBlockHash);
        READWRITE(version);
    }

private:
    const Params* params;
    unsigned int version = 0;
    LelantusProof lelantusProof;
    std::vector<Scalar> serialNumbers;
    std::vector<uint32_t> groupIds;
    std::vector<std::vector<unsigned char>> ecdsaSignatures;
    std::vector<std::vector<unsigned char>> ecdsaPubkeys;
    std::vector<std::pair<uint32_t, uint256>> coinGroupIdAndBlockHash;

};

} //namespace lelantus

#endif //ZCOIN_LIBLELANTUS_JOINSPLIT_H
