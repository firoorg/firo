#ifndef ZCOIN_LIBLELANTUS_JOINSPLIT_H
#define ZCOIN_LIBLELANTUS_JOINSPLIT_H

#include "coin.h"
#include "lelantus_proof.h"

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
              const std::vector<std::vector<PublicCoin>>& anonymity_sets,
              const Scalar& Vout,
              const std::vector<PrivateCoin>& Cout,
              const Scalar& fee);

    void setVersion(unsigned int nVersion) {
        version = nVersion;
    }

    const std::vector<Scalar>& getCoinSerialNumbers();

    const std::vector<uint32_t>& getCoinGroupIds();

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
        READWRITE(version);
    }

private:
    const Params* params;
    unsigned int version = 0;
    LelantusProof lelantusProof;
    std::vector<Scalar> serialNumbers;
    std::vector<uint32_t> groupIds;

};

} //namespace lelantus

#endif //ZCOIN_LIBLELANTUS_JOINSPLIT_H
