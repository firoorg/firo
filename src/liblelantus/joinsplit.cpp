#include "joinsplit.h"
#include "lelantus_prover.h"
#include "lelantus_verifier.h"

namespace lelantus {

JoinSplit::JoinSplit(const Params *p,
             const std::vector<std::pair<PrivateCoin, uint32_t>> &Cin,
             const std::vector<std::vector<PublicCoin>> &anonymity_sets,
             const Scalar &Vout,
             const std::vector<PrivateCoin> &Cout,
             const Scalar &fee)
        :
        params(p) {

    serialNumbers.reserve(Cin.size());
    for(size_t i = 0; i < Cin.size(); i++) {
        serialNumbers.emplace_back(Cin[i].first.getSerialNumber());
    }

    if (!HasValidSerials()) {
        throw ZerocoinException("JoinSplit has invalid serial number");
    }

    std::vector <size_t> indexes;
    for(size_t i = 0; i < Cin.size(); i++) {
        uint64_t index;
        if(!getIndex(Cin[i].first.getPublicCoin(), anonymity_sets[Cin[i].second], index))
            throw ZerocoinException("No such coin in this anonymity set");
        indexes.emplace_back(index);
    }

    LelantusProver prover(p);

    prover.proof(anonymity_sets, uint64_t(0), Cin, indexes, Vout, Cout, fee, lelantusProof);

    //TODO(levon) implement signing

}


const std::vector<Scalar>& JoinSplit::getCoinSerialNumbers() {
    return this->serialNumbers;
}

bool JoinSplit::getIndex(const PublicCoin& coin, const std::vector<PublicCoin>& anonymity_set, uint64_t& index) {
    for (std::size_t j = 0; j < anonymity_set.size(); ++j) {
        if(anonymity_set[j] == coin){
            index = j;
            return true;
        }
    }
    return false;
}

bool JoinSplit::HasValidSerials() const {
    for(size_t i = 0; i < serialNumbers.size(); i++)
        if(!serialNumbers[i].isMember() || serialNumbers[i].isZero())
            return false;
    return true;
}

} //namespace lelantus