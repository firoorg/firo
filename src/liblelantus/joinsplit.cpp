#include "joinsplit.h"
#include "lelantus_prover.h"
#include "lelantus_verifier.h"
#include "../sigma/openssl_context.h"

namespace lelantus {

JoinSplit::JoinSplit(const Params *p,
             const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
             const std::unordered_map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
             const Scalar& Vout,
             const std::vector<PrivateCoin>& Cout,
             const Scalar& fee,
             const std::vector<uint256>& groupBlockHashes,
             const uint256& txHash)
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
        const auto& set = anonymity_sets.find(Cin[i].second);
        if(set == anonymity_sets.end())
            throw ZerocoinException("No such anonymity set");

        if(!getIndex(Cin[i].first.getPublicCoin(), set->second, index))
            throw ZerocoinException("No such coin in this anonymity set");
        indexes.emplace_back(index);
    }

    LelantusProver prover(p);

    prover.proof(anonymity_sets, uint64_t(0), Cin, indexes, Vout, Cout, fee, lelantusProof);

    SpendMetaData m(anonymity_sets, groupBlockHashes, txHash);

    updateMetaData(Cin, m, Cout.size());

    coinGroupIdAndBlockHash = m.coinGroupIdAndBlockHash;
}

void JoinSplit::updateMetaData(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin, const SpendMetaData& m, size_t coutSize) {
    // Proves that the coin is correct w.r.t. serial number and hidden coin secret
    // (This proof is bound to the coin 'metadata', i.e., transaction hash)
    uint256 metahash = signatureHash(m, coutSize);


    ecdsaSignatures.resize(Cin.size());
    ecdsaPubkeys.resize(Cin.size());
    int i = 0;
    for(auto& coin : Cin) {
        // Sign each spend under the public key associate with the serial number.
        secp256k1_pubkey pubkey;
        size_t len = 33;
        secp256k1_ecdsa_signature sig;

        ecdsaSignatures[i].resize(64);
        ecdsaPubkeys[i].resize(33);

        // TODO timing channel, since secp256k1_ec_pubkey_serialize does not expect its output to be secret.
        // See main_impl.h of ecdh module on secp256k1
        if (!secp256k1_ec_pubkey_create(
                OpenSSLContext::get_context(), &pubkey, coin.first.getEcdsaSeckey())) {
            throw ZerocoinException("Invalid secret key");
        }
        if (1 != secp256k1_ec_pubkey_serialize(
                OpenSSLContext::get_context(),
                &this->ecdsaPubkeys[i][0], &len, &pubkey, SECP256K1_EC_COMPRESSED)) {
            throw ZerocoinException("Unable to serialize public key");
        }

        if (1 != secp256k1_ecdsa_sign(
                OpenSSLContext::get_context(), &sig,
                metahash.begin(), coin.first.getEcdsaSeckey(), NULL, NULL)) {
            throw ZerocoinException("Unable to sign with EcdsaSeckey.");
        }
        if (1 != secp256k1_ecdsa_signature_serialize_compact(
                OpenSSLContext::get_context(), &this->ecdsaSignatures[i][0], &sig)) {
            throw ZerocoinException("Unable to serialize ecdsa_signature.");
        }

        i++;
    }

}

uint256 JoinSplit::signatureHash(const SpendMetaData& m, size_t coutSize) const {
    CHashWriter h(0,0);
    std::vector<unsigned char> buffer;
    buffer.resize(lelantusProof.memoryRequired(serialNumbers.size(), params->get_bulletproofs_n(), coutSize));
    lelantusProof.serialize(&buffer[0]);
    h << m << buffer;
    return h.GetHash();
}

const std::vector<uint32_t>& JoinSplit::getCoinGroupIds() {
    return this->groupIds;
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