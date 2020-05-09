#include "joinsplit.h"
#include "lelantus_prover.h"
#include "lelantus_verifier.h"
#include "../sigma/openssl_context.h"
#include "util.h"

namespace lelantus {

JoinSplit::JoinSplit(const Params *p,
             const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
             const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
             const Scalar& Vout,
             const std::vector<PrivateCoin>& Cout,
             const uint64_t& fee,
             const std::vector<uint256>& groupBlockHashes,
             const uint256& txHash)
        :
        params (p),
        fee (fee){

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

        groupIds.push_back(Cin[i].second);
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

bool JoinSplit::Verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<PublicCoin>& Cout,
        const Scalar& Vout,
        const uint256& txHash) const {
    std::vector<uint256> groupBlockHashes;
    groupBlockHashes.reserve(coinGroupIdAndBlockHash.size());

    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
        groupBlockHashes.emplace_back(idAndHash.second);
    }

    SpendMetaData m(anonymity_sets, groupBlockHashes, txHash);

    uint256 metahash = signatureHash(m, Cout.size());

    if(serialNumbers.size() != ecdsaSignatures.size() || serialNumbers.size() != ecdsaPubkeys.size()) {
        LogPrintf("Sigma spend failed due to serialNumbers and ecdsaSignatures/ecdsaPubkeys number mismatch.");
        return false;
    }

    for(size_t i = 0; i < serialNumbers.size(); i++) {
        // Verify ecdsa_signature, to make sure someone did not change the output of transaction.
        // Check sizes
        if (this->ecdsaPubkeys[i].size() != 33 || this->ecdsaSignatures[i].size() != 64) {
            LogPrintf("Lelantus joinsplit failed due to incorrect size of ecdsaSignature.");
            return false;
        }

        // Verify signature
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature signature;

        if (!secp256k1_ec_pubkey_parse(OpenSSLContext::get_context(), &pubkey, ecdsaPubkeys[i].data(), 33)) {
            LogPrintf("Lelantus joinsplit failed due to unable to parse ecdsaPubkey.");
            return false;
        }

        // Recompute and compare hash of public key
        Scalar coinSerialNumberExpected = PrivateCoin::serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);
        if (serialNumbers[i] != coinSerialNumberExpected) {
            LogPrintf("Lelantus joinsplit failed due to serial number does not match public key hash.");
            return false;
        }

        if (1 != secp256k1_ecdsa_signature_parse_compact(OpenSSLContext::get_context(), &signature, ecdsaSignatures[i].data()) ) {
            LogPrintf("Lelantus joinsplit failed due to signature cannot be parsed.");
            return false;
        }

        if (!secp256k1_ecdsa_verify(
                OpenSSLContext::get_context(), &signature, metahash.begin(), &pubkey)) {
            LogPrintf("Lelantus joinsplit failed due to signature cannot be verified.");
            return false;
        }
    }

    LelantusVerifier verifier(params);

    // Now verify lelantus proof
    return verifier.verify(anonymity_sets, serialNumbers, groupIds, uint64_t(0),Vout, fee, Cout, lelantusProof);
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

const std::vector<std::pair<uint32_t, uint256>>& JoinSplit::getIdAndBlockHashes() {
    return this->coinGroupIdAndBlockHash;
}

const std::vector<Scalar>& JoinSplit::getCoinSerialNumbers() {
    return this->serialNumbers;
}

const uint64_t& JoinSplit::getFee() {
    return this->fee;
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