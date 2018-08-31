/**
 * @file       CoinSpend.cpp
 *
 * @brief      CoinSpend class for the Zerocoin library.
 *
 * @author     Ian Miers, Christina Garman and Matthew Green
 * @date       June 2013
 *
 * @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
 * @license    This project is released under the MIT license.
 **/

#include "Zerocoin.h"
#include <util.h>

namespace libzerocoin {

CoinSpend::CoinSpend(const Params* p, const PrivateCoin& coin,
                     Accumulator& a, const AccumulatorWitness& witness, const SpendMetaData& m,
					uint256 _accumulatorBlockHash):
	params(p),
	denomination(coin.getPublicCoin().getDenomination()),
    coinSerialNumber((coin.getSerialNumber())),
    ecdsaSignature(64, 0),
    ecdsaPubkey(33, 0),
	accumulatorPoK(&p->accumulatorParams),
	serialNumberSoK(p),
	commitmentPoK(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup),
	accumulatorBlockHash(_accumulatorBlockHash)
{

	// Sanity check: let's verify that the Witness is valid with respect to
	// the coin and Accumulator provided.
	if (!(witness.VerifyWitness(a, coin.getPublicCoin()))) {
		throw ZerocoinException("Accumulator witness does not verify");
	}
		    
	if (!HasValidSerial()) {
		throw ZerocoinException("Invalid serial # range"); 
	}
		    
	// 1: Generate two separate commitments to the public coin (C), each under
	// a different set of public parameters. We do this because the RSA accumulator
	// has specific requirements for the commitment parameters that are not
	// compatible with the group we use for the serial number proof.
	// Specifically, our serial number proof requires the order of the commitment group
	// to be the same as the modulus of the upper group. The Accumulator proof requires a
	// group with a significantly larger order.
	const Commitment fullCommitmentToCoinUnderSerialParams(&p->serialNumberSoKCommitmentGroup, coin.getPublicCoin().getValue());
	this->serialCommitmentToCoinValue = fullCommitmentToCoinUnderSerialParams.getCommitmentValue();

	const Commitment fullCommitmentToCoinUnderAccParams(&p->accumulatorParams.accumulatorPoKCommitmentGroup, coin.getPublicCoin().getValue());
	this->accCommitmentToCoinValue = fullCommitmentToCoinUnderAccParams.getCommitmentValue();

	// 2. Generate a ZK proof that the two commitments contain the same public coin.
	this->commitmentPoK = CommitmentProofOfKnowledge(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup, fullCommitmentToCoinUnderSerialParams, fullCommitmentToCoinUnderAccParams);

	// Now generate the two core ZK proofs:
	// 3. Proves that the committed public coin is in the Accumulator (PoK of "witness")
	this->accumulatorPoK = AccumulatorProofOfKnowledge(&p->accumulatorParams, fullCommitmentToCoinUnderAccParams, witness, a);

	// 4. Proves that the coin is correct w.r.t. serial number and hidden coin secret
	// (This proof is bound to the coin 'metadata', i.e., transaction hash)
	uint256 metahash = signatureHash(m);
    this->serialNumberSoK = SerialNumberSignatureOfKnowledge(p, coin, fullCommitmentToCoinUnderSerialParams, coin.getVersion()==ZEROCOIN_TX_VERSION_1_5 ? metahash : uint256());

	if(coin.getVersion() == 2){
	        // 5. Sign the transaction under the public key associate with the serial number.
	        secp256k1_pubkey pubkey;
	        size_t len = 33;
	        secp256k1_ecdsa_signature sig;

	        // TODO timing channel, since secp256k1_ec_pubkey_serialize does not expect its output to be secret.
	        // See main_impl.h of ecdh module on secp256k1
	        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, coin.getEcdsaSeckey())) {
	            throw ZerocoinException("Invalid secret key");
	        }
	        secp256k1_ec_pubkey_serialize(ctx, &this->ecdsaPubkey[0], &len, &pubkey, SECP256K1_EC_COMPRESSED);

	        secp256k1_ecdsa_sign(ctx, &sig, metahash.begin(), coin.getEcdsaSeckey(), NULL, NULL);
	        secp256k1_ecdsa_signature_serialize_compact(ctx, &this->ecdsaSignature[0], &sig);
	}
}

const Bignum&CoinSpend::getCoinSerialNumber() {
	return this->coinSerialNumber;
}

CoinDenomination CoinSpend::getDenomination() const {
	return static_cast<CoinDenomination>(this->denomination);
}

bool CoinSpend::Verify(const Accumulator& a, const SpendMetaData &m) const {
    if (!HasValidSerial()){
        LogPrintf("incorrect serial.\n");
        return false;
    }

	uint256 metahash = signatureHash(m);
	// Verify both of the sub-proofs using the given meta-data
    LogPrintf("a.getDenomination(): %s\n",a.getDenomination());
    LogPrintf("this->denomination: %s\n",this->denomination);
    int ret = (a.getDenomination() == this->denomination);
    if(!ret){
        LogPrintf("ret is false A, returning.\n");
        return false;  
    }
    ret = commitmentPoK.Verify(serialCommitmentToCoinValue, accCommitmentToCoinValue);
    if(!ret){
        LogPrintf("ret is false B, returning.\n");
        return false;  
    }
    ret = accumulatorPoK.Verify(a, accCommitmentToCoinValue);
    if(!ret){
            LogPrintf("ret is false C, returning.\n");
            return false;  
    }
    LogPrintf("metahash: %s\n", metahash.ToString());
    ret = serialNumberSoK.Verify(coinSerialNumber, serialCommitmentToCoinValue, this->version == ZEROCOIN_TX_VERSION_1_5 ? metahash : uint256());
    if (!ret) {
            LogPrintf("ret is false D, returning.\n");
            return false;
    }


    if (this->version != 2) {
        LogPrintf("returning ret.\n");
        return ret;
    }
    else {
        // Check if this is a coin that requires a signatures
        if (coinSerialNumber.bitSize() > 160){
            LogPrintf("bitsize did not verify.\n");
            return false;
        }

        // Check sizes
        if (this->ecdsaPubkey.size() != 33 || this->ecdsaSignature.size() != 64) {
            LogPrintf("sizes did not verify.\n");
            return false;
        }

        // Verify signature
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature signature;

        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, ecdsaPubkey.data(), 33)) {
            LogPrintf("secp256k1_ec_pubkey_parse did not verify.\n");
            return false;
        }

        // Recompute and compare hash of public key
        if (coinSerialNumber != PrivateCoin::serialNumberFromSerializedPublicKey(ctx, &pubkey)) {
            LogPrintf("coinSerialNumber did not verify.\n");
            return false;
        }

        secp256k1_ecdsa_signature_parse_compact(ctx, &signature, ecdsaSignature.data());
        if (!secp256k1_ecdsa_verify(ctx, &signature, metahash.begin(), &pubkey)) {
            LogPrintf("ecdsa did not verify.\n");
            return false;
        }

        return true;
    }

}

bool CoinSpend::HasValidSerial() const { 
	return coinSerialNumber > 0 && coinSerialNumber < params->coinCommitmentGroup.groupOrder; 
}

const uint256 CoinSpend::signatureHash(const SpendMetaData &m) const {
	CHashWriter h(0,0);
	h << m << serialCommitmentToCoinValue << accCommitmentToCoinValue << commitmentPoK << accumulatorPoK;
	return h.GetHash();
}

} /* namespace libzerocoin */
