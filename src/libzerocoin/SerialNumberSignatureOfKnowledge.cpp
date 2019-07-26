/**
* @file       SerialNumberSignatureOfKnowledge.cpp
*
* @brief      SerialNumberSignatureOfKnowledge class for the Zerocoin library.
*
* @author     Ian Miers, Christina Garman and Matthew Green
* @date       June 2013
*
* @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
* @license    This project is released under the MIT license.
**/

#include "Zerocoin.h"
#include "ParallelTasks.h"

namespace libzerocoin {

SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(const Params* p): params(p) { }

SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(const Params* p, const PrivateCoin& coin, const Commitment& commitmentToCoin, uint256 msghash)
    :params(p), s_notprime(p->zkp_iterations), sprime(p->zkp_iterations) {

    ParallelTasks::DoNotDisturb dnd;

	// Sanity check: verify that the order of the "accumulatedValueCommitmentGroup" is
	// equal to the modulus of "coinCommitmentGroup". Otherwise we will produce invalid
	// proofs.
	if (params->coinCommitmentGroup.modulus != params->serialNumberSoKCommitmentGroup.groupOrder) {
		throw ZerocoinException("Groups are not structured correctly.");
	}

	Bignum a = params->coinCommitmentGroup.g;
	Bignum b = params->coinCommitmentGroup.h;
	Bignum g = params->serialNumberSoKCommitmentGroup.g;
	Bignum h = params->serialNumberSoKCommitmentGroup.h;

	CHashWriter hasher(0,0);
	hasher << *params << commitmentToCoin.getCommitmentValue() << coin.getSerialNumber();
    if (!msghash.IsNull())
        hasher << msghash;

	vector<Bignum> r(params->zkp_iterations);
	vector<Bignum> v(params->zkp_iterations);
	vector<Bignum> c(params->zkp_iterations);


	for(uint32_t i=0; i < params->zkp_iterations; i++) {
		//FIXME we really ought to use one BN_CTX for all of these
		// operations for performance reasons, not the one that
		// is created individually  by the wrapper
		r[i] = Bignum::randBignum(params->coinCommitmentGroup.groupOrder);
		v[i] = Bignum::randBignum(params->serialNumberSoKCommitmentGroup.groupOrder);
	}

	// Openssl's rng is not thread safe, so we don't call it in a parallel loop,
	// instead we generate the random values beforehand and run the calculations
	// based on those values in parallel.

    ParallelTasks challenges(params->zkp_iterations);

	for(uint32_t i=0; i < params->zkp_iterations; i++) {
		// compute g^{ {a^x b^r} h^v} mod p2
        challenges.Add([this, i, &coin, &c, &r, &v] {
            c[i] = challengeCalculation(coin.getSerialNumber(), r[i], v[i]);
        });
	}
    challenges.Wait();

	// We can't hash data in parallel either
	// because OPENMP cannot not guarantee loops
	// execute in order.
	for(uint32_t i=0; i < params->zkp_iterations; i++) {
		hasher << c[i];
	}
    this->hash = hasher.GetArith256Hash();
	unsigned char *hashbytes =  (unsigned char*) &hash;

    challenges.Reset();
	for(uint32_t i = 0; i < params->zkp_iterations; i++) {
		int bit = i % 8;
		int byte = i / 8;

		bool challenge_bit = ((hashbytes[byte] >> bit) & 0x01);
		if (challenge_bit) {
			s_notprime[i]       = r[i];
			sprime[i]           = v[i];
		} else {
            challenges.Add([this, i, &r, &v, &b, &commitmentToCoin, &coin] {
                s_notprime[i]   = r[i] - coin.getRandomness();
                sprime[i]       = v[i] - (commitmentToCoin.getRandomness() *
			                              b.pow_mod(r[i] - coin.getRandomness(), params->serialNumberSoKCommitmentGroup.groupOrder));
            });
		}
    }
    challenges.Wait();
}

inline Bignum SerialNumberSignatureOfKnowledge::challengeCalculation(const Bignum& a_exp,const Bignum& b_exp,
        const Bignum& h_exp) const {

	Bignum a = params->coinCommitmentGroup.g;
	Bignum b = params->coinCommitmentGroup.h;
	Bignum g = params->serialNumberSoKCommitmentGroup.g;
	Bignum h = params->serialNumberSoKCommitmentGroup.h;

	Bignum exponent = (a.pow_mod(a_exp, params->serialNumberSoKCommitmentGroup.groupOrder)
	                   * b.pow_mod(b_exp, params->serialNumberSoKCommitmentGroup.groupOrder)) % params->serialNumberSoKCommitmentGroup.groupOrder;

	return (g.pow_mod(exponent, params->serialNumberSoKCommitmentGroup.modulus) * h.pow_mod(h_exp, params->serialNumberSoKCommitmentGroup.modulus)) % params->serialNumberSoKCommitmentGroup.modulus;
}

bool SerialNumberSignatureOfKnowledge::Verify(const Bignum& coinSerialNumber, const Bignum& valueOfCommitmentToCoin,
        const uint256 msghash) const {

    ParallelTasks::DoNotDisturb dnd;

	Bignum a = params->coinCommitmentGroup.g;
	Bignum b = params->coinCommitmentGroup.h;
	Bignum g = params->serialNumberSoKCommitmentGroup.g;
	Bignum h = params->serialNumberSoKCommitmentGroup.h;

	// Make sure that the serial number has a unique representation
	if (coinSerialNumber < 0 || coinSerialNumber >= params->coinCommitmentGroup.groupOrder){
		return false;
	}


	CHashWriter hasher(0,0);
	hasher << *params << valueOfCommitmentToCoin <<coinSerialNumber;
    if (!msghash.IsNull())
        hasher << msghash;

	vector<CBigNum> tprime(params->zkp_iterations);
	unsigned char *hashbytes = (unsigned char*) &this->hash;

    ParallelTasks challenges(params->zkp_iterations);

	for(uint32_t i = 0; i < params->zkp_iterations; i++) {
        challenges.Add([this, i, hashbytes, &b, &h, &tprime, &coinSerialNumber, &valueOfCommitmentToCoin] {
            int bit = i % 8;
            int byte = i / 8;
            bool challenge_bit = ((hashbytes[byte] >> bit) & 0x01);
            if(challenge_bit) {
                tprime[i] = challengeCalculation(coinSerialNumber, s_notprime[i], sprime[i]);
            } else {
                Bignum exp = b.pow_mod(s_notprime[i], params->serialNumberSoKCommitmentGroup.groupOrder);
                tprime[i] = ((valueOfCommitmentToCoin.pow_mod(exp, params->serialNumberSoKCommitmentGroup.modulus) % params->serialNumberSoKCommitmentGroup.modulus) *
                             (h.pow_mod(sprime[i], params->serialNumberSoKCommitmentGroup.modulus) % params->serialNumberSoKCommitmentGroup.modulus)) %
                            params->serialNumberSoKCommitmentGroup.modulus;
            }
        });
	}
    challenges.Wait();

	for(uint32_t i = 0; i < params->zkp_iterations; i++) {
		hasher << tprime[i];
	}
    return hasher.GetArith256Hash() == hash;
}

} /* namespace libzerocoin */
