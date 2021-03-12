/**
* @file       Zerocoin.h
*
* @brief      Exceptions and constants for Zerocoin
*
* @author     Ian Miers, Christina Garman and Matthew Green
* @date       June 2013
*
* @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
* @license    This project is released under the MIT license.
**/

#ifndef ZEROCOIN_H_
#define ZEROCOIN_H_

#include <stdexcept>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_ecdh.h>

#define ZEROCOIN_DEFAULT_SECURITYLEVEL      80
#define ZEROCOIN_MIN_SECURITY_LEVEL         80
#define ZEROCOIN_MAX_SECURITY_LEVEL         80
#define ACCPROOF_KPRIME                     160
#define ACCPROOF_KDPRIME                    128
#define MAX_COINMINT_ATTEMPTS               10000
#define ZEROCOIN_MINT_PRIME_PARAM			20
#define ZEROCOIN_VERSION_STRING             "0.11"
#define ZEROCOIN_VERSION_INT				11
#define ZEROCOIN_PROTOCOL_VERSION           "1"
#define HASH_OUTPUT_BITS                    256
#define ZEROCOIN_COMMITMENT_EQUALITY_PROOF  "COMMITMENT_EQUALITY_PROOF"
#define ZEROCOIN_ACCUMULATOR_PROOF          "ACCUMULATOR_PROOF"
#define ZEROCOIN_SERIALNUMBER_PROOF         "SERIALNUMBER_PROOF"
#define ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER  "PUBLICKEY_TO_SERIALNUMBER"

// Versions of zerocoin mint/spend transactions
#define ZEROCOIN_TX_VERSION_1               1
#define ZEROCOIN_TX_VERSION_2               2
#define ZEROCOIN_TX_VERSION_1_5             15
#define ZEROCOIN_TX_VERSION_3               30
#define ZEROCOIN_TX_VERSION_3_1             31
#define LELANTUS_TX_VERSION_4               40
#define SIGMA_TO_LELANTUS_JOINSPLIT         41
#define LELANTUS_TX_VERSION_4_5             45
#define SIGMA_TO_LELANTUS_JOINSPLIT_FIXED   46

// Activate multithreaded mode for proof verification
#define ZEROCOIN_THREADING 1

// Uses a fast technique for coin generation. Could be more vulnerable
// to timing attacks. Turn off if an attacker can measure coin minting time.
#define	ZEROCOIN_FAST_MINT 1

// Errors thrown by the Zerocoin library

class ZerocoinException : public std::runtime_error
{
public:
	explicit ZerocoinException(const std::string& str) : std::runtime_error(str) {}
};

namespace libzerocoin {
   // Defined in coin.cpp
   extern secp256k1_context* ctx;
}

#include "../serialize.h"
#include "bitcoin_bignum/bignum.h"
#include "../hash.h"
#include "Params.h"
#include "Coin.h"
#include "Commitment.h"
#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "CoinSpend.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "ParamGeneration.h"

#endif /* ZEROCOIN_H_ */
