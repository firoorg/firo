// Copyright (c) 2014 BctCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef H_BctCoin_SCHNORR
#define H_BctCoin_SCHNORR

#include <string>
#include <iostream>
using namespace std;

#include "cryptopp/osrng.h"      // Random Number Generator
#include "cryptopp/eccrypto.h"   // Elliptic Curve
#include "cryptopp/ecp.h"        // F(p) EC
#include "cryptopp/integer.h"    // Integer 
#include "cryptopp/sha3.h"		 // SHA3

#define SCHNORR_SECRET_KEY_SIZE 32
#define SCHNORR_SIG_SIZE 32
#define SCHNORR_PUBLIC_KEY_COMPRESSED_SIZE 33
#define SCHNORR_PUBLIC_KEY_UNCOMPRESSED_SIZE 65

#endif
