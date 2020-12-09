#ifndef ZCOIN_BIP47UTIL_H
#define ZCOIN_BIP47UTIL_H
#include "key.h"
#include <iostream>
#include <list>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <openssl/sha.h>
#include "GroupElement.h"

#define HARDENED_BIT 0x80000000

class COutPoint;

namespace bip47 {

class CPaymentCode;
class CAccount;

namespace utils {

/******************************************************************************/
bool pcodeFromMaskedPayload(std::vector<unsigned char> payload, COutPoint const & outpoint, CKey const & myPrivkey, CPubKey const & outPubkey, CPaymentCode & pcode);

/******************************************************************************/
CExtKey derive(CExtKey const & source, std::vector<uint32_t> const & path);

/******************************************************************************/
GroupElement GeFromPubkey(CPubKey const & pubKey);
CPubKey PubkeyFromGe(GroupElement const & ge);

} }

#endif // ZCOIN_BIP47UTIL_H
