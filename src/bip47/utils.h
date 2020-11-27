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

class CWallet;
class CTxOut;
class CTxIn;
class CTransaction;

namespace bip47 {

class CPaymentCode;
class CAccount;

namespace utils {
bool doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result);
bool isValidNotificationTransactionOpReturn(CTxOut txout);
bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout);
bool getPaymentCodeInNotificationTransaction(std::vector<unsigned char> const & privKeyBytes, CTransaction const & tx, CPaymentCode &paymentCode);
bool getOpCodeData(CTxOut const & txout, vector<unsigned char>& op_data);
bool getScriptSigPubkey(CTxIn const & txin, vector<unsigned char>& pubkeyBytes);

CExtKey derive(CExtKey const & source, std::vector<uint32_t> const & path);

GroupElement GeFromPubkey(CPubKey const & pubKey);
CPubKey PubkeyFromGe(GroupElement const & ge);
} }

#endif // ZCOIN_BIP47UTIL_H
