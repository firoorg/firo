#ifndef ZCOIN_BIP47UTIL_H
#define ZCOIN_BIP47UTIL_H
#include "key.h"
#include <iostream>
#include <list>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <openssl/sha.h>
#include "uint256.h"
#include "bip47/utils.h"
#include "utilstrencodings.h"

#define HARDENED_BIT 0x80000000

class CWallet;
class CTxOut;
class CTxIn;
class CTransaction;

namespace bip47 {

class CPaymentCode;
class CPaymentAddress;
class CAccount;

namespace util {
static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
unsigned char* copyOfRange(const std::vector<unsigned char> &original, int from, int to,std::vector<unsigned char> &result);
bool doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result);
bool isValidNotificationTransactionOpReturn(CTxOut txout);
bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout);
bool getPaymentCodeInNotificationTransaction(vector<unsigned char> privKeyBytes, CTransaction tx, CPaymentCode &paymentCode);
bool getOpCodeData(CTxOut txout, vector<unsigned char>& op_data);
bool getScriptSigPubkey(CTxIn txin, vector<unsigned char>& pubkeyBytes);
CPaymentAddress getPaymentAddress(CPaymentCode &pcode, int idx, CExtKey extkey);
CPaymentAddress getReceiveAddress(CAccount* v_bip47Account, CWallet* pbip47Wallet, CPaymentCode &pcode_from, int idx);
CPaymentAddress getSendAddress(CWallet* pbip47Wallet, CPaymentCode &pcode_to, int idx);

};

}

#endif // ZCOIN_BIP47UTIL_H
