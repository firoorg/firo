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

class CPaymentCode;
class CPaymentAddress;
class CWallet;
class CTxOut;
class CTxIn;
class CTransaction;
class CBIP47Account;

class CBIP47Util {
    public:
		static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
	    static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
	    static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
	    static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
	    static unsigned char* copyOfRange(const std::vector<unsigned char> &original, int from, int to,std::vector<unsigned char> &result);
	    static bool doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result);
	    static bool isValidNotificationTransactionOpReturn(CTxOut txout);
	    static bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout);
	    static bool getPaymentCodeInNotificationTransaction(vector<unsigned char> privKeyBytes, CTransaction tx, CPaymentCode &paymentCode);
	    static bool getOpCodeData(CTxOut txout, vector<unsigned char>& op_data);
	    static bool getScriptSigPubkey(CTxIn txin, vector<unsigned char>& pubkeyBytes);
	    static CPaymentAddress getPaymentAddress(CPaymentCode &pcode, int idx, CExtKey extkey);
	    static CPaymentAddress getReceiveAddress(CBIP47Account* v_bip47Account, CWallet* pbip47Wallet, CPaymentCode &pcode_from, int idx);
	    static CPaymentAddress getSendAddress(CWallet* pbip47Wallet, CPaymentCode &pcode_to, int idx);

};
#endif // ZCOIN_BIP47UTIL_H
