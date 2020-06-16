#ifndef ZCOIN_BIP47UTIL_H
#define ZCOIN_BIP47UTIL_H
#include "key.h"

class CPaymentCode;
class CPaymentAddress;
class CWallet;
class CTxOut;
class CTxIn;
class CTransaction;

class CBIP47Util {
    public:
	    static bool isValidNotificationTransactionOpReturn(CTxOut txout);
	    static bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout);
	    static bool getPaymentCodeInNotificationTransaction(vector<unsigned char> privKeyBytes, CTransaction tx, CPaymentCode &paymentCode);
	    static bool getOpCodeData(CTxOut txout, vector<unsigned char>& op_data);
	    static bool getScriptSigPubkey(CTxIn txin, vector<unsigned char>& pubkeyBytes);
	    static CPaymentAddress getPaymentAddress(CPaymentCode &pcode, int idx, CExtKey extkey);
	    static CPaymentAddress getReceiveAddress(CWallet* pbip47Wallet, CPaymentCode &pcode_from, int idx);
	    static CPaymentAddress getSendAddress(CWallet* pbip47Wallet, CPaymentCode &pcode_to, int idx);

};
#endif // ZCOIN_BIP47UTIL_H
