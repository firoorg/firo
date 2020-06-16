#ifndef ZCOIN_BIP47UTIL_H
#define ZCOIN_BIP47UTIL_H
#include "key.h"

class PaymentCode;
class PaymentAddress;
class CWallet;
class CTxOut;
class CTxIn;
class CTransaction;

class BIP47Util {
    public:
    static bool isValidNotificationTransactionOpReturn(CTxOut txout);
    static bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout);
    static bool getPaymentCodeInNotificationTransaction(vector<unsigned char> privKeyBytes, CTransaction tx, PaymentCode &paymentCode);
    static bool getOpCodeData(CTxOut txout, vector<unsigned char>& op_data);
    static bool getScriptSigPubkey(CTxIn txin, vector<unsigned char>& pubkeyBytes);
    static PaymentAddress getPaymentAddress(PaymentCode &pcode, int idx, CExtKey extkey);
    static PaymentAddress getReceiveAddress(CWallet* pbip47Wallet, PaymentCode &pcode_from, int idx);
    static PaymentAddress getSendAddress(CWallet* pbip47Wallet, PaymentCode &pcode_to, int idx);

};
#endif // ZCOIN_BIP47UTIL_H
