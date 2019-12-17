#ifndef BIP47UTIL_H
#define BIP47UTIL_H
#include "bip47_common.h"
#include "wallet/wallet.h"

class PaymentCode;
class PaymentAddress;

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
#endif
