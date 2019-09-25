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
    static PaymentAddress getPaymentAddress(PaymentCode &pcode, int idx, CExtKey extkey);

};
#endif
