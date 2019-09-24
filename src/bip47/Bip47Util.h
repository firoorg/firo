#ifndef BIP47UTIL_H
#define BIP47UTIL_H

class CTxOut;

class BIP47Util {
 public:
 static bool isValidNotificationTransactionOpReturn(CTxOut txout);
};
#endif
