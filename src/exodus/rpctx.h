#ifndef ELYSIUM_RPCTX
#define ELYSIUM_RPCTX

#include <univalue.h>

UniValue elysium_sendrawtx(const UniValue& params, bool fHelp);
UniValue elysium_send(const UniValue& params, bool fHelp);
UniValue elysium_sendall(const UniValue& params, bool fHelp);
UniValue elysium_senddexsell(const UniValue& params, bool fHelp);
UniValue elysium_senddexaccept(const UniValue& params, bool fHelp);
UniValue elysium_sendissuancecrowdsale(const UniValue& params, bool fHelp);
UniValue elysium_sendissuancefixed(const UniValue& params, bool fHelp);
UniValue elysium_sendissuancemanaged(const UniValue& params, bool fHelp);
UniValue elysium_sendsto(const UniValue& params, bool fHelp);
UniValue elysium_sendgrant(const UniValue& params, bool fHelp);
UniValue elysium_sendrevoke(const UniValue& params, bool fHelp);
UniValue elysium_sendclosecrowdsale(const UniValue& params, bool fHelp);
UniValue trade_MP(const UniValue& params, bool fHelp);
UniValue elysium_sendtrade(const UniValue& params, bool fHelp);
UniValue elysium_sendcanceltradesbyprice(const UniValue& params, bool fHelp);
UniValue elysium_sendcanceltradesbypair(const UniValue& params, bool fHelp);
UniValue elysium_sendcancelalltrades(const UniValue& params, bool fHelp);
UniValue elysium_sendchangeissuer(const UniValue& params, bool fHelp);
UniValue elysium_sendactivation(const UniValue& params, bool fHelp);
UniValue elysium_sendalert(const UniValue& params, bool fHelp);

#endif // ELYSIUM_RPCTX
