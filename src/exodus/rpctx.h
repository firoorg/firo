#ifndef EXODUS_RPCTX
#define EXODUS_RPCTX

#include <univalue.h>

UniValue exodus_sendrawtx(const UniValue& params, bool fHelp);
UniValue exodus_send(const UniValue& params, bool fHelp);
UniValue exodus_sendall(const UniValue& params, bool fHelp);
UniValue exodus_senddexsell(const UniValue& params, bool fHelp);
UniValue exodus_senddexaccept(const UniValue& params, bool fHelp);
UniValue exodus_sendissuancecrowdsale(const UniValue& params, bool fHelp);
UniValue exodus_sendissuancefixed(const UniValue& params, bool fHelp);
UniValue exodus_sendissuancemanaged(const UniValue& params, bool fHelp);
UniValue exodus_sendsto(const UniValue& params, bool fHelp);
UniValue exodus_sendgrant(const UniValue& params, bool fHelp);
UniValue exodus_sendrevoke(const UniValue& params, bool fHelp);
UniValue exodus_sendclosecrowdsale(const UniValue& params, bool fHelp);
UniValue trade_MP(const UniValue& params, bool fHelp);
UniValue exodus_sendtrade(const UniValue& params, bool fHelp);
UniValue exodus_sendcanceltradesbyprice(const UniValue& params, bool fHelp);
UniValue exodus_sendcanceltradesbypair(const UniValue& params, bool fHelp);
UniValue exodus_sendcancelalltrades(const UniValue& params, bool fHelp);
UniValue exodus_sendchangeissuer(const UniValue& params, bool fHelp);
UniValue exodus_sendactivation(const UniValue& params, bool fHelp);
UniValue exodus_sendalert(const UniValue& params, bool fHelp);

#endif // EXODUS_RPCTX
