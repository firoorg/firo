#ifndef EXODUS_RPCTX
#define EXODUS_RPCTX

#include <univalue.h>
#include "rpc/server.h"

UniValue exodus_sendrawtx(const JSONRPCRequest& request);
UniValue exodus_send(const JSONRPCRequest& request);
UniValue exodus_sendall(const JSONRPCRequest& request);
UniValue exodus_senddexsell(const JSONRPCRequest& request);
UniValue exodus_senddexaccept(const JSONRPCRequest& request);
UniValue exodus_sendissuancecrowdsale(const JSONRPCRequest& request);
UniValue exodus_sendissuancefixed(const JSONRPCRequest& request);
UniValue exodus_sendissuancemanaged(const JSONRPCRequest& request);
UniValue exodus_sendsto(const JSONRPCRequest& request);
UniValue exodus_sendgrant(const JSONRPCRequest& request);
UniValue exodus_sendrevoke(const JSONRPCRequest& request);
UniValue exodus_sendclosecrowdsale(const JSONRPCRequest& request);
UniValue trade_MP(const JSONRPCRequest& request);
UniValue exodus_sendtrade(const JSONRPCRequest& request);
UniValue exodus_sendcanceltradesbyprice(const JSONRPCRequest& request);
UniValue exodus_sendcanceltradesbypair(const JSONRPCRequest& request);
UniValue exodus_sendcancelalltrades(const JSONRPCRequest& request);
UniValue exodus_sendchangeissuer(const JSONRPCRequest& request);
UniValue exodus_sendactivation(const JSONRPCRequest& request);
UniValue exodus_sendalert(const JSONRPCRequest& request);

#endif // EXODUS_RPCTX
