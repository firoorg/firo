#ifndef ELYSIUM_RPCTX
#define ELYSIUM_RPCTX

#include <univalue.h>
#include "rpc/server.h"

UniValue elysium_sendrawtx(const JSONRPCRequest& request);
UniValue elysium_send(const JSONRPCRequest& request);
UniValue elysium_sendall(const JSONRPCRequest& request);
UniValue elysium_senddexsell(const JSONRPCRequest& request);
UniValue elysium_senddexaccept(const JSONRPCRequest& request);
UniValue elysium_sendissuancecrowdsale(const JSONRPCRequest& request);
UniValue elysium_sendissuancefixed(const JSONRPCRequest& request);
UniValue elysium_sendissuancemanaged(const JSONRPCRequest& request);
UniValue elysium_sendsto(const JSONRPCRequest& request);
UniValue elysium_sendgrant(const JSONRPCRequest& request);
UniValue elysium_sendrevoke(const JSONRPCRequest& request);
UniValue elysium_sendclosecrowdsale(const JSONRPCRequest& request);
UniValue trade_MP(const JSONRPCRequest& request);
UniValue elysium_sendtrade(const JSONRPCRequest& request);
UniValue elysium_sendcanceltradesbyprice(const JSONRPCRequest& request);
UniValue elysium_sendcanceltradesbypair(const JSONRPCRequest& request);
UniValue elysium_sendcancelalltrades(const JSONRPCRequest& request);
UniValue elysium_sendchangeissuer(const JSONRPCRequest& request);
UniValue elysium_sendactivation(const JSONRPCRequest& request);
UniValue elysium_sendalert(const JSONRPCRequest& request);

#endif // ELYSIUM_RPCTX
