#ifndef EXODUS_RPCPAYLOAD_H
#define EXODUS_RPCPAYLOAD_H

#include <univalue.h>
#include "rpc/server.h"

UniValue exodus_createpayload_simplesend(const JSONRPCRequest& request);
UniValue exodus_createpayload_sendall(const JSONRPCRequest& request);
UniValue exodus_createpayload_dexsell(const JSONRPCRequest& request);
UniValue exodus_createpayload_dexaccept(const JSONRPCRequest& request);
UniValue exodus_createpayload_sto(const JSONRPCRequest& request);
UniValue exodus_createpayload_issuancefixed(const JSONRPCRequest& request);
UniValue exodus_createpayload_issuancecrowdsale(const JSONRPCRequest& request);
UniValue exodus_createpayload_issuancemanaged(const JSONRPCRequest& request);
UniValue exodus_createpayload_closecrowdsale(const JSONRPCRequest& request);
UniValue exodus_createpayload_grant(const JSONRPCRequest& request);
UniValue exodus_createpayload_revoke(const JSONRPCRequest& request);
UniValue exodus_createpayload_changeissuer(const JSONRPCRequest& request);
UniValue exodus_createpayload_trade(const JSONRPCRequest& request);
UniValue exodus_createpayload_canceltradesbyprice(const JSONRPCRequest& request);
UniValue exodus_createpayload_canceltradesbypair(const JSONRPCRequest& request);
UniValue exodus_createpayload_cancelalltrades(const JSONRPCRequest& request);

#endif // EXODUS_RPCPAYLOAD_H
