#ifndef ELYSIUM_RPCPAYLOAD_H
#define ELYSIUM_RPCPAYLOAD_H

#include <univalue.h>
#include "rpc/server.h"

UniValue elysium_createpayload_simplesend(const JSONRPCRequest& request);
UniValue elysium_createpayload_sendall(const JSONRPCRequest& request);
UniValue elysium_createpayload_dexsell(const JSONRPCRequest& request);
UniValue elysium_createpayload_dexaccept(const JSONRPCRequest& request);
UniValue elysium_createpayload_sto(const JSONRPCRequest& request);
UniValue elysium_createpayload_issuancefixed(const JSONRPCRequest& request);
UniValue elysium_createpayload_issuancecrowdsale(const JSONRPCRequest& request);
UniValue elysium_createpayload_issuancemanaged(const JSONRPCRequest& request);
UniValue elysium_createpayload_closecrowdsale(const JSONRPCRequest& request);
UniValue elysium_createpayload_grant(const JSONRPCRequest& request);
UniValue elysium_createpayload_revoke(const JSONRPCRequest& request);
UniValue elysium_createpayload_changeissuer(const JSONRPCRequest& request);
UniValue elysium_createpayload_trade(const JSONRPCRequest& request);
UniValue elysium_createpayload_canceltradesbyprice(const JSONRPCRequest& request);
UniValue elysium_createpayload_canceltradesbypair(const JSONRPCRequest& request);
UniValue elysium_createpayload_cancelalltrades(const JSONRPCRequest& request);

#endif // ELYSIUM_RPCPAYLOAD_H
