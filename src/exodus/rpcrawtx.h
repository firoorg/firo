#ifndef EXODUS_RPCRAWTX_H
#define EXODUS_RPCRAWTX_H

#include <univalue.h>
#include "rpc/server.h"

UniValue exodus_decodetransaction(const JSONRPCRequest& request);
UniValue exodus_createrawtx_opreturn(const JSONRPCRequest& request);
UniValue exodus_createrawtx_multisig(const JSONRPCRequest& request);
UniValue exodus_createrawtx_input(const JSONRPCRequest& request);
UniValue exodus_createrawtx_reference(const JSONRPCRequest& request);
UniValue exodus_createrawtx_change(const JSONRPCRequest& request);


#endif // EXODUS_RPCRAWTX_H
