#ifndef EXODUS_RPCRAWTX_H
#define EXODUS_RPCRAWTX_H

#include <univalue.h>

UniValue exodus_decodetransaction(const UniValue& params, bool fHelp);
UniValue exodus_createrawtx_opreturn(const UniValue& params, bool fHelp);
UniValue exodus_createrawtx_multisig(const UniValue& params, bool fHelp);
UniValue exodus_createrawtx_input(const UniValue& params, bool fHelp);
UniValue exodus_createrawtx_reference(const UniValue& params, bool fHelp);
UniValue exodus_createrawtx_change(const UniValue& params, bool fHelp);


#endif // EXODUS_RPCRAWTX_H
