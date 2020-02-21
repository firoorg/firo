#ifndef ELYSIUM_RPCRAWTX_H
#define ELYSIUM_RPCRAWTX_H

#include <univalue.h>

UniValue elysium_decodetransaction(const UniValue& params, bool fHelp);
UniValue elysium_createrawtx_opreturn(const UniValue& params, bool fHelp);
UniValue elysium_createrawtx_multisig(const UniValue& params, bool fHelp);
UniValue elysium_createrawtx_input(const UniValue& params, bool fHelp);
UniValue elysium_createrawtx_reference(const UniValue& params, bool fHelp);
UniValue elysium_createrawtx_change(const UniValue& params, bool fHelp);

#endif // ELYSIUM_RPCRAWTX_H
