#ifndef ELYSIUM_RPCPAYLOAD_H
#define ELYSIUM_RPCPAYLOAD_H

#include <univalue.h>

UniValue elysium_createpayload_simplesend(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_sendall(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_dexsell(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_dexaccept(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_sto(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_issuancefixed(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_issuancecrowdsale(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_issuancemanaged(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_closecrowdsale(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_grant(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_revoke(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_changeissuer(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_trade(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_canceltradesbyprice(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_canceltradesbypair(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_cancelalltrades(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_createdenomination(const UniValue& params, bool fHelp);
UniValue elysium_createpayload_mintbypublickeys(const UniValue& params, bool fHelp);

#endif // ELYSIUM_RPCPAYLOAD_H
