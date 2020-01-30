#ifndef EXODUS_RPCPAYLOAD_H
#define EXODUS_RPCPAYLOAD_H

#include <univalue.h>

UniValue exodus_createpayload_simplesend(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_sendall(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_dexsell(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_dexaccept(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_sto(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_issuancefixed(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_issuancecrowdsale(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_issuancemanaged(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_closecrowdsale(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_grant(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_revoke(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_changeissuer(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_trade(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_canceltradesbyprice(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_canceltradesbypair(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_cancelalltrades(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_createdenomination(const UniValue& params, bool fHelp);
UniValue exodus_createpayload_mintbypublickeys(const UniValue& params, bool fHelp);

#endif // EXODUS_RPCPAYLOAD_H
