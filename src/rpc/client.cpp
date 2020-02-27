// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"

#include <set>
#include <stdint.h>

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <univalue.h>

using namespace std;

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
};

static const CRPCConvertParam vRPCConvertParams[] =
{
    { "stop", 0 },
    { "setmocktime", 0 },
    { "getaddednodeinfo", 0 },
    { "generate", 0 },
    { "generate", 1 },
    { "generatetoaddress", 0 },
    { "generatetoaddress", 2 },
    { "getnetworkhashps", 0 },
    { "getnetworkhashps", 1 },
    { "sendtoaddress", 1 },
    { "sendtoaddress", 4 },
    { "settxfee", 0 },
    { "getreceivedbyaddress", 1 },
    { "getreceivedbyaccount", 1 },
    { "listreceivedbyaddress", 0 },
    { "listreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 2 },
    { "listreceivedbyaccount", 0 },
    { "listreceivedbyaccount", 1 },
    { "listreceivedbyaccount", 2 },
    { "getbalance", 1 },
    { "getbalance", 2 },
    { "getblockhash", 0 },
    { "move", 2 },
    { "move", 3 },
    { "sendfrom", 2 },
    { "sendfrom", 3 },
    { "listtransactions", 1 },
    { "listtransactions", 2 },
    { "listtransactions", 3 },
    { "listaccounts", 0 },
    { "listaccounts", 1 },
    { "walletpassphrase", 1 },
    { "getblocktemplate", 0 },
    { "listsinceblock", 1 },
    { "listsinceblock", 2 },
    { "sendmany", 1 },
    { "sendmany", 2 },
    { "sendmany", 4 },
    { "addmultisigaddress", 0 },
    { "addmultisigaddress", 1 },
    { "createmultisig", 0 },
    { "createmultisig", 1 },
    { "listunspent", 0 },
    { "listunspent", 1 },
    { "listunspent", 2 },
    { "regeneratemintpool", 0 },
    { "listunspentmintzerocoins", 0 },
    { "listunspentmintzerocoins", 1 },
    { "listunspentmintzerocoins", 2 },
    { "listunspentsigmamints", 0 },
    { "listunspentsigmamints", 1 },
    { "listunspentsigmamints", 2 },
    { "getblock", 1 },
    { "getblockheader", 1 },
    { "gettransaction", 1 },
    { "getrawtransaction", 1 },
    { "createrawtransaction", 0 },
    { "createrawtransaction", 1 },
    { "createrawtransaction", 2 },
    { "signrawtransaction", 1 },
    { "signrawtransaction", 2 },
    { "sendrawtransaction", 1 },
    { "fundrawtransaction", 1 },
    { "gettxout", 1 },
    { "gettxout", 2 },
    { "gettxoutproof", 0 },
    { "lockunspent", 0 },
    { "lockunspent", 1 },
    { "importprivkey", 2 },
    { "importaddress", 2 },
    { "importaddress", 3 },
    { "importpubkey", 2 },
    { "verifychain", 0 },
    { "verifychain", 1 },
    { "keypoolrefill", 0 },
    { "getrawmempool", 0 },
    { "estimatefee", 0 },
    { "estimatepriority", 0 },
    { "estimatesmartfee", 0 },
    { "estimatesmartpriority", 0 },
    { "prioritisetransaction", 1 },
    { "prioritisetransaction", 2 },
    { "setban", 2 },
    { "setban", 3 },
    { "getmempoolancestors", 1 },
    { "getmempooldescendants", 1 },
    { "getblockhashes", 0 },
    { "getblockhashes", 1 },
    { "getspentinfo", 0},
    { "getaddresstxids", 0},
    { "getaddressbalance", 0},
    { "getaddressdeltas", 0},
    { "getaddressutxos", 0},
    { "getaddressmempool", 0},
        //[zcoin]
    { "setmininput", 0 },
    { "mint", 0 },
    { "mintzerocoin", 0 },
    { "spendzerocoin", 0 },
    { "spendmanyzerocoin", 0 },
    { "spendmany", 1 },
    { "spendmany", 2 },
    { "spendmany", 4 },
    { "setgenerate", 0 },
    { "setgenerate", 1 },
    { "setmintzerocoinstatus", 2 },
    { "setmintzerocoinstatus", 1 },
    { "setsigmamintstatus", 1 },
    { "listmintzerocoins", 0 },
    { "listsigmamints", 0 },
    { "listpubcoins", 0 },
    { "listsigmapubcoins", 0 },
    { "listspendzerocoins", 0 },
    { "listspendzerocoins", 1 },
    { "listsigmaspends", 0 },
    { "listsigmaspends", 1 },
	{ "spendallzerocoin", 0 },
    { "remintzerocointosigma", 0 },
    /* Elysium - data retrieval calls */
	{ "elysium_gettradehistoryforaddress", 1 },
	{ "elysium_gettradehistoryforaddress", 2 },
	{ "elysium_gettradehistoryforpair", 0 },
	{ "elysium_gettradehistoryforpair", 1 },
	{ "elysium_gettradehistoryforpair", 2 },
	{ "elysium_setautocommit", 0 },
	{ "elysium_getcrowdsale", 0 },
	{ "elysium_getcrowdsale", 1 },
	{ "elysium_getgrants", 0 },
	{ "elysium_getbalance", 1 },
	{ "elysium_getproperty", 0 },
	{ "elysium_listtransactions", 1 },
	{ "elysium_listtransactions", 2 },
	{ "elysium_listtransactions", 3 },
	{ "elysium_listtransactions", 4 },
	{ "elysium_listmints", 0 },
	{ "elysium_listmints", 1 },
	{ "elysium_listmints", 2 },
	{ "elysium_getallbalancesforid", 0 },
	{ "elysium_listblocktransactions", 0 },
	{ "elysium_getorderbook", 0 },
	{ "elysium_getorderbook", 1 },
	{ "elysium_getseedblocks", 0 },
	{ "elysium_getseedblocks", 1 },
	{ "elysium_getmetadexhash", 0 },
	{ "elysium_getfeecache", 0 },
	{ "elysium_getfeeshare", 1 },
	{ "elysium_getfeetrigger", 0 },
	{ "elysium_getfeedistribution", 0 },
	{ "elysium_getfeedistributions", 0 },
	{ "elysium_getbalanceshash", 0 },

	/* Elysium - transaction calls */
	{ "elysium_send", 2 },
	{ "elysium_sendsto", 1 },
	{ "elysium_sendsto", 4 },
	{ "elysium_sendall", 2 },
	{ "elysium_sendtrade", 1 },
	{ "elysium_sendtrade", 3 },
	{ "elysium_sendcanceltradesbyprice", 1 },
	{ "elysium_sendcanceltradesbyprice", 3 },
	{ "elysium_sendcanceltradesbypair", 1 },
	{ "elysium_sendcanceltradesbypair", 2 },
	{ "elysium_sendcancelalltrades", 1 },
	{ "elysium_sendissuancefixed", 1 },
	{ "elysium_sendissuancefixed", 2 },
	{ "elysium_sendissuancefixed", 3 },
	{ "elysium_sendissuancefixed", 10 },
	{ "elysium_sendissuancemanaged", 1 },
	{ "elysium_sendissuancemanaged", 2 },
	{ "elysium_sendissuancemanaged", 3 },
	{ "elysium_sendissuancemanaged", 9 },
	{ "elysium_sendissuancecrowdsale", 1 },
	{ "elysium_sendissuancecrowdsale", 2 },
	{ "elysium_sendissuancecrowdsale", 3 },
	{ "elysium_sendissuancecrowdsale", 9 },
	{ "elysium_sendissuancecrowdsale", 11 },
	{ "elysium_sendissuancecrowdsale", 12 },
	{ "elysium_sendissuancecrowdsale", 13 },
	{ "elysium_senddexsell", 1 },
	{ "elysium_senddexsell", 4 },
	{ "elysium_senddexsell", 6 },
	{ "elysium_senddexaccept", 2 },
	{ "elysium_senddexaccept", 4 },
	{ "elysium_sendclosecrowdsale", 1 },
	{ "elysium_sendgrant", 2 },
	{ "elysium_sendrevoke", 1 },
	{ "elysium_sendchangeissuer", 2 },
	{ "elysium_sendenablefreezing", 1 },
	{ "elysium_senddisablefreezing", 1 },
	{ "elysium_sendfreeze", 2 },
	{ "elysium_sendunfreeze", 2 },
	{ "elysium_senddeactivation", 1 },
	{ "elysium_sendactivation", 1 },
	{ "elysium_sendactivation", 2 },
	{ "elysium_sendactivation", 3 },
	{ "elysium_sendalert", 1 },
	{ "elysium_sendalert", 2 },
	{ "elysium_sendcreatedenomination", 1 },
	{ "elysium_sendmint", 1 },
	{ "elysium_sendmint", 2 },
	{ "elysium_sendmint", 3 },
	{ "elysium_sendspend", 1 },
	{ "elysium_sendspend", 2 },

	/* Elysium - raw transaction calls */
	{ "elysium_decodetransaction", 1 },
	{ "elysium_decodetransaction", 2 },
	{ "elysium_createrawtx_reference", 2 },
	{ "elysium_createrawtx_input", 2 },
	{ "elysium_createrawtx_change", 1 },
	{ "elysium_createrawtx_change", 3 },
	{ "elysium_createrawtx_change", 4 },

	/* Elysium - payload creation */
	{ "elysium_createpayload_simplesend", 0 },
	{ "elysium_createpayload_sendall", 0 },
	{ "elysium_createpayload_dexsell", 0 },
	{ "elysium_createpayload_dexsell", 3 },
	{ "elysium_createpayload_dexsell", 5 },
	{ "elysium_createpayload_dexaccept", 0 },
	{ "elysium_createpayload_sto", 0 },
	{ "elysium_createpayload_sto", 2 },
	{ "elysium_createpayload_issuancefixed", 0 },
	{ "elysium_createpayload_issuancefixed", 1 },
	{ "elysium_createpayload_issuancefixed", 2 },
	{ "elysium_createpayload_issuancemanaged", 0 },
	{ "elysium_createpayload_issuancemanaged", 1 },
	{ "elysium_createpayload_issuancemanaged", 2 },
	{ "elysium_createpayload_issuancecrowdsale", 0 },
	{ "elysium_createpayload_issuancecrowdsale", 1 },
	{ "elysium_createpayload_issuancecrowdsale", 2 },
	{ "elysium_createpayload_issuancecrowdsale", 8 },
	{ "elysium_createpayload_issuancecrowdsale", 10 },
	{ "elysium_createpayload_issuancecrowdsale", 11 },
	{ "elysium_createpayload_issuancecrowdsale", 12 },
	{ "elysium_createpayload_closecrowdsale", 0 },
	{ "elysium_createpayload_grant", 0 },
	{ "elysium_createpayload_revoke", 0 },
	{ "elysium_createpayload_changeissuer", 0 },
	{ "elysium_createpayload_trade", 0 },
	{ "elysium_createpayload_trade", 2 },
	{ "elysium_createpayload_canceltradesbyprice", 0 },
	{ "elysium_createpayload_canceltradesbyprice", 2 },
	{ "elysium_createpayload_canceltradesbypair", 0 },
	{ "elysium_createpayload_canceltradesbypair", 1 },
	{ "elysium_createpayload_cancelalltrades", 0 },

	/* Elysium - backwards compatibility */
	{ "getcrowdsale_MP", 0 },
	{ "getcrowdsale_MP", 1 },
	{ "getgrants_MP", 0 },
	{ "send_MP", 2 },
	{ "getbalance_MP", 1 },
	{ "sendtoowners_MP", 1 },
	{ "getproperty_MP", 0 },
	{ "listtransactions_MP", 1 },
	{ "listtransactions_MP", 2 },
	{ "listtransactions_MP", 3 },
	{ "listtransactions_MP", 4 },
	{ "getallbalancesforid_MP", 0 },
	{ "listblocktransactions_MP", 0 },
	{ "getorderbook_MP", 0 },
	{ "getorderbook_MP", 1 },
	{ "trade_MP", 1 }, // depreciated
	{ "trade_MP", 3 }, // depreciated
	{ "trade_MP", 5 }, // depreciated
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int> > members;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw runtime_error(string("Error parsing JSON:")+strVal);
    return jVal[0];
}

/** Convert strings to command-specific RPC representation */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}
