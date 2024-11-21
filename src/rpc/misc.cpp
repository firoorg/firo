// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "validation.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include "sigma.h"
#include "txdb.h"

#include "masternode-sync.h"
#include "evo/deterministicmns.h"
#include "llmq/quorums_instantsend.h"
#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getinfo\n"
            "\nDEPRECATED. Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total firo balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.push_back(Pair("walletversion", pwallet->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    if(g_connman)
        obj.push_back(Pair("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL)));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string())));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("testnet",       Params().NetworkIDString() == CBaseChainParams::TESTNET));
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwallet->GetKeyPoolSize()));
    }
    if (pwallet && pwallet->IsCrypted()) {
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
    obj.push_back(Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
#endif
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    DescribeAddressVisitor(CWallet *_pwallet) : pwallet(_pwallet) {}

    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CExchangeKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("exchangepubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            BOOST_FOREACH(const CTxDestination& addr, addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given Firo address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The Firo address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\", (string) The Firo address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,        (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    CBitcoinAddress address(request.params[0].get_str());
    bool isValid = address.IsValid();

    bool isvalidSpark = false;
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    spark::Address sAddress(params);

    if (!isValid) {
        try {
            unsigned char coinNetwork = sAddress.decode(request.params[0].get_str());
            isvalidSpark = coinNetwork == network;
        } catch (const std::exception &) {
            isvalidSpark = false;
        }
    }

    UniValue ret(UniValue::VOBJ);
    if (isvalidSpark)
        ret.push_back(Pair("isvalidSpark", isvalidSpark));
    else
        ret.push_back(Pair("isvalid", isValid));

    if (isValid)
    {
        CTxDestination dest = address.Get();
        std::string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.pushKVs(detail);
        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.push_back(Pair("account", pwallet->mapAddressBook[dest].name));
        }
        CKeyID keyID;
        if (pwallet) {
            const auto& meta = pwallet->mapKeyMetadata;
            auto it = address.GetKeyIDExt(keyID) ? meta.find(keyID) : meta.end();
            if (it == meta.end()) {
                it = meta.find(CScriptID(scriptPubKey));
            }
            if (it != meta.end()) {
                ret.push_back(Pair("timestamp", it->second.nCreateTime));
                if (!it->second.hdKeypath.empty()) {
                    ret.push_back(Pair("hdkeypath", it->second.hdKeypath));
                    ret.push_back(Pair("hdmasterkeyid", it->second.hdMasterKeyID.GetHex()));
                }
            }
        }
#endif
    } else if (isvalidSpark) {
        std::string currentAddress = sAddress.encode(network);
        ret.push_back(Pair("address", currentAddress));

#ifdef ENABLE_WALLET
        bool ismine = false;
        if (pwallet && pwallet->sparkWallet) {
            ismine = pwallet->sparkWallet->isAddressMine(currentAddress);
        }

        ret.push_back(Pair("ismine", ismine));
#endif
    }
    return ret;
}

// Needed even with !ENABLE_WALLET, to pass (ignored) pointers around
class CWallet;

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(CWallet * const pwallet, const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw std::runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw std::runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw std::runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Firo address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwallet && address.IsValid()) {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw std::runtime_error(
                    strprintf("%s does not refer to a key",ks));
            CPubKey vchPubKey;
            if (!pwallet->GetPubKey(keyID, vchPubKey)) {
                throw std::runtime_error(
                    strprintf("no full public key for address %s",ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw std::runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw std::runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw std::runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw std::runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

UniValue mnsync(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "evoznsync [status|next|reset]\n"
            "Returns the sync status, updates to the next step or resets it entirely.\n"
        );

    std::string strMode = request.params[0].get_str();

    if(strMode == "status") {
        UniValue objStatus(UniValue::VOBJ);
        objStatus.push_back(Pair("AssetID", masternodeSync.GetAssetID()));
        objStatus.push_back(Pair("AssetName", masternodeSync.GetAssetName()));
        objStatus.push_back(Pair("AssetStartTime", masternodeSync.GetAssetStartTime()));
        objStatus.push_back(Pair("Attempt", masternodeSync.GetAttempt()));
        objStatus.push_back(Pair("IsBlockchainSynced", masternodeSync.IsBlockchainSynced()));
        objStatus.push_back(Pair("IsSynced", masternodeSync.IsSynced()));
        objStatus.push_back(Pair("IsFailed", masternodeSync.IsFailed()));
        return objStatus;
    }

    if(strMode == "next")
    {
        masternodeSync.SwitchToNextAsset(*g_connman);
        return "sync updated to " + masternodeSync.GetAssetName();
    }

    if(strMode == "reset")
    {
        masternodeSync.Reset();
        masternodeSync.SwitchToNextAsset(*g_connman);
        return "success";
    }
    return "failure";
}

UniValue createmultisig(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
#else
    CWallet * const pwallet = NULL;
#endif

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2)
    {
        std::string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are Firo addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) Firo address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(pwallet, request.params);
    CScriptID innerID(inner);
    CBitcoinAddress address(innerID);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Firo address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}

UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivkey);
    if (!fGood)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    CKey key = vchSecret.GetKey();
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue verifyprivatetxown(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
                "verifyprivatetxown \"txid\" \"signature\" \"message\"\n"
                "\nVerify a lelantus tx ownership\n"
                "\nArguments:\n"
                "1. \"txid\"        (string, required) Txid, in which we spend lelantus coins.\n"
                "2. \"proof\"       (string, required) The signatures of the message encoded in base 64\n"
                "3. \"message\"     (string, required) The message that was signed.\n"
                "\nResult:\n"
                "true|false   (boolean) If the signature is verified or not.\n"
                "\nExamples:\n"
                "\nVerify the signature\n"
                + HelpExampleCli("verifyprivatetxown", "\"34df0ec7bcc8a2bda2c0df41ac560172d974c56ffc9adc0e2377d0fc54b4e8f9\" \"signature\" \"my message\"") +
                "\nAs json rpc\n"
                + HelpExampleRpc("verifyprivatetxown", "\"34df0ec7bcc8a2bda2c0df41ac560172d974c56ffc9adc0e2377d0fc54b4e8f9\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strTxId  = request.params[0].get_str();
    std::string strProof = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    uint256 txid = uint256S(strTxId);
    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strProof.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    return VerifyPrivateTxOwn(txid, vchSig, strMessage);
}


UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all callsites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM));
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

bool getAddressFromIndex(AddressType const & type, const uint160 &hash, std::string &address)
{
    if (type == AddressType::payToScriptHash) {
        address = CBitcoinAddress(CScriptID(hash)).ToString();
    } else if (type == AddressType::payToPubKeyHash || type == AddressType::payToExchangeAddress) {
        address = CBitcoinAddress(CKeyID(hash)).ToString();
    } else {
        return false;
    }
    return true;
}

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, AddressType> > &addresses)
{
    if (params[0].isStr()) {
        CBitcoinAddress address(params[0].get_str());
        uint160 hashBytes;
        AddressType type = AddressType::unknown;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else if (params[0].isObject()) {

        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {

            CBitcoinAddress address(it->get_str());
            uint160 hashBytes;
            AddressType type = AddressType::unknown;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

namespace {
void handleSingleAddress(const UniValue& uniAddress, std::vector<std::pair<uint160, AddressType> > &addresses)
{
    std::string const addr = uniAddress.get_str();
    if(zerocoin::utils::isZerocoinMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::zerocoinMint));
    } else if(zerocoin::utils::isZerocoinSpend(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::zerocoinSpend));
    } else if(zerocoin::utils::isZerocoin(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::zerocoinMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::zerocoinSpend));

    } else if(zerocoin::utils::isSigmaMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sigmaMint));
    } else if(zerocoin::utils::isSigmaSpend(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sigmaSpend));
    } else if(zerocoin::utils::isSigma(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sigmaMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::sigmaSpend));

    } else if(zerocoin::utils::isLelantusMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusMint));
    } else if(zerocoin::utils::isLelantusJMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusJMint));
    } else if(zerocoin::utils::isLelantusJSplit(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusJSplit));
    } else if(zerocoin::utils::isLelantus(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusJMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::lelantusJSplit));

    } else if(zerocoin::utils::isSparkMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sparkMint));
    } else if(zerocoin::utils::isSparkSMint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sparksMint));
    } else if(zerocoin::utils::isSparkSpend(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sparkSpend));
    } else if(zerocoin::utils::isSpark(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::sparkMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::sparksMint));
        addresses.push_back(std::make_pair(uint160(), AddressType::sparkSpend));

    } else if(zerocoin::utils::isZerocoinRemint(addr)) {
        addresses.push_back(std::make_pair(uint160(), AddressType::zerocoinRemint));
    } else {
        CBitcoinAddress address(addr);
        uint160 hashBytes;
        AddressType type = AddressType::unknown;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    }
}
}

bool getZerocoinAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, AddressType> > &addresses)
{
    if (params[0].isStr()) {
        handleSingleAddress(params[0], addresses);
    } else if (params[0].isObject()) {

        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
            handleSingleAddress(*it, addresses);
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                   std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b) {
    return a.second.time < b.second.time;
}

UniValue getaddressmempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaddressmempool\n"
                        "\nReturns all mempool deltas for an address (requires addressindex to be enabled).\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"addresses\"\n"
                        "    [\n"
                        "      \"address\"  (string) The base58check encoded address\n"
                        "      ,...\n"
                        "    ]\n"
                        "}\n"
                        "\nResult:\n"
                        "[\n"
                        "  {\n"
                        "    \"address\"  (string) The base58check encoded address\n"
                        "    \"txid\"  (string) The related txid\n"
                        "    \"index\"  (number) The related input or output index\n"
                        "    \"satoshis\"  (number) The difference of duffs\n"
                        "    \"timestamp\"  (number) The time the transaction entered the mempool (seconds)\n"
                        "    \"prevtxid\"  (string) The previous txid (if spending)\n"
                        "    \"prevout\"  (string) The previous transaction output index (if spending)\n"
                        "  }\n"
                        "]\n"
                        "\nExamples:\n"
                + HelpExampleCli("getaddressmempool", "'{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}'")
                + HelpExampleRpc("getaddressmempool", "{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}")
        );

    std::vector<std::pair<uint160, AddressType> > addresses;

    if (!getZerocoinAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > indexes;

    if (!mempool.getAddressIndex(addresses, indexes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
    }

    std::sort(indexes.begin(), indexes.end(), timestampSort);

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::iterator it = indexes.begin(); it != indexes.end(); it++) {

        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.addressBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("address", address));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("satoshis", it->second.amount));
        delta.push_back(Pair("timestamp", it->second.time));
        if (it->second.amount < 0) {
            delta.push_back(Pair("prevtxid", it->second.prevhash.GetHex()));
            delta.push_back(Pair("prevout", (int)it->second.prevout));
        }
        result.push_back(delta);
    }

    return result;
}

UniValue getaddressutxos(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaddressutxos\n"
                        "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"addresses\"\n"
                        "    [\n"
                        "      \"address\"  (string) The base58check encoded address\n"
                        "      ,...\n"
                        "    ]\n"
                        "}\n"
                        "\nResult\n"
                        "[\n"
                        "  {\n"
                        "    \"address\"  (string) The address base58check encoded\n"
                        "    \"txid\"  (string) The output txid\n"
                        "    \"outputIndex\"  (number) The output index\n"
                        "    \"script\"  (string) The script hex encoded\n"
                        "    \"satoshis\"  (number) The number of duffs of the output\n"
                        "    \"height\"  (number) The block height\n"
                        "  }\n"
                        "]\n"
                        "\nExamples:\n"
                + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}'")
                + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}")
        );

    std::vector<std::pair<uint160, AddressType> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint160, AddressType> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        result.push_back(output);
    }

    return result;
}

UniValue getaddressdeltas(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1 || !request.params[0].isObject())
        throw std::runtime_error(
                "getaddressdeltas\n"
                        "\nReturns all changes for an address (requires addressindex to be enabled).\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"addresses\"\n"
                        "    [\n"
                        "      \"address\"  (string) The base58check encoded address\n"
                        "      ,...\n"
                        "    ]\n"
                        "  \"start\" (number) The start block height\n"
                        "  \"end\" (number) The end block height\n"
                        "}\n"
                        "\nResult:\n"
                        "[\n"
                        "  {\n"
                        "    \"satoshis\"  (number) The difference of duffs\n"
                        "    \"txid\"  (string) The related txid\n"
                        "    \"index\"  (number) The related input or output index\n"
                        "    \"blockindex\"  (number) The related block index\n"
                        "    \"height\"  (number) The block height\n"
                        "    \"address\"  (string) The base58check encoded address\n"
                        "  }\n"
                        "]\n"
                        "\nExamples:\n"
                + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}'")
                + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}")
        );


    UniValue startValue = find_value(request.params[0].get_obj(), "start");
    UniValue endValue = find_value(request.params[0].get_obj(), "end");

    int start = 0;
    int end = 0;

    if (startValue.isNum() && endValue.isNum()) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint160, AddressType> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, AddressType> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("satoshis", it->second));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("blockindex", (int)it->first.txindex));
        delta.push_back(Pair("height", it->first.blockHeight));
        delta.push_back(Pair("address", address));
        result.push_back(delta);
    }

    return result;
}

UniValue getaddressbalance(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaddressbalance\n"
                        "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"addresses\"\n"
                        "    [\n"
                        "      \"address\"  (string) The base58check encoded address\n"
                        "      ,...\n"
                        "    ]\n"
                        "}\n"
                        "\nResult:\n"
                        "{\n"
                        "  \"balance\"  (string) The current balance in duffs\n"
                        "  \"received\"  (string) The total number of duffs received (including change)\n"
                        "}\n"
                        "\nExamples:\n"
                + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}'")
                + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}")
        );

    std::vector<std::pair<uint160, AddressType> > addresses;

    if (!getZerocoinAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, AddressType> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    CAmount balance = 0;
    CAmount received = 0;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        if (it->second > 0) {
            received += it->second;
        }
        balance += it->second;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("balance", balance));
    result.push_back(Pair("received", received));

    return result;

}

UniValue getanonymityset(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "getanonymityset\n"
                        "\nReturns the anonymity set and latest block hash.\n"
                        "\nArguments:\n"
                        "{\n"
                        "      \"coinGroupId\"  (int)\n"
                        "      \"startBlockHash\"    (string)\n" // if this is empty it returns the full set
                        "}\n"
                        "\nResult:\n"
                        "{\n"
                        "  \"blockHash\"   (string) Latest block hash for anonymity set\n"
                        "  \"setHash\"   (string) Anonymity set hash\n"
                        "  \"mints\" (Pair<string,Pair<string,Pair<<string, uint64_t>>) Serialized GroupElements paired with txhash which is paired with mint tag and mint value\n"
                        "}\n"
                + HelpExampleCli("getanonymityset", "\"1\"" "{\"ca511f07489e35c9bc60ca62c82de225ba7aae7811ce4c090f95aa976639dc4e\"}")
                + HelpExampleRpc("getanonymityset", "\"1\"" "{\"ca511f07489e35c9bc60ca62c82de225ba7aae7811ce4c090f95aa976639dc4e\"}")
        );


    int coinGroupId;
    std::string startBlockHash;
    try {
        coinGroupId = std::stol(request.params[0].get_str());
        startBlockHash = request.params[1].get_str();
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    if(!GetBoolArg("-mobile", false)){
        throw std::runtime_error(std::string("Please rerun Firo with -mobile "));
    }

    uint256 blockHash;
    std::vector<std::pair <lelantus::PublicCoin,std::pair<lelantus::MintValueData, uint256>>> coins;
    std::vector<unsigned char> setHash;

    {
        LOCK(cs_main);
        lelantus::CLelantusState* lelantusState = lelantus::CLelantusState::GetState();
        lelantusState->GetCoinsForRecovery(
                &chainActive,
                chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1),
                coinGroupId,
                startBlockHash,
                blockHash,
                coins,
                setHash);
    }

    UniValue ret(UniValue::VOBJ);
    UniValue mints(UniValue::VARR);

    int i = 0;
    for (const auto& coin : coins) {
        std::vector<unsigned char> vch = coin.first.getValue().getvch();
        std::vector<UniValue> data;
        data.push_back(EncodeBase64(vch.data(), size_t(34)));
        data.push_back(EncodeBase64(coin.second.second.begin(), coin.second.second.size()));
        if (coin.second.first.isJMint) {
            data.push_back(EncodeBase64(coin.second.first.encryptedValue.data(), coin.second.first.encryptedValue.size()));
        } else {
            data.push_back(coin.second.first.amount);
        }
        data.push_back(EncodeBase64(coin.second.first.txHash.begin(), coin.second.first.txHash.size()));

        UniValue entity(UniValue::VARR);
        entity.push_backV(data);
        mints.push_back(entity);
        i++;
    }

    ret.push_back(Pair("blockHash", EncodeBase64(blockHash.begin(), blockHash.size())));
    ret.push_back(Pair("setHash", UniValue(EncodeBase64(setHash.data(), setHash.size()))));
    ret.push_back(Pair("coins", mints));

    return ret;
}

UniValue getmintmetadata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getmintmetadata\n"
                        "\nReturns the anonymity set id and nHeight of mint.\n"
                        "\nArguments:\n"
                        "  \"mints\"\n"
                        "    [\n"
                        "      {\n"
                        "        \"pubcoin\" (string) The PubCoin value\n"
                        "      }\n"
                        "      ,...\n"
                        "    ]\n"
                        "\nResult:\n"
                        "{\n"
                        "  \"metadata\"   (Pair<string,int>) nHeight and id for each pubcoin\n"
                        "}\n"
                + HelpExampleCli("getmintmetadata", "'{\"mints\": [{\"denom\":5000000, \"pubcoin\":\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"}]}'")
                + HelpExampleRpc("getmintmetadata", "{\"mints\": [{\"denom\":5000000, \"pubcoin\":\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"}]}")
        );

    UniValue mintValues = find_value(request.params[0].get_obj(), "mints");
    if (!mintValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "mints is expected to be an array");
    }
    lelantus::CLelantusState* lelantusState = lelantus::CLelantusState::GetState();
    UniValue ret(UniValue::VARR);
    for(UniValue const & mintData : mintValues.getValues()){
        std::vector<unsigned char> serializedCoin = ParseHex(find_value(mintData, "pubcoin").get_str().c_str());

        secp_primitives::GroupElement pubCoin;
        pubCoin.deserialize(serializedCoin.data());

        std::pair<int, int> coinHeightAndId;
        {
            LOCK(cs_main);
            coinHeightAndId = lelantusState->GetMintedCoinHeightAndId(lelantus::PublicCoin(pubCoin));
        }
        UniValue metaData(UniValue::VOBJ);
        metaData.pushKV(std::to_string(coinHeightAndId.first), coinHeightAndId.second);
        ret.push_back(metaData);
    }
    return ret;
}

UniValue getusedcoinserials(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getusedcoinserials\n"
                "\nReturns the set of used coin serial.\n"
                "\nArguments:\n"
                "{\n"
                "      \"startNumber \"  (int) Number of elements already existing on user side\n"
                "}\n"
                "\nResult:\n"
                "{\n"
                "  \"serials\" (std::string[]) array of Serialized Scalars\n"
                "}\n"
        );

    int startNumber;
    try {
        startNumber = std::stol(request.params[0].get_str());
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    lelantus::CLelantusState* lelantusState = lelantus::CLelantusState::GetState();
    std::unordered_map<Scalar, int>  serials;
    {
        LOCK(cs_main);
        serials = lelantusState->GetSpends();
    }

    UniValue serializedSerials(UniValue::VARR);
    int i = 0;
    for ( auto it = serials.begin(); it != serials.end(); ++it, ++i) {
        if ((serials.size() - i - 1) < startNumber)
            continue;
        std::vector<unsigned char> serialized;
        serialized.resize(32);
        it->first.serialize(serialized.data());
        serializedSerials.push_back(EncodeBase64(serialized.data(), 32));
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("serials", serializedSerials));

    return ret;
}

UniValue getfeerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "getfeerate\n"
                "\nReturns the fee rate.\n"
                "\nResult:\n"
                "{\n"
                "  \"rate\" (int) Fee rate\n"
                "}\n"
        );

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("rate", ::minRelayTxFee.GetFeePerK()));

    return ret;
}

UniValue getlatestcoinid(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "getlatestcoinid\n"
                "\nReturns the set of used coin serial.\n"
                "\nResult:\n"
                "{\n"
                "  [\n"
                "      {\n"
                "        \"coinGroupId\" (int) The latest group id\n"
                "      }\n"
                "      ,...\n"
                "    ]\n"
                "}\n"
        );

    lelantus::CLelantusState* lelantusState = lelantus::CLelantusState::GetState();
    int latestCoinId;
    {
        LOCK(cs_main);
        latestCoinId = lelantusState->GetLatestCoinID();
    }

    return UniValue(latestCoinId);
}

UniValue getsparkanonymityset(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "getsparkanonymityset\n"
                "\nReturns the anonymity set and latest block hash.\n"
                "\nArguments:\n"
                "{\n"
                "      \"coinGroupId\"  (int)\n"
                "      \"startBlockHash\"    (string)\n" // if this is empty it returns the full set
                "}\n"
                "\nResult:\n"
                "{\n"
                "  \"blockHash\"   (string) Latest block hash for anonymity set\n"
                "  \"setHash\"   (string) Anonymity set hash\n"
                "  \"mints\" (Pair<string, string>) Serialized Spark coin paired with txhash\n"
                "}\n"
                + HelpExampleCli("getsparkanonymityset", "\"1\" " "\"ca511f07489e35c9bc60ca62c82de225ba7aae7811ce4c090f95aa976639dc4e\"")
                + HelpExampleRpc("getsparkanonymityset", "\"1\" " "\"ca511f07489e35c9bc60ca62c82de225ba7aae7811ce4c090f95aa976639dc4e\"")
        );


    int coinGroupId;
    std::string startBlockHash;
    try {
        coinGroupId = std::stol(request.params[0].get_str());
        startBlockHash = request.params[1].get_str();
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    if(!GetBoolArg("-mobile", false)){
        throw std::runtime_error(std::string("Please rerun Firo with -mobile "));
    }

    uint256 blockHash;
    std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>> coins;
    std::vector<unsigned char> setHash;

    {
        LOCK(cs_main);
        spark::CSparkState* sparkState = spark::CSparkState::GetState();
        sparkState->GetCoinsForRecovery(
                &chainActive,
                chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1),
                coinGroupId,
                startBlockHash,
                blockHash,
                coins,
                setHash);
    }

    UniValue ret(UniValue::VOBJ);
    UniValue mints(UniValue::VARR);

    for (const auto& coin : coins) {
        CDataStream serializedCoin(SER_NETWORK, PROTOCOL_VERSION);
        serializedCoin << coin;
        std::vector<unsigned char> vch(serializedCoin.begin(), serializedCoin.end());

        std::vector<UniValue> data;
        data.push_back(EncodeBase64(vch.data(), size_t(vch.size()))); // coin
        data.push_back(EncodeBase64(coin.second.first.begin(), coin.second.first.size())); // tx hash
        data.push_back(EncodeBase64(coin.second.second.data(), coin.second.second.size())); // spark serial context

        UniValue entity(UniValue::VARR);
        entity.push_backV(data);
        mints.push_back(entity);
    }

    ret.push_back(Pair("blockHash", EncodeBase64(blockHash.begin(), blockHash.size())));
    ret.push_back(Pair("setHash", UniValue(EncodeBase64(setHash.data(), setHash.size()))));
    ret.push_back(Pair("coins", mints));

    return ret;
}

UniValue getsparkmintmetadata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getmintmetadata\n"
                "\nReturns the anonymity set id and nHeight of mint.\n"
                "\nArguments:\n"
                "  \"coinHashes\"\n"
                "    [\n"
                "      {\n"
                "        \"coinHash\" (string) The hash of the spark mint\n"
                "      }\n"
                "      ,...\n"
                "    ]\n"
                "\nResult:\n"
                "{\n"
                "  \"metadata\"   (Pair<string,int>) nHeight and id for each coin\n"
                "}\n"
                + HelpExampleCli("getsparkmintmetadata", "'{\"coinHashes\": [\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\",\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"]}'")
                + HelpExampleRpc("getsparkmintmetadata", "{\"coinHashes\": [\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\",\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"]}")

        );

    UniValue coinHashes = find_value(request.params[0].get_obj(), "coinHashes");
    if (!coinHashes.isArray()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "mints is expected to be an array");
    }

    spark::CSparkState* sparkState =  spark::CSparkState::GetState();

    UniValue ret(UniValue::VARR);
    for(UniValue const & element : coinHashes.getValues()) {
        uint256 coinHash;
        coinHash.SetHex(element.get_str());
        spark::Coin coin(spark::Params::get_default());
        if(!sparkState->HasCoinHash(coin, coinHash))
            continue;

        std::pair<int, int> coinHeightAndId;
        {
            LOCK(cs_main);
            coinHeightAndId = sparkState->GetMintedCoinHeightAndId(coin);
        }
        UniValue metaData(UniValue::VOBJ);
        metaData.pushKV(std::to_string(coinHeightAndId.first), coinHeightAndId.second);
        ret.push_back(metaData);
    }

    return ret;
}

UniValue getusedcoinstags(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getusedcoinstags\n"
                "\nReturns the set of used coin tags.\n"
                "\nArguments:\n"
                "{\n"
                "      \"startNumber \"  (int) Number of elements already existing on user side\n"
                "}\n"
                "\nResult:\n"
                "{\n"
                "  \"tags\" (std::string[]) array of Serialized GroupElements\n"
                "}\n"
        );

    int startNumber;
    try {
        startNumber = std::stol(request.params[0].get_str());
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    spark::CSparkState* sparkState =  spark::CSparkState::GetState();
    std::unordered_map<GroupElement, int, spark::CLTagHash>  tags;
    {
        LOCK(cs_main);
        tags = sparkState->GetSpends();
    }
    UniValue serializedTags(UniValue::VARR);
    int i = 0;
    for ( auto it = tags.begin(); it != tags.end(); ++it, ++i) {
        if ((tags.size() - i - 1) < startNumber)
            continue;
        std::vector<unsigned char> serialized;
        serialized.resize(34);
        it->first.serialize(serialized.data());
        serializedTags.push_back(EncodeBase64(serialized.data(), 34));
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("tags", serializedTags));

    return ret;
}

UniValue getusedcoinstagstxhashes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getusedcoinstagstxhashes\n"
                "\nReturns the set of used coin tags paired with tx ids in which it was spent, this rpc required -mobile argument, \n"
                "\nArguments:\n"
                "{\n"
                "      \"startNumber \"  (int) Number of elements already existing on user side\n"
                "}\n"
                "\nResult:\n"
                "{\n"
                "  \"tags\" (std::string[]) array of Serialized GroupElements paired with unit256 (tx ids) \n"
                "}\n"
        );

    int startNumber;
    try {
        startNumber = std::stol(request.params[0].get_str());
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    spark::CSparkState* sparkState =  spark::CSparkState::GetState();
    std::unordered_map<GroupElement, int, spark::CLTagHash>  tags;
    std::unordered_map<uint256, uint256> ltagTxhash;
    {
        LOCK(cs_main);
        tags = sparkState->GetSpends();
        ltagTxhash = sparkState->GetSpendTxIds();
    }
    UniValue serializedTagsTxIds(UniValue::VARR);
    int i = 0;
    for ( auto it = tags.begin(); it != tags.end(); ++it, ++i) {
        if ((tags.size() - i - 1) < startNumber)
            continue;
        std::vector<unsigned char> serialized;
        serialized.resize(34);
        it->first.serialize(serialized.data());
        std::vector<UniValue> data;
        data.push_back(EncodeBase64(serialized.data(), 34));
        uint256 txid;
        uint256 ltagHash = primitives::GetLTagHash(it->first);
        if (ltagTxhash.count(ltagHash) > 0)
            txid = ltagTxhash[ltagHash];
        data.push_back(EncodeBase64(txid.begin(), txid.size()));
        UniValue entity(UniValue::VARR);
        entity.push_backV(data);
        serializedTagsTxIds.push_back(entity);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("tagsandtxids", serializedTagsTxIds));

    return ret;
}

UniValue getsparklatestcoinid(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "getlatestcoinid\n"
                "\nReturns the last coin group ID for Spark.\n"
                "\nResult:\n"
                "{\n"
                "  [\n"
                "      {\n"
                "        \"coinGroupId\" (int) The latest group id\n"
                "      }\n"
                "      ,...\n"
                "    ]\n"
                "}\n"
        );

    spark::CSparkState* sparkState =  spark::CSparkState::GetState();
    int latestCoinId;
    {
        LOCK(cs_main);
        latestCoinId = sparkState->GetLatestCoinID();
    }

    return UniValue(latestCoinId);
}

UniValue getmempoolsparktxids(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "getmempoolsparktxids\n"
                "\nReturns spark transaction ids existing in the mempool.\n"
        );

    UniValue result(UniValue::VARR);
    std::vector<TxMempoolInfo> txs = mempool.infoAll();
    for (auto it = txs.begin(); it != txs.end(); it++) {
        if (!it->tx->IsSparkTransaction())
            continue;
        result.push_back(EncodeBase64(it->tx->GetHash().begin(), it->tx->GetHash().size()));
    }

    return result;
}

UniValue getmempoolsparktxs(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getmempoolsparktxs\n"
                "\nReturns spark metadata for each transaction id, in case tx already was removed from mempool, nothing will be returned for specific id.\n"
                "\nArguments:\n"
                "  \"txids\"\n"
                "    [\n"
                "      {\n"
                "        \"txid\" (string) The transaction hash\n"
                "      }\n"
                "      ,...\n"
                "    ]\n"
                "\nResult:\n"
                "txid , {\n"
                "  \"lTags\"   Array of GroupElements, or a string 'MintTX' in case it is mint tx\n"
                "  \"serial_context\"   byte array which is used to identify the output spark coins, it is unique for each ix\n"
                "  \"coins\" Array of serialized spar::Coin elements, the output coins of the tx\n"
                "}\n"
                + HelpExampleCli("getmempoolsparktxs", "'{\"txids\": [\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\",\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"]}'")
                + HelpExampleRpc("getmempoolsparktxs", "{\"txids\": [\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\",\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"]}")

        );

    UniValue txids = find_value(request.params[0].get_obj(), "txids");

    UniValue result(UniValue::VOBJ);
    for(UniValue const & element : txids.getValues()){
        uint256 txid;
        txid.SetHex(element.get_str());
        CTransactionRef tx = mempool.get(txid);
        if (tx == nullptr || !tx->IsSparkTransaction())
            continue;

        UniValue data(UniValue::VOBJ);
        std::vector<UniValue> lTags_;
        UniValue lTags_json(UniValue::VARR);
        if (tx->IsSparkSpend())
        {
            try {
                spark::SpendTransaction spend = spark::ParseSparkSpend(*tx);
                auto lTags = spend.getUsedLTags();
                for ( auto it = lTags.begin(); it != lTags.end(); ++it) {
                    std::vector<unsigned char> serialized;
                    serialized.resize(34);
                    it->serialize(serialized.data());
                    lTags_.push_back(EncodeBase64(serialized.data(), 34));
                }
            } catch (const std::exception &) {
                continue;
            }
        } else {
            lTags_.push_back("MintTX");
        }
        lTags_json.push_backV(lTags_);

        data.push_back(Pair("lTags ", lTags_json)); // Spend lTags for corresponding tx,

        std::vector<unsigned char> serial_context = spark::getSerialContext(*tx);
        UniValue serial_context_json(UniValue::VARR);
        serial_context_json.push_back(EncodeBase64(serial_context.data(), serial_context.size()));
        data.push_back(Pair("serial_context", serial_context_json)); // spark serial context

        std::vector<spark::Coin>  coins = spark::GetSparkMintCoins(*tx);
        std::vector<UniValue> serialized_coins;
        UniValue serialized_json(UniValue::VARR);
        for (auto& coin: coins) {
            CDataStream serializedCoin(SER_NETWORK, PROTOCOL_VERSION);
            serializedCoin << coin;
            std::vector<unsigned char> vch(serializedCoin.begin(), serializedCoin.end());
            serialized_coins.push_back(EncodeBase64(vch.data(), size_t(vch.size()))); // coi
        }
        serialized_json.push_backV(serialized_coins);
        data.push_back(Pair("coins", serialized_json));

        bool fLLMQLocked = llmq::quorumInstantSendManager->IsLocked(txid);
        data.push_back(Pair("isLocked", fLLMQLocked));

        result.push_back(Pair(EncodeBase64(txid.begin(), txid.size()), data));
    }

    return result;
}

UniValue checkifmncollateral(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "checkifmncollateral\n"
                "\nReturns bool value.\n"
                "\nArguments:\n"
                "  \"txHash\"\n"
                "  \"index\"\n"
                + HelpExampleCli("checkifmncollateral", "\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\""  "\"0\" ")
                + HelpExampleRpc("checkifmncollateral", "\"b476ed2b374bb081ea51d111f68f0136252521214e213d119b8dc67b92f5a390\"" "\"0\" ")
        );

    std::string strTxId;
    int index;

    try {
        strTxId = request.params[0].get_str();
        index = std::stol(request.params[1].get_str());
    } catch (std::logic_error const & e) {
        throw std::runtime_error(std::string("An exception occurred while parsing parameters: ") + e.what());
    }

    uint256 txid = uint256S(strTxId);

    CTransactionRef tx;
    uint256 hashBlock;
    if(!GetTransaction(txid, tx, Params().GetConsensus(), hashBlock, true))
        throw std::runtime_error("Unknown transaction.");

    auto mnList = deterministicMNManager->GetListAtChainTip();
    COutPoint o(txid, index);
    bool fMnExists = deterministicMNManager->IsProTxWithCollateral(tx, index) || mnList.HasMNByCollateral(o);
    return UniValue(fMnExists);
}

UniValue getaddresstxids(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getaddresstxids\n"
                        "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"addresses\"\n"
                        "    [\n"
                        "      \"address\"  (string) The base58check encoded address\n"
                        "      ,...\n"
                        "    ]\n"
                        "  \"start\" (number) The start block height\n"
                        "  \"end\" (number) The end block height\n"
                        "}\n"
                        "\nResult:\n"
                        "[\n"
                        "  \"transactionid\"  (string) The transaction id\n"
                        "  ,...\n"
                        "]\n"
                        "\nExamples:\n"
                + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}'")
                + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"]}")
        );

    std::vector<std::pair<uint160, AddressType> > addresses;

    if (!getZerocoinAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (request.params[0].isObject()) {
        UniValue startValue = find_value(request.params[0].get_obj(), "start");
        UniValue endValue = find_value(request.params[0].get_obj(), "end");
        if (startValue.isNum() && endValue.isNum()) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, AddressType> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;

}

UniValue getspentinfo(const JSONRPCRequest& request)
{

    if (request.fHelp || request.params.size() != 1 || !request.params[0].isObject())
        throw std::runtime_error(
                "getspentinfo\n"
                        "\nReturns the txid and index where an output is spent.\n"
                        "\nArguments:\n"
                        "{\n"
                        "  \"txid\" (string) The hex string of the txid\n"
                        "  \"index\" (number) The start block height\n"
                        "}\n"
                        "\nResult:\n"
                        "{\n"
                        "  \"txid\"  (string) The transaction id\n"
                        "  \"index\"  (number) The spending input index\n"
                        "  ,...\n"
                        "}\n"
                        "\nExamples:\n"
                + HelpExampleCli("getspentinfo", "'{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'")
                + HelpExampleRpc("getspentinfo", "{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}")
        );

    UniValue txidValue = find_value(request.params[0].get_obj(), "txid");
    UniValue indexValue = find_value(request.params[0].get_obj(), "index");

    if (!txidValue.isStr() || !indexValue.isNum()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid txid or index");
    }

    uint256 txid = ParseHashV(txidValue, "txid");
    int outputIndex = indexValue.get_int();

    CSpentIndexKey key(txid, outputIndex);
    CSpentIndexValue value;

    if (!GetSpentIndex(key, value)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get spent info");
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", value.txid.GetHex()));
    obj.push_back(Pair("index", (int)value.inputIndex));
    obj.push_back(Pair("height", value.blockHeight));

    return obj;
}

UniValue gettotalsupply(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "gettotalsupply\n"
                        "\nReturns the total coin amount produced in the coinbase transactions up until the latest block.\n"
                        "\nArguments: none\n"
                        "\nResult:\n"
                        "{\n"
                        "  \"total\"  (string) The total supply in duffs\n"
                        "}\n"
                        "\nExamples:\n"
                + HelpExampleCli("gettotalsupply", "")
                + HelpExampleRpc("gettotalsupply", "")
        );

    CAmount total = 0;

    if(!pblocktree->ReadTotalSupply(total))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Cannot read the total supply from the database. This functionality requires -addressindex to be enabled. Enabling -addressindex requires reindexing.");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("total", total));

    return result;
}

UniValue getinfoex(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getinfoex\n"
            "An engineering version of getinfo. Takes significant time to finish.\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total firo balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "  \"moneysupply\": \"...\"      (numeric) current coinbase supply\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

    UniValue info = getinfo(request);

    CAmount total = 0;

    if(!pblocktree->ReadTotalSupply(total))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Cannot read the total supply from the database");

    info.push_back(Pair("moneysupply", total));

    return info;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("used", uint64_t(stats.used)));
    obj.push_back(Pair("free", uint64_t(stats.free)));
    obj.push_back(Pair("total", uint64_t(stats.total)));
    obj.push_back(Pair("locked", uint64_t(stats.locked)));
    obj.push_back(Pair("chunks_used", uint64_t(stats.chunks_used)));
    obj.push_back(Pair("chunks_free", uint64_t(stats.chunks_free)));
    return obj;
}

UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmemoryinfo\n"
            "Returns an object containing information about memory usage.\n"
            "\nResult:\n"
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("locked", RPCLockedMemoryInfo()));
    return obj;
}

UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "bitcoin-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getinfo",                &getinfo,                true,  {} }, /* uses wallet if enabled */
    { "control",            "getmemoryinfo",          &getmemoryinfo,          true,  {} },
    { "util",               "validateaddress",        &validateaddress,        true,  {"address"} }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         true,  {"nrequired","keys"} },
    { "util",               "verifymessage",          &verifymessage,          true,  {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, true,  {"privkey","message"} },

        /* Address index */
    { "addressindex",       "getaddressmempool",      &getaddressmempool,      true  },
    { "addressindex",       "getaddressutxos",        &getaddressutxos,        false },
    { "addressindex",       "getaddressdeltas",       &getaddressdeltas,       false },
    { "addressindex",       "getaddresstxids",        &getaddresstxids,        false },
    { "addressindex",       "getaddressbalance",      &getaddressbalance,      false },

    /* Znode features */
    { "firo",              "znsync",                 &mnsync,                 true,  {} },
    { "firo",              "evoznsync",              &mnsync,                 true,  {} },

    { "firo",              "verifyprivatetxown",      &verifyprivatetxown,      true,  {} },

    /* Not shown in help */
    { "hidden",             "getinfoex",              &getinfoex,              false },
    { "addressindex",       "gettotalsupply",         &gettotalsupply,         false },

        /* Mobile related */
    { "mobile",             "getanonymityset",        &getanonymityset,        false  },
    { "mobile",             "getmintmetadata",        &getmintmetadata,        true  },
    { "mobile",             "getusedcoinserials",     &getusedcoinserials,     false  },
    { "mobile",             "getfeerate",             &getfeerate,             true  },
    { "mobile",             "getlatestcoinid",        &getlatestcoinid,        true  },

        /* Mobile Spark */
    { "mobile",             "getsparkanonymityset",   &getsparkanonymityset, false },
    { "mobile",             "getsparkmintmetadata",   &getsparkmintmetadata, true  },
    { "mobile",             "getusedcoinstags",       &getusedcoinstags,     false },
    { "mobile",             "getusedcoinstagstxhashes", &getusedcoinstagstxhashes, false },
    { "mobile",             "getsparklatestcoinid",   &getsparklatestcoinid, true  },
    { "mobile",             "getmempoolsparktxids",   &getmempoolsparktxids, true },
    { "mobile",             "getmempoolsparktxs",     &getmempoolsparktxs,       true  },

    { "mobile",             "checkifmncollateral",   &checkifmncollateral, false  },

    { "hidden",             "setmocktime",            &setmocktime,            true,  {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                  true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
