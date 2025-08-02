// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "libspark/keys.h"
#include "rpc/server.h"
#include "init.h"
#include "validation.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"
#include "merkleblock.h"
#include "core_io.h"
#include "authhelper.h"

#include "rpcwallet.h"
#include "rpcdump.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

bool EnsureWalletIsAvailable(bool avoidException);

std::string static EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) {
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) |
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

UniValue importprivkey(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "importprivkey \"firoprivkey\" ( \"label\" ) ( rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"firoprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nImport using default blank label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );


    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    const CHDChain& chain = pwallet->GetHDChain();
    if(chain.nVersion == chain.VERSION_WITH_BIP39){
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets and private keys is disabled for mnemonic-enabled wallets."
                                             "To import your dump file, create a non-mnemonic wallet by setting \"usemnemonic=0\" in your firo.conf file, after backing up and removing your existing wallet.");
    }


    std::string strSecret = request.params[0].get_str();
    std::string strLabel = "";
    if (request.params.size() > 1)
        strLabel = request.params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (request.params.size() > 2)
        fRescan = request.params[2].get_bool();

    if (fRescan && fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        pwallet->MarkDirty();
        pwallet->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwallet->HaveKey(vchAddress)) {
            return NullUniValue;
        }

        pwallet->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwallet->AddKeyPubKey(key, pubkey)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
        }

        // whenever a key is imported, we need to scan the whole chain
        pwallet->UpdateTimeFirstKey(1);

        if (fRescan) {
            pwallet->ScanForWalletTransactions(chainActive.Genesis(), true);
        }
    }

    return NullUniValue;
}

void ImportAddress(CWallet *, const CBitcoinAddress& address, const std::string& strLabel);
void ImportScript(CWallet * const pwallet, const CScript& script, const std::string& strLabel, bool isRedeemScript)
{
    if (!isRedeemScript && ::IsMine(*pwallet, script) == ISMINE_SPENDABLE) {
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
    }

    pwallet->MarkDirty();

    if (!pwallet->HaveWatchOnly(script) && !pwallet->AddWatchOnly(script, 0 /* nCreateTime */)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
    }

    if (isRedeemScript) {
        if (!pwallet->HaveCScript(script) && !pwallet->AddCScript(script)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        }
        ImportAddress(pwallet, CBitcoinAddress(CScriptID(script)), strLabel);
    } else {
        CTxDestination destination;
        if (ExtractDestination(script, destination)) {
            pwallet->SetAddressBook(destination, strLabel, "receive");
        }
    }
}

void ImportAddress(CWallet * const pwallet, const CBitcoinAddress& address, const std::string& strLabel)
{
    CScript script = GetScriptForDestination(address.Get());
    ImportScript(pwallet, script, strLabel, false);
    // add to address book or update label
    if (address.IsValid())
        pwallet->SetAddressBook(address.Get(), strLabel, "receive");
}

UniValue importaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
        throw std::runtime_error(
            "importaddress \"address\" ( \"label\" rescan p2sh )\n"
            "\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"script\"           (string, required) The hex-encoded script (or address)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "4. p2sh                 (boolean, optional, default=false) Add the P2SH version of the script as well\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "If you have the full public key, you should call importpubkey instead of this.\n"
            "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
            "as change, and not show up in many RPCs.\n"
            "\nExamples:\n"
            "\nImport a script with rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myscript\", \"testing\", false")
        );


    std::string strLabel = "";
    if (request.params.size() > 1)
        strLabel = request.params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (request.params.size() > 2)
        fRescan = request.params[2].get_bool();

    if (fRescan && fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (request.params.size() > 3)
        fP2SH = request.params[3].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (address.IsValid()) {
        if (fP2SH)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
        ImportAddress(pwallet, address, strLabel);
    } else if (IsHex(request.params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(request.params[0].get_str()));
        ImportScript(pwallet, CScript(data.begin(), data.end()), strLabel, fP2SH);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address or script");
    }

    if (fRescan)
    {
        pwallet->ScanForWalletTransactions(chainActive.Genesis(), true);
        pwallet->ReacceptWalletTransactions();
    }

    return NullUniValue;
}

UniValue importprunedfunds(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "importprunedfunds\n"
            "\nImports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n"
            "\nArguments:\n"
            "1. \"rawtransaction\" (string, required) A raw transaction in hex funding an already-existing address in wallet\n"
            "2. \"txoutproof\"     (string, required) The hex output from gettxoutproof that contains the transaction\n"
        );

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();
    CWalletTx wtx(pwallet, MakeTransactionRef(std::move(tx)));

    CDataStream ssMB(ParseHexV(request.params[1], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    std::vector<uint256> vMatch;
    std::vector<unsigned int> vIndex;
    unsigned int txnIndex = 0;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) == merkleBlock.header.hashMerkleRoot) {

        LOCK(cs_main);

        if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

        std::vector<uint256>::const_iterator it;
        if ((it = std::find(vMatch.begin(), vMatch.end(), hashTx))==vMatch.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
        }

        txnIndex = vIndex[it - vMatch.begin()];
    }
    else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    wtx.nIndex = txnIndex;
    wtx.hashBlock = merkleBlock.header.GetHash();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->IsMine(wtx)) {
        pwallet->AddToWallet(wtx, false);
        return NullUniValue;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
}

UniValue removeprunedfunds(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "removeprunedfunds \"txid\"\n"
            "\nDeletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will effect wallet balances.\n"
            "\nArguments:\n"
            "1. \"txid\"           (string, required) The hex-encoded id of the transaction you are deleting\n"
            "\nExamples:\n"
            + HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());
    std::vector<uint256> vHash;
    vHash.push_back(hash);
    std::vector<uint256> vHashOut;

    if (pwallet->ZapSelectTx(vHash, vHashOut) != DB_LOAD_OK) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not properly delete the transaction.");
    }

    if(vHashOut.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction does not exist in wallet.");
    }

    return NullUniValue;
}

UniValue importpubkey(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
        throw std::runtime_error(
            "importpubkey \"pubkey\" ( \"label\" rescan )\n"
            "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"pubkey\"           (string, required) The hex-encoded public key\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport a public key with rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importpubkey", "\"mypubkey\", \"testing\", false")
        );


    std::string strLabel = "";
    if (request.params.size() > 1)
        strLabel = request.params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (request.params.size() > 2)
        fRescan = request.params[2].get_bool();

    if (fRescan && fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    if (!IsHex(request.params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(request.params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end());
    if (!pubKey.IsFullyValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwallet->cs_wallet);

    ImportAddress(pwallet, CBitcoinAddress(pubKey.GetID()), strLabel);
    ImportScript(pwallet, GetScriptForRawPubKey(pubKey), strLabel, false);

    if (fRescan)
    {
        pwallet->ScanForWalletTransactions(chainActive.Genesis(), true);
        pwallet->ReacceptWalletTransactions();
    }

    return NullUniValue;
}


UniValue importwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "importwallet \"filename\"\n"
            "\nImports keys from a wallet dump file (see dumpwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    const CHDChain& chain = pwallet->GetHDChain();
    if(chain.nVersion == chain.VERSION_WITH_BIP39){
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets and private keys is disabled for mnemonic-enabled wallets."
                                             "To import your dump file, create a non-mnemonic wallet by setting \"usemnemonic=0\" in your firo.conf file, after backing up and removing your existing wallet.");
    }


    std::ifstream file;
    file.open(request.params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime();

    bool fGood = true;

    bool fMintUpdate = false;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    CWalletDB walletdb(pwallet->strWalletFile);
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;

    pwallet->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) {
        pwallet->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;
        CBitcoinSecret vchSecret;

        if (!vchSecret.SetString(vstr[0]))
            continue;
        CKey key = vchSecret.GetKey();
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();
        if (pwallet->HaveKey(keyid)) {
            LogPrintf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString());
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;
        // CKeyMetadata
        bool fHd = false;
        std::string hdKeypath;
        CKeyID hdMasterKeyID;

        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (!masterKeyID.IsNull() && vstr[nStr] == "sigma=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
            if(!masterKeyID.IsNull() && boost::algorithm::starts_with(vstr[nStr], "hdKeypath=")){
                hdKeypath = vstr[nStr].substr(10);
                fHd = true;
            }
            if(!masterKeyID.IsNull() && boost::algorithm::starts_with(vstr[nStr], "hdMasterKeyID=")){
                hdMasterKeyID.SetHex(vstr[nStr].substr(14));
            }
        }
        LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString());

        // Add entry to mapKeyMetadata (Need to populate KeyMetadata before for it to be written to DB in the following call)
        if(!masterKeyID.IsNull()){
            pwallet->mapKeyMetadata[keyid].nCreateTime = nTime;
            if(fHd){
                pwallet->mapKeyMetadata[keyid].hdKeypath = hdKeypath;
                pwallet->mapKeyMetadata[keyid].hdMasterKeyID = hdMasterKeyID;
                pwallet->mapKeyMetadata[keyid].ParseComponents();
            }
        }

        if (!pwallet->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }

        if(!masterKeyID.IsNull() && fHd){
            // If change component in HD path is 2, this is a mint seed key. Add to mintpool. (Have to call after key addition)
            if(pwallet->mapKeyMetadata[keyid].nChange.first==2){
                pwallet->zwallet->RegenerateMintPoolEntry(walletdb, hdMasterKeyID, keyid, pwallet->mapKeyMetadata[keyid].nChild.first);
                fMintUpdate = true;
            }
        }
        if (fLabel)
            pwallet->SetAddressBook(keyid, strLabel, "receive");
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();
    pwallet->ShowProgress("", 100); // hide progress dialog in GUI
    pwallet->UpdateTimeFirstKey(nTimeBegin);

    CBlockIndex *pindex = chainActive.FindEarliestAtLeast(nTimeBegin - 7200);

    LogPrintf("Rescanning last %i blocks\n", pindex ? chainActive.Height() - pindex->nHeight + 1 : 0);
    pwallet->ScanForWalletTransactions(pindex);
    pwallet->MarkDirty();

    if(fMintUpdate){
        pwallet->zwallet->SyncWithChain();
        pwallet->zwallet->GetTracker().ListMints(false, false);
    }

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue;
}

UniValue dumpsparkviewkey(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        throw std::runtime_error("wallet not available");
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error("dumpviewkey\n\nDisplay our Spark View Key.\n");

  return {pwallet->GetSparkViewKeyStr()};
}

UniValue dumpprivkey(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "dumpprivkey \"address\"\n"
            "\nReveals the private key corresponding to 'address'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"address\"   (string, required) The Firo address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwallet->GetKey(keyID, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    return CBitcoinSecret(vchSecret).ToString();
}

UniValue dumpprivkey_firo(const JSONRPCRequest& request)
{
#ifndef UNSAFE_DUMPPRIVKEY
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "dumpprivkey \"firoaddress\"\n"
            "\nReveals the private key corresponding to 'firoaddress'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"firoaddress\"   (string, required) The Firo address for the private key\n"
            "2. \"one-time-auth-code\"   (string, optional) A one time authorization code received from a previous call of dumpprivkey"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("dumpprivkey", "\"myaddress\" \"12aB\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\",\"12aB\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
        );

    if (request.params.size() == 1 || !AuthorizationHelper::inst().authorize(__FUNCTION__ + request.params[0].get_str(), request.params[1].get_str()))
    {
        std::string warning =
            "WARNING! Your one time authorization code is: " + AuthorizationHelper::inst().generateAuthorizationCode(__FUNCTION__ + request.params[0].get_str()) + "\n"
            "This command exports your wallet private key. Anyone with this key has complete control over your funds. \n"
            "If someone asked you to type in this command, chances are they want to steal your coins. \n"
            "Firo team members will never ask for this command's output and it is not needed for masternode setup or diagnosis!\n"
            "\n"
            " Please seek help on one of our public channels. \n"
            " Telegram: https://t.me/firoproject \n"
            " Discord: https://discord.com/invite/TGZPRbRT3Y\n"
            " Reddit: https://www.reddit.com/r/FiroProject/\n"
            "\n"
            ;
        throw std::runtime_error(warning);
    }
#endif

    JSONRPCRequest newRequest;
    newRequest.params.setArray();
    newRequest.params.push_back(request.params[0]);

    return dumpprivkey(newRequest);
}

UniValue dumpwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    boost::filesystem::path filePath = request.params[0].get_str();
    filePath = boost::filesystem::absolute(filePath);

    std::ofstream file;
    file.open(filePath.string().c_str());

    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CTxDestination, int64_t> mapKeyBirth;
    const std::map<CKeyID, int64_t>& mapKeyPool = pwallet->GetAllReserveKeys();
    pwallet->GetKeyBirthTimes(mapKeyBirth);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (const auto& entry : mapKeyBirth) {
        if (const CKeyID* keyID = boost::get<CKeyID>(&entry.first)) { // set and test
            vKeyBirth.push_back(std::make_pair(entry.second, *keyID));
        }
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by Firo %s\n", CLIENT_BUILD);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime()));
    file << "\n";

    // add the base58check encoded extended master if the wallet uses HD
    MnemonicContainer mContainer = pwallet->GetMnemonicContainer();
    const CHDChain& chain = pwallet->GetHDChain();
    CKeyID masterKeyID = chain.masterKeyID;
    if(!mContainer.IsNull() && chain.nVersion >= CHDChain::VERSION_WITH_BIP39)
    {
        if(mContainer.IsCrypted())
        {
            if(!pwallet->DecryptMnemonicContainer(mContainer))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot decrypt hd chain");
        }

        SecureString mnemonic;
        //Don't dump mnemonic words in case user has set only hd seed during wallet creation
        if(mContainer.GetMnemonic(mnemonic))
            file << "# mnemonic: " << mnemonic << "\n";

        SecureVector seed = mContainer.GetSeed();
        file << "# HD seed: " << HexStr(seed) << "\n\n";

        CExtKey masterKey;
        masterKey.SetMaster(&seed[0], seed.size());

        CBitcoinExtKey b58extkey;
        b58extkey.SetKey(masterKey);

        file << "# extended private masterkey: " << b58extkey.ToString() << "\n";
    }
    else if (!masterKeyID.IsNull())
    {
        CKey key;
        if (pwallet->GetKey(masterKeyID, key)) {
            CExtKey masterKey;
            masterKey.SetMaster(key.begin(), key.size());

            CBitcoinExtKey b58extkey;
            b58extkey.SetKey(masterKey);

            file << "# extended private masterkey: " << b58extkey.ToString() << "\n\n";
        }
    }
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = CBitcoinAddress(keyid).ToString();
        CKey key;
        if(!masterKeyID.IsNull()){
            if(!pwallet->mapKeyMetadata[keyid].ParseComponents())
                continue;
        }
        if (pwallet->GetKey(keyid, key)) {
            file << strprintf("%s %s ", CBitcoinSecret(key).ToString(), strTime);
            if (pwallet->mapAddressBook.count(keyid)) {
                file << strprintf("label=%s", EncodeDumpString(pwallet->mapAddressBook[keyid].name));
            } else if (keyid == masterKeyID) {
                file << "hdmaster=1";
            } else if (mapKeyPool.count(keyid)) {
                file << "reserve=1";
            } else if (!masterKeyID.IsNull() && pwallet->mapKeyMetadata[keyid].hdKeypath == "m") {
                file << "inactivehdmaster=1";
            } else if (!masterKeyID.IsNull() && pwallet->mapKeyMetadata[keyid].nChange.first == 2) {
                file << "sigma=1";
            } else {
                file << "change=1";
            }
            if(!masterKeyID.IsNull()){
                if(pwallet->mapKeyMetadata.find(keyid) != pwallet->mapKeyMetadata.end()){
                    if(pwallet->mapKeyMetadata[keyid].nVersion >= CKeyMetadata::VERSION_WITH_HDDATA){
                        std::string hdKeypath = pwallet->mapKeyMetadata[keyid].hdKeypath;
                        uint160 hdMasterKeyID = pwallet->mapKeyMetadata[keyid].hdMasterKeyID;
                        if(hdKeypath != "")
                            file << strprintf(" hdKeypath=%s", hdKeypath);
                        if(!hdMasterKeyID.IsNull())
                            file << strprintf(" hdMasterKeyID=%s", hdMasterKeyID.ToString());
                    }
                }
            }
            file << strprintf(" # addr=%s\n", strAddr);
        }
    }

    if (pwallet->sparkWallet) {
        file << "\n";
        CKey key;
        uint32_t nCount;
        {
            LOCK(pwalletMain->cs_wallet);
            nCount = GetArg("-sparkncount", 1);
            pwalletMain->GetKeyFromKeypath(BIP44_SPARK_INDEX, nCount, key);
        }

        file << strprintf("# Spark key secret %s\n", CBitcoinSecret(key).ToString());
    }

    file << "\n";
    file << "# End of dump\n";
    file.close();

    UniValue reply(UniValue::VOBJ);
    reply.push_back(Pair("filename", filePath.string()));
    return reply;
}

UniValue dumpwallet_firo(const JSONRPCRequest& request)
{
#ifndef UNSAFE_DUMPPRIVKEY
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"             (string, required) The filename\n"
            "2. \"one-time-auth-code\"   (string, optional) A one time authorization code received from a previous call of dumpwallet"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleCli("dumpwallet", "\"test\" \"12aB\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\",\"12aB\"")
        );

    if(request.params.size() == 1 || !AuthorizationHelper::inst().authorize(__FUNCTION__ + request.params[0].get_str(), request.params[1].get_str()))
    {
        std::string warning =
            "WARNING! Your one time authorization code is: " + AuthorizationHelper::inst().generateAuthorizationCode(__FUNCTION__ + request.params[0].get_str()) + "\n"
            "This command exports all your private keys. Anyone with these keys has complete control over your funds. \n"
            "If someone asked you to type in this command, chances are they want to steal your coins. \n"
            "Firo team members will never ask for this command's output and it is not needed for masternode setup or diagnosis!\n"
            "\n"
            " Please seek help on one of our public channels. \n"
            " Telegram: https://t.me/firoproject \n"
            " Discord: https://discord.com/invite/TGZPRbRT3Y\n"
            " Reddit: https://www.reddit.com/r/FiroProject/\n"
            "\n"
            ;
        throw std::runtime_error(warning);
    }
#endif

    JSONRPCRequest newRequest;
    newRequest.params.setArray();
    newRequest.params.push_back(request.params[0]);

    return dumpwallet(newRequest);
}

UniValue ProcessImport(CWallet *pwallet, const UniValue& data, const int64_t timestamp)
{
    try {
        bool success = false;

        // Required fields.
        const UniValue& scriptPubKey = data["scriptPubKey"];

        // Should have script or JSON with "address".
        if (!(scriptPubKey.getType() == UniValue::VOBJ && scriptPubKey.exists("address")) && !(scriptPubKey.getType() == UniValue::VSTR)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid scriptPubKey");
        }

        // Optional fields.
        const std::string& strRedeemScript = data.exists("redeemscript") ? data["redeemscript"].get_str() : "";
        const UniValue& pubKeys = data.exists("pubkeys") ? data["pubkeys"].get_array() : UniValue();
        const UniValue& keys = data.exists("keys") ? data["keys"].get_array() : UniValue();
        const bool& internal = data.exists("internal") ? data["internal"].get_bool() : false;
        const bool& watchOnly = data.exists("watchonly") ? data["watchonly"].get_bool() : false;
        const std::string& label = data.exists("label") && !internal ? data["label"].get_str() : "";

        bool isScript = scriptPubKey.getType() == UniValue::VSTR;
        bool isP2SH = strRedeemScript.length() > 0;
        const std::string& output = isScript ? scriptPubKey.get_str() : scriptPubKey["address"].get_str();

        // Parse the output.
        CScript script;
        CBitcoinAddress address;

        if (!isScript) {
            address = CBitcoinAddress(output);
            if (!address.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            script = GetScriptForDestination(address.Get());
        } else {
            if (!IsHex(output)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid scriptPubKey");
            }

            std::vector<unsigned char> vData(ParseHex(output));
            script = CScript(vData.begin(), vData.end());
        }

        // Watchonly and private keys
        if (watchOnly && keys.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Incompatibility found between watchonly and keys");
        }

        // Internal + Label
        if (internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Incompatibility found between internal and label");
        }

        // Not having Internal + Script
        if (!internal && isScript) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal must be set for hex scriptPubKey");
        }

        // Keys / PubKeys size check.
        if (!isP2SH && (keys.size() > 1 || pubKeys.size() > 1)) { // Address / scriptPubKey
            throw JSONRPCError(RPC_INVALID_PARAMETER, "More than private key given for one address");
        }

        // Invalid P2SH redeemScript
        if (isP2SH && !IsHex(strRedeemScript)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid redeem script");
        }

        // Process. //

        // P2SH
        if (isP2SH) {
            // Import redeem script.
            std::vector<unsigned char> vData(ParseHex(strRedeemScript));
            CScript redeemScript = CScript(vData.begin(), vData.end());

            // Invalid P2SH address
            if (!script.IsPayToScriptHash()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid P2SH address / script");
            }

            pwallet->MarkDirty();

            if (!pwallet->HaveWatchOnly(redeemScript) && !pwallet->AddWatchOnly(redeemScript, timestamp)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
            }

            if (!pwallet->HaveCScript(redeemScript) && !pwallet->AddCScript(redeemScript)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
            }

            CBitcoinAddress redeemAddress = CBitcoinAddress(CScriptID(redeemScript));
            CScript redeemDestination = GetScriptForDestination(redeemAddress.Get());

            if (::IsMine(*pwallet, redeemDestination) == ISMINE_SPENDABLE) {
                throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
            }

            pwallet->MarkDirty();

            if (!pwallet->HaveWatchOnly(redeemDestination) && !pwallet->AddWatchOnly(redeemDestination, timestamp)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
            }

            // add to address book or update label
            if (address.IsValid()) {
                pwallet->SetAddressBook(address.Get(), label, "receive");
            }

            // Import private keys.
            if (keys.size()) {
                for (size_t i = 0; i < keys.size(); i++) {
                    const std::string& privkey = keys[i].get_str();

                    CBitcoinSecret vchSecret;
                    bool fGood = vchSecret.SetString(privkey);

                    if (!fGood) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");
                    }

                    CKey key = vchSecret.GetKey();

                    if (!key.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
                    }

                    CPubKey pubkey = key.GetPubKey();
                    assert(key.VerifyPubKey(pubkey));

                    CKeyID vchAddress = pubkey.GetID();
                    pwallet->MarkDirty();
                    pwallet->SetAddressBook(vchAddress, label, "receive");

                    if (pwallet->HaveKey(vchAddress)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key");
                    }

                    pwallet->mapKeyMetadata[vchAddress].nCreateTime = timestamp;

                    if (!pwallet->AddKeyPubKey(key, pubkey)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
                    }

                    pwallet->UpdateTimeFirstKey(timestamp);
                }
            }

            success = true;
        } else {
            // Import public keys.
            if (pubKeys.size() && keys.size() == 0) {
                const std::string& strPubKey = pubKeys[0].get_str();

                if (!IsHex(strPubKey)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
                }

                std::vector<unsigned char> vData(ParseHex(strPubKey));
                CPubKey pubKey(vData.begin(), vData.end());

                if (!pubKey.IsFullyValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");
                }

                CBitcoinAddress pubKeyAddress = CBitcoinAddress(pubKey.GetID());

                // Consistency check.
                if (!isScript && !(pubKeyAddress.Get() == address.Get())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Consistency check failed");
                }

                // Consistency check.
                if (isScript) {
                    CBitcoinAddress scriptAddress;
                    CTxDestination destination;

                    if (ExtractDestination(script, destination)) {
                        scriptAddress = CBitcoinAddress(destination);
                        if (!(scriptAddress.Get() == pubKeyAddress.Get())) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Consistency check failed");
                        }
                    }
                }

                CScript pubKeyScript = GetScriptForDestination(pubKeyAddress.Get());

                if (::IsMine(*pwallet, pubKeyScript) == ISMINE_SPENDABLE) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
                }

                pwallet->MarkDirty();

                if (!pwallet->HaveWatchOnly(pubKeyScript) && !pwallet->AddWatchOnly(pubKeyScript, timestamp)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
                }

                // add to address book or update label
                if (pubKeyAddress.IsValid()) {
                    pwallet->SetAddressBook(pubKeyAddress.Get(), label, "receive");
                }

                // TODO Is this necessary?
                CScript scriptRawPubKey = GetScriptForRawPubKey(pubKey);

                if (::IsMine(*pwallet, scriptRawPubKey) == ISMINE_SPENDABLE) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
                }

                pwallet->MarkDirty();

                if (!pwallet->HaveWatchOnly(scriptRawPubKey) && !pwallet->AddWatchOnly(scriptRawPubKey, timestamp)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
                }

                success = true;
            }

            // Import private keys.
            if (keys.size()) {
                const std::string& strPrivkey = keys[0].get_str();

                // Checks.
                CBitcoinSecret vchSecret;
                bool fGood = vchSecret.SetString(strPrivkey);

                if (!fGood) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");
                }

                CKey key = vchSecret.GetKey();
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
                }

                CPubKey pubKey = key.GetPubKey();
                assert(key.VerifyPubKey(pubKey));

                CBitcoinAddress pubKeyAddress = CBitcoinAddress(pubKey.GetID());

                // Consistency check.
                if (!isScript && !(pubKeyAddress.Get() == address.Get())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Consistency check failed");
                }

                // Consistency check.
                if (isScript) {
                    CBitcoinAddress scriptAddress;
                    CTxDestination destination;

                    if (ExtractDestination(script, destination)) {
                        scriptAddress = CBitcoinAddress(destination);
                        if (!(scriptAddress.Get() == pubKeyAddress.Get())) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Consistency check failed");
                        }
                    }
                }

                CKeyID vchAddress = pubKey.GetID();
                pwallet->MarkDirty();
                pwallet->SetAddressBook(vchAddress, label, "receive");

                if (pwallet->HaveKey(vchAddress)) {
                    return false;
                }

                pwallet->mapKeyMetadata[vchAddress].nCreateTime = timestamp;

                if (!pwallet->AddKeyPubKey(key, pubKey)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
                }

                pwallet->UpdateTimeFirstKey(timestamp);

                success = true;
            }

            // Import scriptPubKey only.
            if (pubKeys.size() == 0 && keys.size() == 0) {
                if (::IsMine(*pwallet, script) == ISMINE_SPENDABLE) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
                }

                pwallet->MarkDirty();

                if (!pwallet->HaveWatchOnly(script) && !pwallet->AddWatchOnly(script, timestamp)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
                }

                if (scriptPubKey.getType() == UniValue::VOBJ) {
                    // add to address book or update label
                    if (address.IsValid()) {
                        pwallet->SetAddressBook(address.Get(), label, "receive");
                    }
                }

                success = true;
            }
        }

        UniValue result = UniValue(UniValue::VOBJ);
        result.pushKV("success", UniValue(success));
        return result;
    } catch (const UniValue& e) {
        UniValue result = UniValue(UniValue::VOBJ);
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
        return result;
    } catch (...) {
        UniValue result = UniValue(UniValue::VOBJ);
        result.pushKV("success", UniValue(false));
        result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, "Missing required fields"));
        return result;
    }
}

int64_t GetImportTimestamp(const UniValue& data, int64_t now)
{
    if (data.exists("timestamp")) {
        const UniValue& timestamp = data["timestamp"];
        if (timestamp.isNum()) {
            return timestamp.get_int64();
        } else if (timestamp.isStr() && timestamp.get_str() == "now") {
            return now;
        }
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected number or \"now\" timestamp value for key. got type %s", uvTypeName(timestamp.type())));
    }
    throw JSONRPCError(RPC_TYPE_ERROR, "Missing required timestamp field for key");
}

UniValue importmulti(const JSONRPCRequest& mainRequest)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(mainRequest);
    if (!EnsureWalletIsAvailable(pwallet, mainRequest.fHelp)) {
        return NullUniValue;
    }

    // clang-format off
    if (mainRequest.fHelp || mainRequest.params.size() < 1 || mainRequest.params.size() > 2)
        throw std::runtime_error(
            "importmulti \"requests\" \"options\"\n\n"
            "Import addresses/scripts (with private or public keys, redeem script (P2SH)), rescanning all addresses in one-shot-only (rescan can be disabled via options).\n\n"
            "Arguments:\n"
            "1. requests     (array, required) Data to be imported\n"
            "  [     (array of json objects)\n"
            "    {\n"
            "      \"scriptPubKey\": \"<script>\" | { \"address\":\"<address>\" }, (string / json, required) Type of scriptPubKey (string for script, json for address)\n"
            "      \"timestamp\": timestamp | \"now\"                        , (integer / string, required) Creation time of the key in seconds since epoch (Jan 1 1970 GMT),\n"
            "                                                              or the string \"now\" to substitute the current synced blockchain time. The timestamp of the oldest\n"
            "                                                              key will determine how far back blockchain rescans need to begin for missing wallet transactions.\n"
            "                                                              \"now\" can be specified to bypass scanning, for keys which are known to never have been used, and\n"
            "                                                              0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest key\n"
            "                                                              creation time of all keys being imported by the importmulti call will be scanned.\n"
            "      \"redeemscript\": \"<script>\"                            , (string, optional) Allowed only if the scriptPubKey is a P2SH address or a P2SH scriptPubKey\n"
            "      \"pubkeys\": [\"<pubKey>\", ... ]                         , (array, optional) Array of strings giving pubkeys that must occur in the output or redeemscript\n"
            "      \"keys\": [\"<key>\", ... ]                               , (array, optional) Array of strings giving private keys whose corresponding public keys must occur in the output or redeemscript\n"
            "      \"internal\": <true>                                    , (boolean, optional, default: false) Stating whether matching outputs should be be treated as not incoming payments\n"
            "      \"watchonly\": <true>                                   , (boolean, optional, default: false) Stating whether matching outputs should be considered watched even when they're not spendable, only allowed if keys are empty\n"
            "      \"label\": <label>                                      , (string, optional, default: '') Label to assign to the address (aka account name, for now), only allowed with internal=false\n"
            "    }\n"
            "  ,...\n"
            "  ]\n"
            "2. options                 (json, optional)\n"
            "  {\n"
            "     \"rescan\": <false>,         (boolean, optional, default: true) Stating if should rescan the blockchain after all imports\n"
            "  }\n"
            "\nExamples:\n" +
            HelpExampleCli("importmulti", "'[{ \"scriptPubKey\": { \"address\": \"<my address>\" }, \"timestamp\":1455191478 }, "
                                          "{ \"scriptPubKey\": { \"address\": \"<my 2nd address>\" }, \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
            HelpExampleCli("importmulti", "'[{ \"scriptPubKey\": { \"address\": \"<my address>\" }, \"timestamp\":1455191478 }]' '{ \"rescan\": false}'") +

            "\nResponse is an array with the same size as the input that has the execution result :\n"
            "  [{ \"success\": true } , { \"success\": false, \"error\": { \"code\": -1, \"message\": \"Internal Server Error\"} }, ... ]\n");

    // clang-format on

    RPCTypeCheck(mainRequest.params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ));

    const UniValue& requests = mainRequest.params[0];

    //Default options
    bool fRescan = true;

    if (mainRequest.params.size() > 1) {
        const UniValue& options = mainRequest.params[1];

        if (options.exists("rescan")) {
            fRescan = options["rescan"].get_bool();
        }
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // Verify all timestamps are present before importing any keys.
    const int64_t now = chainActive.Tip() ? chainActive.Tip()->GetMedianTimePast() : 0;
    for (const UniValue& data : requests.getValues()) {
        GetImportTimestamp(data, now);
    }

    bool fRunScan = false;
    const int64_t minimumTimestamp = 1;
    int64_t nLowestTimestamp = 0;

    if (fRescan && chainActive.Tip()) {
        nLowestTimestamp = chainActive.Tip()->GetBlockTime();
    } else {
        fRescan = false;
    }

    UniValue response(UniValue::VARR);

    BOOST_FOREACH (const UniValue& data, requests.getValues()) {
        const int64_t timestamp = std::max(GetImportTimestamp(data, now), minimumTimestamp);
        const UniValue result = ProcessImport(pwallet, data, timestamp);
        response.push_back(result);

        if (!fRescan) {
            continue;
        }

        // If at least one request was successful then allow rescan.
        if (result["success"].get_bool()) {
            fRunScan = true;
        }

        // Get the lowest timestamp.
        if (timestamp < nLowestTimestamp) {
            nLowestTimestamp = timestamp;
        }
    }

    if (fRescan && fRunScan && requests.size()) {
        CBlockIndex* pindex = nLowestTimestamp > minimumTimestamp ? chainActive.FindEarliestAtLeast(std::max<int64_t>(nLowestTimestamp - 7200, 0)) : chainActive.Genesis();
        CBlockIndex* scannedRange = nullptr;
        if (pindex) {
            scannedRange = pwallet->ScanForWalletTransactions(pindex, true);
            pwallet->ReacceptWalletTransactions();
        }

        if (!scannedRange || scannedRange->nHeight > pindex->nHeight) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();
            size_t i = 0;
            for (const UniValue& request : requests.getValues()) {
                // If key creation date is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (GetImportTimestamp(request, now) - 7200 >= scannedRange->GetBlockTimeMax() || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else {
                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to rescan before time %d, transactions may be missing.", scannedRange->GetBlockTimeMax())));
                    response.push_back(std::move(result));
                }
                ++i;
            }
        }
    }

    return response;
}
