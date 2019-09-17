// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"
#include "merkleblock.h"
#include "core_io.h"
#include "authhelper.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

#include <boost/foreach.hpp>

using namespace std;

void EnsureWalletIsUnlocked();
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

UniValue importprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey \"zcoinprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"zcoinprivkey\"   (string, required) The private key (see dumpprivkey)\n"
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
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );


    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

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
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress))
            return NullUniValue;

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        }
    }

    return NullUniValue;
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel);
void ImportScript(const CScript& script, const string& strLabel, bool isRedeemScript)
{
    if (!isRedeemScript && ::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

    pwalletMain->MarkDirty();

    if (!pwalletMain->HaveWatchOnly(script) && !pwalletMain->AddWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

    if (isRedeemScript) {
        if (!pwalletMain->HaveCScript(script) && !pwalletMain->AddCScript(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        ImportAddress(CBitcoinAddress(CScriptID(script)), strLabel);
    } else {
        CTxDestination destination;
        if (ExtractDestination(script, destination)) {
            pwalletMain->SetAddressBook(destination, strLabel, "receive");
        }
    }
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel)
{
    CScript script = GetScriptForDestination(address.Get());
    ImportScript(script, strLabel, false);
    // add to address book or update label
    if (address.IsValid())
        pwalletMain->SetAddressBook(address.Get(), strLabel, "receive");
}

UniValue importaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
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


    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (fRescan && fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (params.size() > 3)
        fP2SH = params[3].get_bool();

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (fP2SH)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
        ImportAddress(address, strLabel);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        ImportScript(CScript(data.begin(), data.end()), strLabel, fP2SH);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address or script");
    }

    if (fRescan)
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        pwalletMain->ReacceptWalletTransactions();
    }

    return NullUniValue;
}

UniValue importprunedfunds(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    // 0.13.x: Silently accept up to 3 params, but ignore the third:
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "importprunedfunds\n"
            "\nImports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n"
            "\nArguments:\n"
            "1. \"rawtransaction\" (string, required) A raw transaction in hex funding an already-existing address in wallet\n"
            "2. \"txoutproof\"     (string, required) The hex output from gettxoutproof that contains the transaction\n"
        );

    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();
    CWalletTx wtx(pwalletMain,tx);

    CDataStream ssMB(ParseHexV(params[1], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    vector<uint256> vMatch;
    vector<unsigned int> vIndex;
    unsigned int txnIndex = 0;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) == merkleBlock.header.hashMerkleRoot) {

        LOCK(cs_main);

        if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

        vector<uint256>::const_iterator it;
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (pwalletMain->IsMine(tx)) {
        CWalletDB walletdb(pwalletMain->strWalletFile, "r+", false);
        pwalletMain->AddToWallet(wtx, false, &walletdb);
        return NullUniValue;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
}

UniValue removeprunedfunds(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "removeprunedfunds \"txid\"\n"
            "\nDeletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will effect wallet balances.\n"
            "\nArguments:\n"
            "1. \"txid\"           (string, required) The hex-encoded id of the transaction you are deleting\n"
            "\nExamples:\n"
            + HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());
    vector<uint256> vHash;
    vHash.push_back(hash);
    vector<uint256> vHashOut;

    if(pwalletMain->ZapSelectTx(vHash, vHashOut) != DB_LOAD_OK) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not properly delete the transaction.");
    }

    if(vHashOut.empty()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction does not exist in wallet.");
    }

    return NullUniValue;
}

UniValue importpubkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
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


    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (fRescan && fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    if (!IsHex(params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end());
    if (!pubKey.IsFullyValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    ImportAddress(CBitcoinAddress(pubKey.GetID()), strLabel);
    ImportScript(GetScriptForRawPubKey(pubKey), strLabel, false);

    if (fRescan)
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        pwalletMain->ReacceptWalletTransactions();
    }

    return NullUniValue;
}


UniValue importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime();

    bool fGood = true;

    bool fMintUpdate = false;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    CWalletDB walletdb(pwalletMain->strWalletFile);

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) {
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;
        CBitcoinSecret vchSecret;
        // begin zerocoin
        if(vstr[0] == "zerocoin=1"){    
            CZerocoinEntry zerocoinEntry;
            zerocoinEntry.value.SetHex(vstr[1]);
            zerocoinEntry.denomination = stoi(vstr[2]);
            zerocoinEntry.randomness.SetHex(vstr[3]);
            zerocoinEntry.serialNumber.SetHex(vstr[4]);
            zerocoinEntry.IsUsed = stoi(vstr[5]);
            zerocoinEntry.nHeight = stoi(vstr[6]);
            zerocoinEntry.id = stoi(vstr[7]);
            if(vstr.size()>8){
                zerocoinEntry.ecdsaSecretKey = ParseHex(vstr[8]);
                zerocoinEntry.IsUsedForRemint = stoi(vstr[9]);
            }
            walletdb.WriteZerocoinEntry(zerocoinEntry);
        }
        else {
            if (!vchSecret.SetString(vstr[0]))
                continue;
            CKey key = vchSecret.GetKey();
            CPubKey pubkey = key.GetPubKey();
            assert(key.VerifyPubKey(pubkey));
            CKeyID keyid = pubkey.GetID();
            if (pwalletMain->HaveKey(keyid)) {
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
                if (vstr[nStr] == "sigma=1")
                    fLabel = false;
                if (vstr[nStr] == "reserve=1")
                    fLabel = false;
                if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                    strLabel = DecodeDumpString(vstr[nStr].substr(6));
                    fLabel = true;
                }
                if(boost::algorithm::starts_with(vstr[nStr], "hdKeypath=")){
                    hdKeypath = vstr[nStr].substr(10);
                    fHd = true;
                }
                if(boost::algorithm::starts_with(vstr[nStr], "hdMasterKeyID=")){
                    hdMasterKeyID.SetHex(vstr[nStr].substr(14));
                }
            }
            LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString());

            // Add entry to mapKeyMetadata (Need to populate KeyMetadata before for it to be written to DB in the following call)
            pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime;
            if(fHd){
                pwalletMain->mapKeyMetadata[keyid].hdKeypath = hdKeypath;
                pwalletMain->mapKeyMetadata[keyid].hdMasterKeyID = hdMasterKeyID;
                pwalletMain->mapKeyMetadata[keyid].ParseComponents();
            }

            if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
                fGood = false;
                continue;
            }

            if(fHd){
                // If change component in HD path is 2, this is a mint seed key. Add to mintpool. (Have to call after key addition)
                if(pwalletMain->mapKeyMetadata[keyid].nChange.first==2){
                    zwalletMain->RegenerateMintPoolEntry(hdMasterKeyID, keyid, pwalletMain->mapKeyMetadata[keyid].nChild.first);
                    fMintUpdate = true;
                }
            }
            if (fLabel)
                pwalletMain->SetAddressBook(keyid, strLabel, "receive");
            nTimeBegin = std::min(nTimeBegin, nTime);
        }
    }
    file.close();
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = chainActive.Tip();
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
        pindex = pindex->pprev;

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex);
    pwalletMain->MarkDirty();

    if(fMintUpdate){
        zwalletMain->SyncWithChain();
        zwalletMain->GetTracker().ListMints(false, false);
    }

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue;
}

//This method intentionally left unchanged.
UniValue dumpprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey \"zcoinaddress\"\n"
            "\nReveals the private key corresponding to 'zcoinaddress'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"   (string, required) The Zcoin address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret).ToString();
}

UniValue dumpprivkey_zcoin(const UniValue& params, bool fHelp)
{
#ifndef UNSAFE_DUMPPRIVKEY
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "dumpprivkey \"zcoinaddress\"\n"
            "\nReveals the private key corresponding to 'zcoinaddress'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"   (string, required) The Zcoin address for the private key\n"
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

    if(params.size() == 1 || !AuthorizationHelper::inst().authorize(__FUNCTION__ + params[0].get_str(), params[1].get_str()))
    {
        std::string warning =
            "WARNING! Your one time authorization code is: " + AuthorizationHelper::inst().generateAuthorizationCode(__FUNCTION__ + params[0].get_str()) + "\n"
            "This command exports your wallet private key. Anyone with this key has complete control over your funds. \n"
            "If someone asked you to type in this command, chances are they want to steal your coins. \n"
            "Zcoin team members will never ask for this command's output and it is not needed for Znode setup or diagnosis!\n"
            "\n"
            " Please seek help on one of our public channels. \n"
            " Telegram: https://t.me/zcoinproject \n"
            " Discord: https://discordapp.com/invite/4FjnQ2q\n"
            " Reddit: https://www.reddit.com/r/zcoin/\n"
            "\n"
            ;
        throw runtime_error(warning);
    }
#endif

    UniValue dumpParams;
    dumpParams.setArray();
    dumpParams.push_back(params[0]);

    return dumpprivkey(dumpParams, false);
}

UniValue dumpwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth;
    std::set<CKeyID> setKeyPool;
    pwalletMain->GetKeyBirthTimes(mapKeyBirth);
    pwalletMain->GetAllReserveKeys(setKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by Zcoin %s\n", CLIENT_BUILD);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime()));
    file << "\n";

    // add the base58check encoded extended master if the wallet uses HD
    CHDChain chain = pwalletMain->GetHDChain();
    CKeyID masterKeyID = chain.masterKeyID;
    if(!chain.IsNull())
    {
        if(chain.IsCrypted())
        {
            if(!pwalletMain->DecryptHDChain(chain))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot decrypt hd chain");
        }

        SecureString mnemonic;
        SecureString passphrase;
        if(!chain.GetMnemonic(mnemonic, passphrase))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot get mnemonic");

        file << "# mnemonic: " << mnemonic << "\n";
        file << "# mnemonic passphrase: " << passphrase << "\n\n";

        SecureVector seed = chain.GetSeed();
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
        if (pwalletMain->GetKey(masterKeyID, key))
        {
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
        pwalletMain->mapKeyMetadata[keyid].ParseComponents();
        if (pwalletMain->GetKey(keyid, key)) {
            file << strprintf("%s %s ", CBitcoinSecret(key).ToString(), strTime);
            if (pwalletMain->mapAddressBook.count(keyid)) {
                file << strprintf("label=%s", EncodeDumpString(pwalletMain->mapAddressBook[keyid].name));
            } else if (keyid == masterKeyID) {
                file << "hdmaster=1";
            } else if (setKeyPool.count(keyid)) {
                file << "reserve=1";
            } else if (pwalletMain->mapKeyMetadata[keyid].hdKeypath == "m") {
                file << "inactivehdmaster=1";
            } else if (pwalletMain->mapKeyMetadata[keyid].nChange.first == 2) {
                file << "sigma=1";
            } else {
                file << "change=1";
            }
            if(pwalletMain->mapKeyMetadata.find(keyid) != pwalletMain->mapKeyMetadata.end()){
                if(pwalletMain->mapKeyMetadata[keyid].nVersion >= CKeyMetadata::VERSION_WITH_HDDATA){
                    string hdKeypath = pwalletMain->mapKeyMetadata[keyid].hdKeypath;
                    uint160 hdMasterKeyID = pwalletMain->mapKeyMetadata[keyid].hdMasterKeyID;
                    if(hdKeypath != "")
                        file << strprintf(" hdKeypath=%s", hdKeypath);
                    if(!hdMasterKeyID.IsNull())
                        file << strprintf(" hdMasterKeyID=%s", hdMasterKeyID.ToString());
                }
            }
            file << strprintf(" # addr=%s\n", strAddr);
        }
    }

    // Begin dump Zerocoins
    list <CZerocoinEntry> listZerocoinEntries;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.ListPubCoin(listZerocoinEntries);

    for (auto& zerocoinEntry : listZerocoinEntries) {
        file << "zerocoin=1 ";
        file << strprintf("%s ", zerocoinEntry.value.GetHex()); // value
        file << strprintf("%d ", zerocoinEntry.denomination); // denomination
        file << strprintf("%s ", zerocoinEntry.randomness.GetHex()); // randomness
        file << strprintf("%s ", zerocoinEntry.serialNumber.GetHex()); // serialNumber
        file << strprintf("%d ", zerocoinEntry.IsUsed); // IsUsed
        file << strprintf("%d ", zerocoinEntry.nHeight); // nHeight
        file << strprintf("%d ", zerocoinEntry.id); // id
        if(!zerocoinEntry.ecdsaSecretKey.empty()){
            file << strprintf("%s ", HexStr(zerocoinEntry.ecdsaSecretKey)); // ecdsaSecretKey
            file << strprintf("%d ", zerocoinEntry.IsUsedForRemint); // IsUsedForRemint
        }
        file << "#\n"; // --
    }

    file << "\n";
    file << "# End of dump\n";
    file.close();
    return NullUniValue;
}

UniValue dumpmnemonic(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "dumpmnemonic\n"
            "\nReturns all mnemonic data: HD seed, Mnemonic words and Mnemonic Passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpmnemonic", "\"test\"")
            + HelpExampleRpc("dumpmnemonic", "\"test\"")
        );

    CHDChain chain = pwalletMain->GetHDChain();

    if(!(chain.nVersion >= CHDChain::VERSION_WITH_BIP39))
        throw runtime_error("Mnemonic is not enabled");

    if(chain.IsCrypted())
    {
        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                               "Error: Please enter the wallet passphrase with walletpassphrase first.");

        if(!pwalletMain->DecryptHDChain(chain))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot decrypt hd chain");
    }

    SecureString mnemonic;
    SecureString passphrase;
    if(!chain.GetMnemonic(mnemonic, passphrase))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot get mnemonic");

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("hdseed", HexStr(chain.GetSeed())));
    obj.push_back(Pair("mnemonic", mnemonic.c_str()));
    obj.push_back(Pair("mnemonicpassphrase", passphrase.c_str()));
    return obj;
}

UniValue dumpwallet_zcoin(const UniValue& params, bool fHelp)
{
#ifndef UNSAFE_DUMPPRIVKEY
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
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

    if(params.size() == 1 || !AuthorizationHelper::inst().authorize(__FUNCTION__ + params[0].get_str(), params[1].get_str()))
    {
        std::string warning =
            "WARNING! Your one time authorization code is: " + AuthorizationHelper::inst().generateAuthorizationCode(__FUNCTION__ + params[0].get_str()) + "\n"
            "This command exports all your private keys. Anyone with these keys has complete control over your funds. \n"
            "If someone asked you to type in this command, chances are they want to steal your coins. \n"
            "Zcoin team members will never ask for this command's output and it is not needed for Znode setup or diagnosis!\n"
            "\n"
            " Please seek help on one of our public channels. \n"
            " Telegram: https://t.me/zcoinproject \n"
            " Discord: https://discordapp.com/invite/4FjnQ2q\n"
            " Reddit: https://www.reddit.com/r/zcoin/\n"
            "\n"
            ;
        throw runtime_error(warning);
    }
#endif

    UniValue dumpParams;
    dumpParams.setArray();
    dumpParams.push_back(params[0]);

    return dumpwallet(dumpParams, false);
}
