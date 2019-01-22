// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "base58.h"
#include "checkpoints.h"
#include "chain.h"
#include "coincontrol.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "zerocoin.h"
#include "zerocoin_v3.h"
#include "../libzerocoin/sigma/CoinSpend.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "darksend.h"
#include "instantx.h"
#include "znode.h"
#include "znode-sync.h"
#include "random.h"

#include <assert.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

using namespace std;

CWallet *pwalletMain = NULL;
/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fSendFreeTransactions = DEFAULT_SEND_FREE_TRANSACTIONS;

const char *DEFAULT_WALLET_DAT = "wallet.dat";
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly {
    bool operator()(const pair <CAmount, pair<const CWalletTx *, unsigned int>> &t1,
                    const pair <CAmount, pair<const CWalletTx *, unsigned int>> &t2) const {
        return t1.first < t2.first;
    }
};

struct CompareByPriority
{
    bool operator()(const COutput& t1,
                    const COutput& t2) const
    {
        return t1.Priority() > t2.Priority();
    }
};

struct CompareByAmount
{
    bool operator()(const CompactTallyItem& t1, const CompactTallyItem& t2) const
    {
        return t1.nAmount > t2.nAmount;
    }
};

int COutput::Priority() const
{
    BOOST_FOREACH(CAmount d, vecPrivateSendDenominations)
    if(tx->vout[i].nValue == d) return 10000;
    if(tx->vout[i].nValue < 1*COIN) return 20000;

    //nondenom return largest first
    return -(tx->vout[i].nValue/COIN);
}

std::string COutput::ToString() const {
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->vout[i].nValue));
}

const CWalletTx *CWallet::GetWalletTx(const uint256 &hash) const {
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey() {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(
            FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation
    if (!hdChain.masterKeyID.IsNull()) {
        // for now we use a fixed keypath scheme of m/0'/0'/k
        CKey key;                      //master key seed (256bit)
        CExtKey masterKey;             //hd master key
        CExtKey accountKey;            //key at m/0'
        CExtKey externalChainChildKey; //key at m/0'/0'
        CExtKey childKey;              //key at m/0'/0'/<n>'

        // try to get the master key
        if (!GetKey(hdChain.masterKeyID, key))
            throw std::runtime_error(std::string(__func__) + ": Master key not found");

        masterKey.SetMaster(key.begin(), key.size());

        // derive m/0'
        // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
        masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

        // derive m/0'/0'
        accountKey.Derive(externalChainChildKey, BIP32_HARDENED_KEY_LIMIT);

        // derive child key at next index, skip keys already known to the wallet
        do {
            // always derive hardened keys
            // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
            // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
            externalChainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
            metadata.hdMasterKeyID = hdChain.masterKeyID;
            // increment childkey index
            hdChain.nExternalChainCounter++;
        } while (HaveKey(childKey.key.GetPubKey().GetID()));
        secret = childKey.key;

        // update the chain model in the database
        if (!CWalletDB(strWalletFile).WriteHDChain(hdChain))
            throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey &secret, const CPubKey &pubkey) {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const vector<unsigned char> &vchCryptedSecret) {
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta) {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) {
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript &redeemScript) {
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript &redeemScript) {
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        std::string strAddr = CBitcoinAddress(CScriptID(redeemScript)).ToString();
        LogPrintf(
                "%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
                __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript &dest) {
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest) {
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}


bool CWallet::LoadWatchOnly(const CScript &dest) {
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString &strWalletPassphrase) {
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type &pMasterKey, mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt,
                                              pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString &strOldWalletPassphrase,
                                     const SecureString &strNewWalletPassphrase) {
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type & pMasterKey, mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt,
                                              pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey)) {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                             pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                        pMasterKey.second.nDeriveIterations * (100 / ((double) (GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                             pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations +
                                                       pMasterKey.second.nDeriveIterations * 100 /
                                                       ((double) (GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n",
                          pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                                  pMasterKey.second.nDeriveIterations,
                                                  pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator &loc) {
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB *pwalletdbIn, bool fExplicit) {
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
        nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked) {
        CWalletDB *pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion) {
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set <uint256> CWallet::GetConflicts(const uint256 &txid) const {
    set <uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx &wtx = it->second;

    std::pair <TxSpends::const_iterator, TxSpends::const_iterator> range;

    BOOST_FOREACH(const CTxIn &txin, wtx.vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
            result.insert(it->second);
    }
    return result;
}

void CWallet::Flush(bool shutdown) {
    bitdb.Flush(shutdown);
}

bool CWallet::Verify() {
    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    LogPrintf("Using wallet %s\n", walletFile);
    uiInterface.InitMessage(_("Verifying wallet..."));

    // Wallet file must be a plain filename without a directory
    if (walletFile != boost::filesystem::basename(walletFile) + boost::filesystem::extension(walletFile))
        return InitError(
                strprintf(_("Wallet %s resides outside data directory %s"), walletFile, GetDataDir().string()));

    if (!bitdb.Open(GetDataDir())) {
        // try moving the database env out of the way
        boost::filesystem::path pathDatabase = GetDataDir() / "database";
        boost::filesystem::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try {
            boost::filesystem::rename(pathDatabase, pathDatabaseBak);
            LogPrintf("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        } catch (const boost::filesystem::filesystem_error &) {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir())) {
            // if it still fails, it probably means we can't even create the database env
            return InitError(strprintf(_("Error initializing wallet database environment %s!"), GetDataDir()));
        }
    }

    if (GetBoolArg("-salvagewallet", false)) {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, walletFile, true))
            return false;
    }

    if (boost::filesystem::exists(GetDataDir() / walletFile)) {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK) {
            InitWarning(strprintf(_("Warning: Wallet file corrupt, data salvaged!"
                                            " Original %s saved as %s in %s; if"
                                            " your balance or transactions are incorrect you should"
                                            " restore from a backup."),
                                  walletFile, "wallet.{timestamp}.bak", GetDataDir()));
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(strprintf(_("%s corrupt, salvage failed"), walletFile));
    }
    LogPrintf("Verify wallet ok!");
    return true;
}

void CWallet::SyncMetaData(pair <TxSpends::iterator, TxSpends::iterator> range) {
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx *copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256 &hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos) {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256 &hash = it->second;
        CWalletTx *copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256 &hash, unsigned int n) const {
    const COutPoint outpoint(hash, n);
    pair <TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256 &wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0 || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint &outpoint, const uint256 &wtxid) {
    mapTxSpends.insert(make_pair(outpoint, wtxid));

    pair <TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256 &wtxid) {
    assert(mapWallet.count(wtxid));
    CWalletTx &thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase() || thisTx.IsZerocoinSpend() || thisTx.IsZerocoinSpendV3()) // Coinbases don't spend anything!
        return;

    BOOST_FOREACH(const CTxIn &txin, thisTx.vin)
    AddToSpends(txin.prevout, wtxid);
}

bool CWallet::EncryptWallet(const SecureString &strWalletPassphrase) {
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double) (GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                 kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations +
                                    kMasterKey.nDeriveIterations * 100 / ((double) (GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                      kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked) {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin()) {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey)) {
            if (fFileBacked) {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked) {
            if (!pwalletdbEncryption->TxnCommit()) {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);

        // if we are using HD, replace the HD master key (seed) with a new one
        if (!hdChain.masterKeyID.IsNull()) {
            CKey key;
            CPubKey masterPubKey = GenerateNewHDMasterKey();
            if (!SetHDMasterKey(masterPubKey))
                return false;
        }

        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb) {
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

bool CWallet::AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment) {
    CWalletDB walletdb(strWalletFile);
    if (!walletdb.TxnBegin())
        return false;

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    AddAccountingEntry(debit, walletdb);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    AddAccountingEntry(credit, walletdb);

    if (!walletdb.TxnCommit())
        return false;

    return true;
}

bool CWallet::GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew) {
    CWalletDB walletdb(strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    if (!bForceNew) {
        if (!account.vchPubKey.IsValid())
            bForceNew = true;
        else {
            // Check if the current key has been used
            CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
            for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
                 it != mapWallet.end() && account.vchPubKey.IsValid();
                 ++it)
                BOOST_FOREACH(const CTxOut &txout, (*it).second.vout)
            if (txout.scriptPubKey == scriptPubKey) {
                bForceNew = true;
                break;
            }
        }
    }

    // Generate a new key
    if (bForceNew) {
        if (!GetKeyFromPool(account.vchPubKey))
            return false;

        SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    }

    pubKey = account.vchPubKey;

    return true;
}

void CWallet::MarkDirty() {
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)&item, mapWallet)
        item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx &wtxIn, bool fFromLoadWallet, CWalletDB *pwalletdb) {
    LogPrintf("CWallet::AddToWallet\n");
    uint256 hash = wtxIn.GetHash();
    LogPrintf("hash=%s\n", hash.ToString());
    if (fFromLoadWallet) {
        mapWallet[hash] = wtxIn;
        CWalletTx &wtx = mapWallet[hash];
        wtx.BindWallet(this);
//        if (!wtx.IsZerocoinSpend()) {
        wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry *) 0)));
        AddToSpends(hash);
//            BOOST_FOREACH(const CTxIn &txin, wtx.vin) {
//                LogPrintf("txin.prevout.hash=%s\n", txin.prevout.hash.ToString());
//                if (mapWallet.count(txin.prevout.hash)) {
//                    CWalletTx &prevtx = mapWallet[txin.prevout.hash];
//                    if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
//                        LogPrintf("Enter\n");
//                        MarkConflicted(prevtx.hashBlock, wtx.GetHash());
//                        LogPrintf("Out\n");
//                    }
//                }
//            }
//        }
    } else {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx &wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew) {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext(pwalletdb);
            wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry *) 0)));
            wtx.nTimeSmart = wtx.nTimeReceived;
            if (!wtxIn.hashUnset()) {
                if (mapBlockIndex.count(wtxIn.hashBlock)) {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        const TxItems &txOrdered = wtxOrdered;
                        for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx) {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            } else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated) {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }
                    int64_t blocktime = mapBlockIndex[wtxIn.hashBlock]->GetBlockTime();
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                } else
                    LogPrintf("AddToWallet(): found %s in block %s not in index\n",
                              wtxIn.GetHash().ToString(),
                              wtxIn.hashBlock.ToString());
            }
            AddToSpends(hash);
        }
        bool fUpdated = false;
        if (!fInsertedNew) {
            // Merge
            if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock) {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            // If no longer abandoned, update
            if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned()) {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex)) {
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe) {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug print
        LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""),
                  (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!pwalletdb->WriteTx(wtx))
                return false;

        // Break debit/credit balance caches:
        wtx.MarkDirty();

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if (!strCmd.empty()) {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    LogPrintf("CWallet::AddToWallet -> ok\n");
    return true;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction &tx, const CBlock *pblock, bool fUpdate) {
    {
//        LogPrintf("CWallet::AddToWalletIfInvolvingMe, tx=%s\n", tx.GetHash().ToString());
        AssertLockHeld(cs_wallet);
//        if (!tx.IsZerocoinSpend() && pblock) {
//            BOOST_FOREACH(const CTxIn &txin, tx.vin) {
//                std::pair <TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(
//                        txin.prevout);
//                while (range.first != range.second) {
//                    if (range.first->second != tx.GetHash()) {
//                        LogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n",
//                                  tx.GetHash().ToString(), pblock->GetHash().ToString(), range.first->second.ToString(),
//                                  range.first->first.hash.ToString(), range.first->first.n);
//                        MarkConflicted(pblock->GetHash(), range.first->second);
//                    }
//                    range.first++;
//                }
//            }
//        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx)) {
            CWalletTx wtx(this, tx);

            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(*pblock);

            // Do not flush the wallet here for performance reasons
            // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our SetBestChain-mechanism
            CWalletDB walletdb(strWalletFile, "r+", false);

            return AddToWallet(wtx, false, &walletdb);
        }
    }
//    LogPrintf("CWallet::AddToWalletIfInvolvingMe -> out false!\n");
    return false;
}

bool CWallet::AbandonTransaction(const uint256 &hashTx) {
    LOCK2(cs_main, cs_wallet);

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set <uint256> todo;
    std::set <uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    assert(mapWallet.count(hashTx));
    CWalletTx &origtx = mapWallet[hashTx];
    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool() || origtx.InStempool()) {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx &wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            assert(!wtx.InStempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CTxIn &txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }

        if (wtx.IsZerocoinSpend()) {
            // find out coin serial number
            assert(wtx.vin.size() == 1);

            const CTxIn &txin = wtx.vin[0];
            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            libzerocoin::CoinSpend spend(txin.nSequence >= ZC_MODULUS_V2_BASE_ID ? ZCParamsV2 : ZCParams,
                                         serializedCoinSpend);

            CBigNum serial = spend.getCoinSerialNumber();

            // mark corresponding mint as unspent
            list <CZerocoinEntry> pubCoins;
            walletdb.ListPubCoin(pubCoins);

            BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, pubCoins) {
                if (zerocoinItem.serialNumber == serial) {
                    CZerocoinEntry modifiedItem = zerocoinItem;
                    modifiedItem.IsUsed = false;
                    pwalletMain->NotifyZerocoinChanged(pwalletMain, zerocoinItem.value.GetHex(),
                                                       std::string("New (") + std::to_string(zerocoinItem.denomination) + "mint)",
                                                       CT_UPDATED);
                    walletdb.WriteZerocoinEntry(modifiedItem);

                    // erase zerocoin spend entry
                    CZerocoinSpendEntry spendEntry;
                    spendEntry.coinSerial = serial;
                    walletdb.EraseCoinSpendSerialEntry(spendEntry);
                }
            }

        } else if (wtx.IsZerocoinSpendV3()) {
            // find out coin serial number
            assert(wtx.vin.size() == 1);

            const CTxIn &txin = wtx.vin[0];
            // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
            // OP_ZEROCOINSPENDV3 is written. In zerocoin you will see +4 instead,
            // because the size of serialized spend is also written, probably in 3 bytes.
            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpendV3 spend(sigma::ParamsV3::get_default(),
                                         serializedCoinSpend);

            Scalar serial = spend.getCoinSerialNumber();

            // mark corresponding mint as unspent
            list <CZerocoinEntryV3> pubCoins;
            walletdb.ListPubCoinV3(pubCoins);

            BOOST_FOREACH(const CZerocoinEntryV3 &zerocoinItem, pubCoins) {
                if (zerocoinItem.serialNumber == serial) {
                    CZerocoinEntryV3 modifiedItem = zerocoinItem;
                    modifiedItem.IsUsed = false;
                    pwalletMain->NotifyZerocoinChanged(
                        pwalletMain,
                        zerocoinItem.value.GetHex(),
                        std::string("New (") + std::to_string((double)zerocoinItem.get_denomination_value() / COIN) + "mint)",                               
                        CT_UPDATED);
                    walletdb.WriteZerocoinEntry(modifiedItem);

                    // erase zerocoin spend entry
                    CZerocoinSpendEntryV3 spendEntry;
                    spendEntry.coinSerial = serial;
                    walletdb.EraseCoinSpendSerialEntry(spendEntry);
                }
            }
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256 &hashBlock, const uint256 &hashTx) {
    LOCK2(cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (mapBlockIndex.count(hashBlock)) {
        CBlockIndex *pindex = mapBlockIndex[hashBlock];
        if (chainActive.Contains(pindex)) {
            conflictconfirms = -(chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set <uint256> todo;
    std::set <uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx &wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CTxIn &txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransaction &tx, const CBlockIndex *pindex, const CBlock *pblock) {
//    LogPrintf("SyncTransaction()\n");
    LOCK2(cs_main, cs_wallet);

    if (!AddToWalletIfInvolvingMe(tx, pblock, true)) {
//        LogPrintf("Not mine!\n");
        return; // Not one of ours
    }

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        if (mapWallet.count(txin.prevout.hash))
            mapWallet[txin.prevout.hash].MarkDirty();
    }
}


isminetype CWallet::IsMine(const CTxIn &txin) const {
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx &prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                return IsMine(prev.vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter &filter) const {
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx &prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]) & filter)
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut &txout) const {
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CWallet::GetCredit(const CTxOut &txout, const isminefilter &filter) const {
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut &txout) const {
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey)) {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut &txout) const {
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction &tx) const {
    BOOST_FOREACH(const CTxOut &txout, tx.vout)
    if (IsMine(txout) && txout.nValue >= nMinimumInputValue)
        return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction &tx) const {
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction &tx, const isminefilter &filter) const {
    CAmount nDebit = 0;
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

CAmount CWallet::GetCredit(const CTransaction &tx, const isminefilter &filter) const {
    CAmount nCredit = 0;
    BOOST_FOREACH(const CTxOut &txout, tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction &tx) const {
    CAmount nChange = 0;
    BOOST_FOREACH(const CTxOut &txout, tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewHDMasterKey() {
    CKey key;
    key.MakeNewKey(true);

    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the pubkey
    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));

    // set the hd keypath to "m" -> Master, refers the masterkeyid to itself
    metadata.hdKeypath = "m";
    metadata.hdMasterKeyID = pubkey.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[pubkey.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, pubkey))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return pubkey;
}

bool CWallet::SetHDMasterKey(const CPubKey &pubkey) {
    LOCK(cs_wallet);

    // ensure this wallet.dat can only be opened by clients supporting HD
    SetMinVersion(FEATURE_HD);

    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.masterKeyID = pubkey.GetID();
    SetHDChain(newHdChain, false);

    return true;
}

bool CWallet::SetHDChain(const CHDChain &chain, bool memonly) {
    LOCK(cs_wallet);
    if (!memonly && !CWalletDB(strWalletFile).WriteHDChain(chain))
        throw runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
    return true;
}

int64_t CWalletTx::GetTxTime() const {
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const {
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase()) {
            // Generated block
            if (!hashUnset()) {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        } else {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end()) {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset()) {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list <COutputEntry> &listReceived,
                           list <COutputEntry> &listSent, CAmount &nFee, string &strSentAccount,
                           const isminefilter &filter) const {
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i) {
        const CTxOut &txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0) {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        } else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable()) {
            LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                      this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int) i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

void CWalletTx::GetAccountAmounts(const string &strAccount, CAmount &nReceived,
                                  CAmount &nSent, CAmount &nFee, const isminefilter &filter) const {
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list <COutputEntry> listReceived;
    list <COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount) {
        BOOST_FOREACH(const COutputEntry &s, listSent)
        nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const COutputEntry &r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination)) {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            } else if (strAccount.empty()) {
                nReceived += r.amount;
            }
        }
    }
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */
int CWallet::ScanForWalletTransactions(CBlockIndex *pindexStart, bool fUpdate) {
    int ret = 0;
    int64_t nNow = GetTime();
    const CChainParams &chainParams = Params();

    CBlockIndex *pindex = pindexStart;
    {
        LOCK2(cs_main, cs_wallet);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
            pindex = chainActive.Next(pindex);

        ShowProgress(_("Rescanning..."),
                     0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), chainActive.Tip(),
                                                                     false);
        while (pindex) {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99,
                                                                      (int) ((Checkpoints::GuessVerificationProgress(
                                                                              chainParams.Checkpoints(), pindex,
                                                                              false) - dProgressStart) /
                                                                             (dProgressTip - dProgressStart) * 100))));

            CBlock block;
            ReadBlockFromDisk(block, pindex, Params().GetConsensus());
            BOOST_FOREACH(CTransaction & tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = chainActive.Next(pindex);
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight,
                          Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex));
            }
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions() {
    LogPrintf("CWallet::ReacceptWalletTransactions()\n");
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(cs_main, cs_wallet);
    std::map < int64_t, CWalletTx * > mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)&item, mapWallet)
    {
        const uint256 &wtxid = item.first;
        CWalletTx &wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (wtx.IsCoinBase() && (nDepth == 0 && !wtx.isAbandoned()))
            continue;

        if (nDepth == 0 && !wtx.isAbandoned()) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    BOOST_FOREACH(PAIRTYPE(const int64_t, CWalletTx *)&item, mapSorted)
    {
        CWalletTx &wtx = *(item.second);

        LOCK(mempool.cs);
        CValidationState state;
        // LogPrintf("CWallet::ReacceptWalletTransactions(): re-accepting transaction %s to mempool/stempool.\n", wtx.GetHash().ToString());

        // When re-accepting transaction back to the wallet after 
        // the app was closed and re-opened, do NOT check their
        // serial numbers, and DO NOT try to mark their serial numbers 
        // a second time. We assume those operations were already done.
        wtx.AcceptToMemoryPool(false, maxTxFee, state, false, false, false);
        // If Dandelion enabled, relay transaction once again.
        if (GetBoolArg("-dandelion", true)) {
            wtx.RelayWalletTransaction(false);
        }
    }
}

bool CWalletTx::RelayWalletTransaction(bool fCheckInputs) {
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase() && !isAbandoned() && GetDepthInMainChain() == 0) {
        CValidationState state;
        /* GetDepthInMainChain already catches known conflicts. */
        if (InMempool() || InStempool() || 
            AcceptToMemoryPool(false, maxTxFee, state, fCheckInputs)) {
            // If Dandelion enabled, push inventory item to just one destination.
            if (GetBoolArg("-dandelion", true)) {
                int64_t nCurrTime = GetTimeMicros();
                int64_t nEmbargo = 1000000 * DANDELION_EMBARGO_MINIMUM
                        + PoissonNextSend(nCurrTime, DANDELION_EMBARGO_AVG_ADD);
                CNode::insertDandelionEmbargo(GetHash(), nEmbargo);
                //LogPrintf(
                //    "dandeliontx %s embargoed for %d seconds\n",
                //    GetHash().ToString(), (nEmbargo - nCurrTime) / 1000000);
                CInv inv(MSG_DANDELION_TX, GetHash());
                return CNode::localDandelionDestinationPushInventory(inv);
            } else {
                // LogPrintf("Relaying wtx %s\n", GetHash().ToString());
                RelayTransaction(*this);
                return true;
            }
        }
    }
    LogPrintf("CWalletTx::RelayWalletTransaction() --> invalid condition\n");
    return false;
}

set <uint256> CWalletTx::GetConflicts() const {
    set <uint256> result;
    if (pwallet != NULL) {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter &filter) const {
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if (filter & ISMINE_SPENDABLE) {
        if (fDebitCached)
            debit += nDebitCached;
        else {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY) {
        if (fWatchDebitCached)
            debit += nWatchDebitCached;
        else {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter &filter) const {
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE) {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY) {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const {
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const {
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++) {
        if (!pwallet->IsSpent(hashTx, i)) {
            const CTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool &fUseCache) const {
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool &fUseCache) const {
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); i++) {
        if (!pwallet->IsSpent(GetHash(), i)) {
            const CTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const {
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const {
    LOCK(mempool.cs);
    if (mempool.exists(GetHash())) {
        return true;
    }
    return false;
}

bool CWalletTx::InStempool() const {
    LOCK(stempool.cs);
    if (stempool.exists(GetHash())) {
        return true;
    }
    return false;
}

bool CWalletTx::IsTrusted() const {
    // Quick answer in most cases
    if (!CheckFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool or stempool.
    if (!InMempool() && !InStempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    BOOST_FOREACH(const CTxIn &txin, vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx *parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == NULL)
            return false;
        const CTxOut &parentOut = parent->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx &tx) const {
    CMutableTransaction tx1 = *this;
    CMutableTransaction tx2 = tx;
    for (unsigned int i = 0; i < tx1.vin.size(); i++) tx1.vin[i].scriptSig = CScript();
    for (unsigned int i = 0; i < tx2.vin.size(); i++) tx2.vin[i].scriptSig = CScript();
    return CTransaction(tx1) == CTransaction(tx2);
}

std::vector <uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime) {
    std::vector <uint256> result;

    LOCK(cs_wallet);
    // Sort them in chronological order
    multimap < unsigned int, CWalletTx * > mapSorted;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)&item, mapWallet)
    {
        CWalletTx &wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx *)&item, mapSorted)
    {
        CWalletTx &wtx = *item.second;
        if (wtx.RelayWalletTransaction())
            result.push_back(wtx.GetHash());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime) {
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector <uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime - 5 * 60);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetAnonymizableBalance(bool fSkipDenominated) const {
    if (fLiteMode) return 0;

    std::vector <CompactTallyItem> vecTally;
    if (!SelectCoinsGrouppedByAddresses(vecTally, fSkipDenominated)) return 0;

    CAmount nTotal = 0;

    BOOST_FOREACH(CompactTallyItem & item, vecTally)
    {
        bool fIsDenominated = IsDenominatedAmount(item.nAmount);
        if (fSkipDenominated && fIsDenominated) continue;
        // assume that the fee to create denoms be PRIVATESEND_COLLATERAL at max
        if (item.nAmount >= vecPrivateSendDenominations.back() + (fIsDenominated ? 0 : PRIVATESEND_COLLATERAL))
            nTotal += item.nAmount;
    }

    return nTotal;
}

CAmount CWallet::GetAnonymizedBalance() const {
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;

            if (pcoin->IsTrusted())
                nTotal += 0;
//                nTotal += pcoin->GetAnonymizedCredit();
        }
    }

    return nTotal;
}

CAmount CWalletTx::GetAnonymizedCredit(bool fUseCache) const {
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

//    if (fUseCache && fAnonymizedCreditCached)
//        return nAnonymizedCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++) {
        const CTxOut &txout = vout[i];
        const CTxIn txin = CTxIn(hashTx, i);

        if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominated(txin)) continue;

//        const int nRounds = pwallet->GetInputPrivateSendRounds(txin);
        const int nRounds = 0;
        if (nRounds >= nPrivateSendRounds) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAnonymizedCredit() : value out of range");
        }
    }

//    nAnonymizedCreditCached = nCredit;
//    fAnonymizedCreditCached = true;
    return nCredit;
}


CAmount CWallet::GetNeedsToBeAnonymizedBalance(CAmount nMinBalance) const {
    if (fLiteMode) return 0;

    CAmount nAnonymizedBalance = GetAnonymizedBalance();
    CAmount nNeedsToAnonymizeBalance = nPrivateSendAmount * COIN - nAnonymizedBalance;

    // try to overshoot target DS balance up to nMinBalance
    nNeedsToAnonymizeBalance += nMinBalance;

    CAmount nAnonymizableBalance = GetAnonymizableBalance();

    // anonymizable balance is way too small
    if (nAnonymizableBalance < nMinBalance) return 0;

    // not enough funds to anonymze amount we want, try the max we can
    if (nNeedsToAnonymizeBalance > nAnonymizableBalance) nNeedsToAnonymizeBalance = nAnonymizableBalance;

    // we should never exceed the pool max
    if (nNeedsToAnonymizeBalance > PRIVATESEND_POOL_MAX) nNeedsToAnonymizeBalance = PRIVATESEND_POOL_MAX;

    return nNeedsToAnonymizeBalance;
}

CAmount CWallet::GetDenominatedBalance(bool unconfirmed) const {
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;

//            nTotal += pcoin->GetDenominatedCredit(unconfirmed);
        }
    }

    return nTotal;
}

CAmount CWallet::GetMintCoins(const CAmount required, std::vector<CZerocoinEntryV3>& out){

    list<CZerocoinEntryV3> listPubCoin;
    CWalletDB(strWalletFile).ListPubCoinV3(listPubCoin);
    // sort by denomination desc and height asc
    listPubCoin.sort(CompDenominationHeightV3);

    CAmount sum(0);
    for(auto it = listPubCoin.begin();it != listPubCoin.end();)
    {
        // enough coin
        if(sum >= required)
            break;
        
        // choose largest coin if don't exceed required
        if(sum + it->denomination <= required)
        {
            out.push_back(*it);
            sum += it->denomination;
            it++;
            continue;
        }

        // seek to next denomination
        auto it2 = it;
        while(it2->denomination == it->denomination)
            it2++;

        // if can use lower denomination dont use this
        CAmount lowerDenomination(0);
        if(it2 != listPubCoin.end())
        {
            lowerDenomination += it2->denomination;
        }
        
        // if lower denomination coin can't full fill using large coin
        if(sum + lowerDenomination < required)
        {
            out.push_back(*it);
            sum += it->denomination;
            it++;
            continue;
        }

        // go to next denomination
        int currentDenomination = it->denomination;
        while(it != listPubCoin.end() && currentDenomination == it->denomination)
            it++;
    }

    return sum;
}

CAmount CWallet::GetUnconfirmedBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && 
                (pcoin->InMempool() || pcoin->InStempool()))
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && 
                (pcoin->InMempool() || pcoin->InStempool()))
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

// Recursively determine the rounds of a given input (How deep is the PrivateSend chain for a given input)
int CWallet::GetRealInputPrivateSendRounds(CTxIn txin, int nRounds) const
{
    static std::map<uint256, CMutableTransaction> mDenomWtxes;

    if(nRounds >= 16) return 15; // 16 rounds max

    uint256 hash = txin.prevout.hash;
    unsigned int nout = txin.prevout.n;

    const CWalletTx* wtx = GetWalletTx(hash);
    if(wtx != NULL)
    {
        std::map<uint256, CMutableTransaction>::const_iterator mdwi = mDenomWtxes.find(hash);
        if (mdwi == mDenomWtxes.end()) {
            // not known yet, let's add it
            LogPrint("privatesend", "GetRealInputPrivateSendRounds INSERTING %s\n", hash.ToString());
            mDenomWtxes[hash] = CMutableTransaction(*wtx);
        } else if(mDenomWtxes[hash].vout[nout].nRounds != -10) {
            // found and it's not an initial value, just return it
            return mDenomWtxes[hash].vout[nout].nRounds;
        }


        // bounds check
        if (nout >= wtx->vout.size()) {
            // should never actually hit this
            LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, -4);
            return -4;
        }

        if (IsCollateralAmount(wtx->vout[nout].nValue)) {
            mDenomWtxes[hash].vout[nout].nRounds = -3;
            LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        //make sure the final output is non-denominate
        if (!IsDenominatedAmount(wtx->vout[nout].nValue)) { //NOT DENOM
            mDenomWtxes[hash].vout[nout].nRounds = -2;
            LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        bool fAllDenoms = true;
        BOOST_FOREACH(CTxOut out, wtx->vout) {
            fAllDenoms = fAllDenoms && IsDenominatedAmount(out.nValue);
        }

        // this one is denominated but there is another non-denominated output found in the same tx
        if (!fAllDenoms) {
            mDenomWtxes[hash].vout[nout].nRounds = 0;
            LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        int nShortest = -10; // an initial value, should be no way to get this by calculations
        bool fDenomFound = false;
        // only denoms here so let's look up
        BOOST_FOREACH(CTxIn txinNext, wtx->vin) {
            if (IsMine(txinNext)) {
                int n = GetRealInputPrivateSendRounds(txinNext, nRounds + 1);
                // denom found, find the shortest chain or initially assign nShortest with the first found value
                if(n >= 0 && (n < nShortest || nShortest == -10)) {
                    nShortest = n;
                    fDenomFound = true;
                }
            }
        }
        mDenomWtxes[hash].vout[nout].nRounds = fDenomFound
                                               ? (nShortest >= 15 ? 16 : nShortest + 1) // good, we a +1 to the shortest one but only 16 rounds max allowed
                                               : 0;            // too bad, we are the fist one in that chain
        LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
        return mDenomWtxes[hash].vout[nout].nRounds;
    }

    return nRounds - 1;
}

// respect current settings
int CWallet::GetInputPrivateSendRounds(CTxIn txin) const
{
    LOCK(cs_wallet);
    int realPrivateSendRounds = GetRealInputPrivateSendRounds(txin, 0);
    return realPrivateSendRounds > nPrivateSendRounds ? nPrivateSendRounds : realPrivateSendRounds;
}


bool CWallet::IsDenominated(const CTxIn &txin) const {
    LOCK(cs_wallet);

    map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
    if (mi != mapWallet.end()) {
        const CWalletTx &prev = (*mi).second;
        if (txin.prevout.n < prev.vout.size()) {
            return IsDenominatedAmount(prev.vout[txin.prevout.n].nValue);
        }
    }

    return false;
}

bool CWallet::IsDenominatedAmount(CAmount nInputAmount) const {
    BOOST_FOREACH(CAmount d, vecPrivateSendDenominations)
    if(nInputAmount == d)
        return true;
    return false;
}

int CWallet::CountInputsWithAmount(CAmount nInputAmount) {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted()) {
                int nDepth = pcoin->GetDepthInMainChain(false);

                for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                    COutput out = COutput(pcoin, i, nDepth, true, true);
                    CTxIn txin = CTxIn(out.tx->GetHash(), out.i);

                    if (out.tx->vout[out.i].nValue != nInputAmount) continue;
                    if (!IsDenominatedAmount(pcoin->vout[i].nValue)) continue;
                    if (IsSpent(out.tx->GetHash(), i) || IsMine(pcoin->vout[i]) != ISMINE_SPENDABLE ||
                        !IsDenominated(txin))
                        continue;

                    nTotal++;
                }
            }
        }
    }

    return nTotal;
}

bool CWallet::HasCollateralInputs(bool fOnlyConfirmed) const {
    vector <COutput> vCoins;
    AvailableCoins(vCoins, fOnlyConfirmed, NULL, false, ONLY_PRIVATESEND_COLLATERAL);

    return !vCoins.empty();
}


bool CWallet::IsCollateralAmount(CAmount nInputAmount) const {
    // collateral inputs should always be a 2x..4x of PRIVATESEND_COLLATERAL
    return nInputAmount >= PRIVATESEND_COLLATERAL * 2 &&
           nInputAmount <= PRIVATESEND_COLLATERAL * 4 &&
           nInputAmount % PRIVATESEND_COLLATERAL == 0;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

void CWallet::AvailableCoins(vector <COutput> &vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl,
                             bool fIncludeZeroValue, AvailableCoinsType nCoinType, bool fUseInstantSend) const {
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const uint256 &wtxid = it->first;
            const CWalletTx *pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain(false);
            // do not use IX for inputs that have less then INSTANTSEND_CONFIRMATIONS_REQUIRED blockchain confirmations
//            if (fUseInstantSend && nDepth < INSTANTSEND_CONFIRMATIONS_REQUIRED)
//                continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool())
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                bool found = false;
                if (nCoinType == ONLY_DENOMINATED) {
                    found = IsDenominatedAmount(pcoin->vout[i].nValue);
                } else if (nCoinType == ONLY_NOT1000IFMN) {
                    found = !(fZNode && pcoin->vout[i].nValue == ZNODE_COIN_REQUIRED * COIN);
                } else if (nCoinType == ONLY_NONDENOMINATED_NOT1000IFMN) {
                    if (IsCollateralAmount(pcoin->vout[i].nValue)) continue; // do not use collateral amounts
                    found = !IsDenominatedAmount(pcoin->vout[i].nValue);
                    if (found && fZNode) found = pcoin->vout[i].nValue != ZNODE_COIN_REQUIRED * COIN; // do not use Hot MN funds
                } else if (nCoinType == ONLY_1000) {
                    found = pcoin->vout[i].nValue == ZNODE_COIN_REQUIRED * COIN;
                } else if (nCoinType == ONLY_PRIVATESEND_COLLATERAL) {
                    found = IsCollateralAmount(pcoin->vout[i].nValue);
                } else {
                    found = true;
                }
                if (!found) continue;

                isminetype mine = IsMine(pcoin->vout[i]);
                if (!(IsSpent(wtxid, i)) &&
                        mine != ISMINE_NO &&
                        (!IsLockedCoin((*it).first, i) || nCoinType == ONLY_1000) &&
                        (pcoin->vout[i].nValue > nMinimumInputValue) &&
                        (
                                !coinControl ||
                                !coinControl->HasSelected() ||
                                coinControl->fAllowOtherInputs ||
                                coinControl->IsSelected(COutPoint((*it).first, i))
                        )
                    ) {
                    vCoins.push_back(COutput(pcoin, i, nDepth,
                                             ((mine & ISMINE_SPENDABLE) != ISMINE_NO) ||
                                             (coinControl && coinControl->fAllowWatchOnly &&
                                              (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO),
                                             (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO));
                }
            }
        }
    }
}


bool CWallet::SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector <CTxIn> &vecTxInRet, CAmount &nValueRet,
                              int nPrivateSendRoundsMin, int nPrivateSendRoundsMax) const {
    CCoinControl *coinControl = NULL;

    vecTxInRet.clear();
    nValueRet = 0;

    vector <COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl, false, nPrivateSendRoundsMin < 0 ? ONLY_NONDENOMINATED_NOT1000IFMN : ONLY_DENOMINATED);

    //order the array so largest nondenom are first, then denominations, then very small inputs.
    sort(vCoins.rbegin(), vCoins.rend(), CompareByPriority());

    BOOST_FOREACH(const COutput &out, vCoins)
    {
        //do not allow inputs less than 1/10th of minimum value
        if (out.tx->vout[out.i].nValue < nValueMin / 10) continue;
        //do not allow collaterals to be selected
        if (IsCollateralAmount(out.tx->vout[out.i].nValue)) continue;
        if (fZNode && out.tx->vout[out.i].nValue == ZNODE_COIN_REQUIRED * COIN) continue; //znode input

        if (nValueRet + out.tx->vout[out.i].nValue <= nValueMax) {
            CTxIn txin = CTxIn(out.tx->GetHash(), out.i);

            int nRounds = GetInputPrivateSendRounds(txin);
            if (nRounds >= nPrivateSendRoundsMax) continue;
            if (nRounds < nPrivateSendRoundsMin) continue;

            txin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->vout[out.i].nValue;
            vecTxInRet.push_back(txin);
        }
    }

    return nValueRet >= nValueMin;
}

// znode
bool CWallet::GetCollateralTxIn(CTxIn& txinRet, CAmount& nValueRet) const
{
    vector<COutput> vCoins;

    AvailableCoins(vCoins);

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        if(IsCollateralAmount(out.tx->vout[out.i].nValue))
        {
            txinRet = CTxIn(out.tx->GetHash(), out.i);
            txinRet.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet = out.tx->vout[out.i].nValue;
            return true;
        }
    }

    return false;
}

bool CWallet::GetZnodeVinAndKeys(CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet, std::string strTxHash,
                                 std::string strOutputIndex) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    std::vector <COutput> vPossibleCoins;
    AvailableCoins(vPossibleCoins, true, NULL, false, ONLY_1000);
    if (vPossibleCoins.empty()) {
        LogPrintf("CWallet::GetZnodeVinAndKeys -- Could not locate any valid znode vin\n");
        return false;
    }

    if (strTxHash.empty()) // No output specified, select the first one
        return GetVinAndKeysFromOutput(vPossibleCoins[0], txinRet, pubKeyRet, keyRet);

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);
    int nOutputIndex = atoi(strOutputIndex.c_str());

    BOOST_FOREACH(COutput & out, vPossibleCoins)
    if (out.tx->GetHash() == txHash && out.i == nOutputIndex) // found it!
        return GetVinAndKeysFromOutput(out, txinRet, pubKeyRet, keyRet);

    LogPrintf("CWallet::GetZnodeVinAndKeys -- Could not locate specified znode vin\n");
    return false;
}

bool CWallet::GetVinAndKeysFromOutput(COutput out, CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    txinRet = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
        return false;
    }

    if (!GetKey(keyID, keyRet)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }

    pubKeyRet = keyRet.GetPubKey();
    return true;
}

//[zcoin]
void CWallet::ListAvailableCoinsMintCoins(vector <COutput> &vCoins, bool fOnlyConfirmed) const {
    vCoins.clear();
    {
        LOCK(cs_wallet);
        list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.ListPubCoin(listPubCoin);
        LogPrintf("listPubCoin.size()=%s\n", listPubCoin.size());
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
//            LogPrintf("pcoin=%s\n", pcoin->GetHash().ToString());
            if (!CheckFinalTx(*pcoin)) {
                LogPrintf("!CheckFinalTx(*pcoin)=%s\n", !CheckFinalTx(*pcoin));
                continue;
            }

            if (fOnlyConfirmed && !pcoin->IsTrusted()) {
                LogPrintf("fOnlyConfirmed = %s, !pcoin->IsTrusted()\n", fOnlyConfirmed, !pcoin->IsTrusted());
                continue;
            }

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) {
                LogPrintf("Not trusted\n");
                continue;
            }

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0) {
                LogPrintf("nDepth=%s\n", nDepth);
                continue;
            }
            LogPrintf("pcoin->vout.size()=%s\n", pcoin->vout.size());

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                if (pcoin->vout[i].scriptPubKey.IsZerocoinMint()) {
                    CTxOut txout = pcoin->vout[i];
                    vector<unsigned char> vchZeroMint;
                    vchZeroMint.insert(vchZeroMint.end(), txout.scriptPubKey.begin() + 6,
                                       txout.scriptPubKey.begin() + txout.scriptPubKey.size());

                    CBigNum pubCoin;
                    pubCoin.setvch(vchZeroMint);
                    LogPrintf("Pubcoin=%s\n", pubCoin.ToString());
                    // CHECKING PROCESS
                    BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
//                        LogPrintf("*******\n");
//                        LogPrintf("pubCoinItem.value=%s,\n", pubCoinItem.value.ToString());
//                        LogPrintf("pubCoinItem.IsUsed=%s\n, ", pubCoinItem.IsUsed);
//                        LogPrintf("pubCoinItem.randomness=%s\n, ", pubCoinItem.randomness);
//                        LogPrintf("pubCoinItem.serialNumber=%s\n, ", pubCoinItem.serialNumber);
                        if (pubCoinItem.value == pubCoin && pubCoinItem.IsUsed == false &&
                            pubCoinItem.randomness != 0 && pubCoinItem.serialNumber != 0) {
                            vCoins.push_back(COutput(pcoin, i, nDepth, true, true));
                            LogPrintf("-->OK\n");
                        }
                    }

                }
            }
        }
    }
}

static void ApproximateBestSubset(vector <pair<CAmount, pair<const CWalletTx *, unsigned int> >> vValue,
                                  const CAmount &nTotalLower,
                                  const CAmount &nTargetValue,
                                  vector<char> &vfBest, CAmount &nBest, int iterations = 1000) {
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++) {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
            for (unsigned int i = 0; i < vValue.size(); i++) {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand() & 1 : !vfIncluded[i]) {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue) {
                        fReachedTarget = true;
                        if (nTotal < nBest) {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount &nTargetValue, const int nConfMine, const int nConfTheirs,
                                 const uint64_t nMaxAncestors, vector <COutput> vCoins,
                                 set <pair<const CWalletTx *, unsigned int>> &setCoinsRet,
                                 CAmount &nValueRet) const {
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair <CAmount, pair<const CWalletTx *, unsigned int>> coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    vector <pair<CAmount, pair<const CWalletTx *, unsigned int> >> vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(const COutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        if (!mempool.TransactionWithinChainLimit(pcoin->GetHash(), nMaxAncestors))
            continue;

        int i = output.i;
        CAmount n = pcoin->vout[i].nValue;

        pair <CAmount, pair<const CWalletTx *, unsigned int>> coin = make_pair(n, make_pair(pcoin, i));

        if (n == nTargetValue) {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        } else if (n < nTargetValue + MIN_CHANGE) {
            vValue.push_back(coin);
            nTotalLower += n;
        } else if (n < coinLowestLarger.first) {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue) {
        for (unsigned int i = 0; i < vValue.size(); ++i) {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue) {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest)) {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    } else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i]) {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        LogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LogPrint("selectcoins", "%s ", FormatMoney(vValue[i].first));
        LogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const vector <COutput> &vAvailableCoins, const CAmount &nTargetValue,
                          set <pair<const CWalletTx *, unsigned int>> &setCoinsRet, CAmount &nValueRet,
                          const CCoinControl *coinControl, AvailableCoinsType nCoinType, bool fUseInstantSend) const {
    vector <COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs) {
        BOOST_FOREACH(const COutput &out, vCoins)
        {
            if (!out.fSpendable)
                continue;
            if (nCoinType == ONLY_DENOMINATED) {
                CTxIn txin = CTxIn(out.tx->GetHash(), out.i);
                int nRounds = GetInputPrivateSendRounds(txin);
                // make sure it's actually anonymized
                if (nRounds < nPrivateSendRounds) continue;
            }
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    //if we're doing only denominated, we need to round up to the nearest smallest denomination
    if (nCoinType == ONLY_DENOMINATED) {
        CAmount nSmallestDenom = vecPrivateSendDenominations.back();
        // Make outputs by looping through denominations, from large to small
        BOOST_FOREACH(CAmount nDenom, vecPrivateSendDenominations)
        {
            BOOST_FOREACH(const COutput &out, vCoins)
            {
                //make sure it's the denom we're looking for, round the amount up to smallest denom
                if (out.tx->vout[out.i].nValue == nDenom && nValueRet + nDenom < nTargetValue + nSmallestDenom) {
                    CTxIn txin = CTxIn(out.tx->GetHash(), out.i);
                    int nRounds = GetInputPrivateSendRounds(txin);
                    // make sure it's actually anonymized
                    if (nRounds < nPrivateSendRounds) continue;
                    nValueRet += nDenom;
                    setCoinsRet.insert(make_pair(out.tx, out.i));
                }
            }
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    set <pair<const CWalletTx *, uint32_t>> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector <COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint &outpoint, vPresetInputs)
    {
        map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end()) {
            const CWalletTx *pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->vout[outpoint.n].nValue;
            setPresetCoins.insert(make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (vector<COutput>::iterator it = vCoins.begin();
         it != vCoins.end() && coinControl && coinControl->HasSelected();) {
        if (setPresetCoins.count(make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    size_t nMaxChainLength = std::min(GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT),
                                      GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    bool res = nTargetValue <= nValueFromPresetInputs ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, 0, vCoins, setCoinsRet, nValueRet) ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, 0, vCoins, setCoinsRet, nValueRet) ||
               (bSpendZeroConfChange &&
                SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, 2, vCoins, setCoinsRet,
                                   nValueRet)) ||
               (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1,
                                                           std::min((size_t) 4, nMaxChainLength / 3), vCoins,
                                                           setCoinsRet, nValueRet)) ||
               (bSpendZeroConfChange &&
                SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength / 2, vCoins,
                                   setCoinsRet, nValueRet)) ||
               (bSpendZeroConfChange &&
                SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength, vCoins,
                                   setCoinsRet,
                                   nValueRet)) ||
               (bSpendZeroConfChange && !fRejectLongChains &&
                SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1,
                                   std::numeric_limits<uint64_t>::max(),
                                   vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::FundTransaction(CMutableTransaction &tx, CAmount &nFeeRet, bool overrideEstimatedFeeRate,
                              const CFeeRate &specificFeeRate, int &nChangePosInOut, std::string &strFailReason,
                              bool includeWatching, bool lockUnspents, const CTxDestination &destChange) {
    vector <CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    BOOST_FOREACH(const CTxOut &txOut, tx.vout)
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.destChange = destChange;
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = includeWatching;
    coinControl.fOverrideFeeRate = overrideEstimatedFeeRate;
    coinControl.nFeeRate = specificFeeRate;

    BOOST_FOREACH(const CTxIn &txin, tx.vin)
        coinControl.Select(txin.prevout);

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosInOut, strFailReason, &coinControl, false))
        return false;

    if (nChangePosInOut != -1)
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, wtx.vout[nChangePosInOut]);

    // Add new txins (keeping original txin scriptSig/order)
    BOOST_FOREACH(const CTxIn &txin, wtx.vin)
    {
        if (!coinControl.IsSelected(txin.prevout)) {
            tx.vin.push_back(txin);

            if (lockUnspents) {
                LOCK2(cs_main, cs_wallet);
                LockCoin(txin.prevout);
            }
        }
    }

    return true;
}

bool CWallet::ConvertList(std::vector <CTxIn> vecTxIn, std::vector <CAmount> &vecAmounts) {
    BOOST_FOREACH(CTxIn txin, vecTxIn) {
        if (mapWallet.count(txin.prevout.hash)) {
            CWalletTx &wtx = mapWallet[txin.prevout.hash];
            if (txin.prevout.n < wtx.vout.size()) {
                vecAmounts.push_back(wtx.vout[txin.prevout.n].nValue);
            }
        } else {
            LogPrintf("CWallet::ConvertList -- Couldn't find transaction\n");
        }
    }
    return true;
}

bool CWallet::SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax,
                                         std::vector <CTxIn> &vecTxInRet, std::vector <COutput> &vCoinsRet,
                                         CAmount &nValueRet, int nPrivateSendRoundsMin, int nPrivateSendRoundsMax) {
    vecTxInRet.clear();
    vCoinsRet.clear();
    nValueRet = 0;

    vector <COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, ONLY_DENOMINATED);

    std::random_shuffle(vCoins.rbegin(), vCoins.rend(), GetRandInt);

    // ( bit on if present )
    // bit 0 - 100ZCOIN+1
    // bit 1 - 10ZCOIN+1
    // bit 2 - 1ZCOIN+1
    // bit 3 - .1ZCOIN+1

    std::vector<int> vecBits;
    if (!darkSendPool.GetDenominationsBits(nDenom, vecBits)) {
        return false;
    }

    int nDenomResult = 0;

    InsecureRand insecureRand;
    BOOST_FOREACH(const COutput &out, vCoins)
    {
        // znode-like input should not be selected by AvailableCoins now anyway
        //if(out.tx->vout[out.i].nValue == 1000*COIN) continue;
        if (nValueRet + out.tx->vout[out.i].nValue <= nValueMax) {

            CTxIn txin = CTxIn(out.tx->GetHash(), out.i);

            int nRounds = GetInputPrivateSendRounds(txin);
            if (nRounds >= nPrivateSendRoundsMax) continue;
            if (nRounds < nPrivateSendRoundsMin) continue;

            BOOST_FOREACH(int nBit, vecBits) {
                if (out.tx->vout[out.i].nValue == vecPrivateSendDenominations[nBit]) {
                    if (nValueRet >= nValueMin) {
                        //randomly reduce the max amount we'll submit (for anonymity)
                        nValueMax -= insecureRand(nValueMax/5);
                        //on average use 50% of the inputs or less
                        int r = insecureRand(vCoins.size());
                        if ((int) vecTxInRet.size() > r) return true;
                    }
                    txin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
                    nValueRet += out.tx->vout[out.i].nValue;
                    vecTxInRet.push_back(txin);
                    vCoinsRet.push_back(out);
                    nDenomResult |= 1 << nBit;
                }
            }
        }
    }

    return nValueRet >= nValueMin && nDenom == nDenomResult;
}

bool CWallet::CreateCollateralTransaction(CMutableTransaction &txCollateral, std::string &strReason) {
    txCollateral.vin.clear();
    txCollateral.vout.clear();

    CReserveKey reservekey(this);
    CAmount nValue = 0;
    CTxIn txinCollateral;

    if (!GetCollateralTxIn(txinCollateral, nValue)) {
        strReason = "PrivateSend requires a collateral transaction and could not locate an acceptable input!";
        return false;
    }

    // make our change address
    CScript scriptChange;
    CPubKey vchPubKey;
    assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
    scriptChange = GetScriptForDestination(vchPubKey.GetID());
    reservekey.KeepKey();

    txCollateral.vin.push_back(txinCollateral);

    //pay collateral charge in fees
    CTxOut txout = CTxOut(nValue - PRIVATESEND_COLLATERAL, scriptChange);
    txCollateral.vout.push_back(txout);
    CAmount amount;
    if (!SignSignature(*this, txinCollateral.prevPubKey, txCollateral, 0, amount, int(SIGHASH_ALL | SIGHASH_ANYONECANPAY))) {
        strReason = "Unable to sign collateral transaction!";
        return false;
    }

    return true;
}

bool CWallet::SelectCoinsGrouppedByAddresses(std::vector <CompactTallyItem> &vecTallyRet, bool fSkipDenominated,
                                             bool fAnonymizable) const {
    LOCK2(cs_main, cs_wallet);

    isminefilter filter = ISMINE_SPENDABLE;

    // try to use cache
    if (fAnonymizable) {
        if(fSkipDenominated && fAnonymizableTallyCachedNonDenom) {
            vecTallyRet = vecAnonymizableTallyCachedNonDenom;
            LogPrint("selectcoins", "SelectCoinsGrouppedByAddresses - using cache for non-denom inputs\n");
            return vecTallyRet.size() > 0;
        }
        if(!fSkipDenominated && fAnonymizableTallyCached) {
            vecTallyRet = vecAnonymizableTallyCached;
            LogPrint("selectcoins", "SelectCoinsGrouppedByAddresses - using cache for all inputs\n");
            return vecTallyRet.size() > 0;
        }
    }

    // Tally
    map <CBitcoinAddress, CompactTallyItem> mapTally;
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;

        if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0) continue;
        if (!fAnonymizable && !wtx.IsTrusted()) continue;

        for (unsigned int i = 0; i < wtx.vout.size(); i++) {
            CTxDestination address;
            if (!ExtractDestination(wtx.vout[i].scriptPubKey, address)) continue;

            isminefilter mine = ::IsMine(*this, address);
            if (!(mine & filter)) continue;

            if (IsSpent(wtx.GetHash(), i) || IsLockedCoin(wtx.GetHash(), i)) continue;

            if (fSkipDenominated && IsDenominatedAmount(wtx.vout[i].nValue)) continue;

            if (fAnonymizable) {
                // ignore collaterals
                if (IsCollateralAmount(wtx.vout[i].nValue)) continue;
                if (fZNode && wtx.vout[i].nValue == ZNODE_COIN_REQUIRED * COIN) continue;
                // ignore outputs that are 10 times smaller then the smallest denomination
                // otherwise they will just lead to higher fee / lower priority
                if (wtx.vout[i].nValue <= vecPrivateSendDenominations.back() / 10) continue;
                // ignore anonymized
                if(GetInputPrivateSendRounds(CTxIn(wtx.GetHash(), i)) >= nPrivateSendRounds) continue;
            }

            CompactTallyItem &item = mapTally[address];
            item.address = address;
            item.nAmount += wtx.vout[i].nValue;
            item.vecTxIn.push_back(CTxIn(wtx.GetHash(), i));
        }
    }

    // construct resulting vector
    vecTallyRet.clear();
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CompactTallyItem)&item, mapTally) {
        if (fAnonymizable && item.second.nAmount < vecPrivateSendDenominations.back()) continue;
        vecTallyRet.push_back(item.second);
    }

    // order by amounts per address, from smallest to largest
    sort(vecTallyRet.rbegin(), vecTallyRet.rend(), CompareByAmount());

    // cache anonymizable for later use
    if (fAnonymizable) {
        if (fSkipDenominated) {
            vecAnonymizableTallyCachedNonDenom = vecTallyRet;
            fAnonymizableTallyCachedNonDenom = true;
        } else {
            vecAnonymizableTallyCached = vecTallyRet;
            fAnonymizableTallyCached = true;
        }
    }

    // debug
    std::string strMessage = "SelectCoinsGrouppedByAddresses - vecTallyRet:\n";
    BOOST_FOREACH(CompactTallyItem & item, vecTallyRet)
        strMessage += strprintf("  %s %f\n", item.address.ToString().c_str(), float(item.nAmount) / COIN);
    LogPrint("selectcoins", "%s", strMessage);

    return vecTallyRet.size() > 0;
}

bool CWallet::CreateTransaction(const vector <CRecipient> &vecSend, CWalletTx &wtxNew, CReserveKey &reservekey,
                                CAmount &nFeeRet,
                                int &nChangePosInOut, std::string &strFailReason, const CCoinControl *coinControl,
                                bool sign, AvailableCoinsType nCoinType, bool fUseInstantSend) {
    LogPrintf("CreateTransaction()\n");
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    BOOST_FOREACH(const CRecipient &recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int) txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            std::vector <COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, coinControl, false, nCoinType, fUseInstantSend);

            nFeeRet = payTxFee.GetFeePerK();
            // Start with no fee and loop until there is enough fee
            while (true) {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                txNew.wit.SetNull();
                wtxNew.fFromMe = true;
//                bool fFirst = true;
                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH(const CRecipient &recipient, vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (txout.IsDust(::minRelayTxFee)) {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0) {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        } else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                set <pair<const CWalletTx *, unsigned int>> setCoins;
                CAmount nValueIn = 0;
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl)) {
                    if (nCoinType == ONLY_NOT1000IFMN) {
                        strFailReason = _("Unable to locate enough funds for this transaction that are not equal 1000 XZC.");
                    } else if (nCoinType == ONLY_NONDENOMINATED_NOT1000IFMN) {
                        strFailReason = _("Unable to locate enough PrivateSend non-denominated funds for this transaction that are not equal 1000 XZC.");
                    } else if (nCoinType == ONLY_DENOMINATED) {
                        strFailReason = _("Unable to locate enough PrivateSend denominated funds for this transaction.");
                        strFailReason += _("PrivateSend uses exact denominated amounts to send funds, you might simply need to anonymize some more coins.");
                    } else if (nValueIn < nValueToSelect) {
                        strFailReason = _("Insufficient funds.");
                    }
                    return false;
                }

                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    assert(age >= 0);
                    if (age != 0)
                        age += 1;
                    dPriority += (double) nCredit * age;
                }

                const CAmount nChange = nValueIn - nValueToSelect;
                if (nChange > 0) {
                    //over pay for denominated transactions
                    if (nCoinType == ONLY_DENOMINATED) {
                        nFeeRet += nChange;
                        wtxNew.mapValue["DS"] = "1";
                        // recheck skipped denominations during next mixing
                        darkSendPool.ClearSkippedDenominations();
                    } else {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange;

                        // coin control: send change to custom address
                        if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                            scriptChange = GetScriptForDestination(coinControl->destChange);

                            // no coin control: send change to newly generated address
                        else {
                            // Note: We use a new key here to keep it from being obvious which side is the change.
                            //  The drawback is that by not reusing a previous key, the change may be lost if a
                            //  backup is restored, if the backup doesn't have the new private key for the change.
                            //  If we reused the old key, it would be possible to add code to look for and
                            //  rediscover unknown transactions that were written with keys of ours to recover
                            //  post-backup change.

                            // Reserve a new key pair from key pool
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            if (!ret) {
                                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                                return false;
                            }

                            scriptChange = GetScriptForDestination(vchPubKey.GetID());
                        }

                        CTxOut newTxOut(nChange, scriptChange);

                        // We do not move dust-change to fees, because the sender would end up paying more than requested.
                        // This would be against the purpose of the all-inclusive feature.
                        // So instead we raise the change and deduct from the recipient.
                        if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(::minRelayTxFee)) {
                            CAmount nDust = newTxOut.GetDustThreshold(::minRelayTxFee) - newTxOut.nValue;
                            newTxOut.nValue += nDust; // raise change until no more dust
                            for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                            {
                                if (vecSend[i].fSubtractFeeFromAmount) {
                                    txNew.vout[i].nValue -= nDust;
                                    if (txNew.vout[i].IsDust(::minRelayTxFee)) {
                                        strFailReason = _(
                                                "The transaction amount is too small to send after the fee has been deducted");
                                        return false;
                                    }
                                    break;
                                }
                            }
                        }

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust(::minRelayTxFee)) {
                            nChangePosInOut = -1;
                            nFeeRet += nChange;
                            reservekey.ReturnKey();
                        } else {
                            if (nChangePosInOut == -1) {
                                // Insert change txn at random position:
                                nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                            } else if ((unsigned int) nChangePosInOut > txNew.vout.size()) {
                                strFailReason = _("Change index out of range");
                                return false;
                            }

                            vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                            txNew.vout.insert(position, newTxOut);
                        }
                    }
                } else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int) &coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second, CScript(), std::numeric_limits < unsigned int > ::max() - 1));

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int) &coin, setCoins)
                {
                    bool signSuccess;
                    const CScript &scriptPubKey = coin.first->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->vout[coin.second].nValue, SIGHASH_ALL),
                                scriptPubKey, sigdata);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata);

                    if (!signSuccess) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(txNew, nIn, sigdata);
                    }

                    nIn++;
                }

                unsigned int nBytes = GetVirtualTransactionSize(txNew);

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) {
                    BOOST_FOREACH(CTxIn & vin, txNew.vin)
                        vin.scriptSig = CScript();
                    txNew.wit.SetNull();
                }

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);

                // Limit size
                if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                    strFailReason = _("Transaction too large");
                    return false;
                }

                dPriority = wtxNew.ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }
 
                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                    nFeeNeeded = coinControl->nMinimumTotalFee;
                }
                if (coinControl && coinControl->fOverrideFeeRate)
                    nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(txNew, 0, 0, 0, 0, false, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey) {
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction fBroadcastTransactions = %B:\n%s", 
                  fBroadcastTransactions, wtxNew.ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB *pwalletdb = fFileBacked ? new CWalletDB(strWalletFile, "r+") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew, false, pwalletdb);

            // Notify that old coins are spent
            set < CWalletTx * > setCoins;
            BOOST_FOREACH(const CTxIn &txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        if (fBroadcastTransactions) {
            CValidationState state;
            // Broadcast
            if (!wtxNew.AcceptToMemoryPool(false, maxTxFee, state, true)) {
                LogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n",
                          state.GetRejectReason());
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                LogPrintf("Successfully accepted txn %s to mempool/stempool, relaying!\n", 
                          wtxNew.GetHash().ToString());
                wtxNew.RelayWalletTransaction();
            }
        }
    }
    return true;
}

bool CWallet::EraseFromWallet(uint256 hash) {
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}

bool CWallet::CreateZerocoinMintModel(
        string &stringError,
        const std::vector<std::pair<std::string,int>>& denominationPairs,
        MintAlgorithm algo) {
    if(algo == SIGMA) {
        // Convert denominations from string to sigma denominations.
        std::vector<std::pair<sigma::CoinDenominationV3, int>> sigma_denominations;
        for(const std::pair<std::string,int>& pair: denominationPairs) {
            sigma::CoinDenominationV3 denom;
            if (!StringToDenomination(pair.first, denom)) {
                stringError = "Unrecognized sigma denomination " + pair.first;
                return false;
            }
            sigma_denominations.push_back(std::make_pair(denom, pair.second));
        }
        return CreateZerocoinMintModelV3(stringError, sigma_denominations);
    }
    else if (algo == ZEROCOIN) {
        // Convert denominations from string to integers.
        std::vector<std::pair<int, int>> int_denominations;
        for(const std::pair<std::string,int>& pair: denominationPairs) {
            int_denominations.push_back(std::make_pair(std::atoi(pair.first.c_str()), pair.second));
        }
        return CreateZerocoinMintModelV2(stringError, int_denominations);
    }
    else
        return false;
}

bool CWallet::CreateZerocoinMintModelV3(
        string &stringError,
        const std::vector<std::pair<sigma::CoinDenominationV3, int>>& denominationPairs) {
    vector<CRecipient> vecSend;
    vector<sigma::PrivateCoinV3> privCoins;
    CWalletTx wtx;

    for(const std::pair<sigma::CoinDenominationV3, int>& denominationPair: denominationPairs) {
        sigma::CoinDenominationV3 denomination = denominationPair.first;
        int64_t denominationValue;
        if (!DenominationToInteger(denomination, denominationValue)) {
            throw runtime_error(
                "mintzerocoin <amount>(0.1, 0.5, 1, 10, 100) (\"zcoinaddress\")\n");
        }

        int64_t coinCount = denominationPair.second;

        LogPrintf("rpcWallet.mintzerocoin() denomination = %s, nAmount = %s \n", 
            denominationValue, coinCount);

        if(coinCount < 0) {
            throw runtime_error("Coin count negative (\"zcoinaddress\")\n");
        }

        sigma::ParamsV3* zcParams = sigma::ParamsV3::get_default();

        for(int64_t i = 0; i < coinCount; i++) {
            // The following constructor does all the work of minting a brand
            // new zerocoin. It stores all the private values inside the
            // PrivateCoin object. This includes the coin secrets, which must be
            // stored in a secure location (wallet) at the client.
            sigma::PrivateCoinV3 newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_3);
            // Get a copy of the 'public' portion of the coin. You should
            // embed this into a Zerocoin 'MINT' transaction along with a series
            // of currency inputs totaling the assigned value of one zerocoin.

            sigma::PublicCoinV3 pubCoin = newCoin.getPublicCoin();

            // Validate
            if (!pubCoin.validate()) {
                stringError = "Unable to mint a V3 sigma coin.";
                return false;
            }

            // Create script for coin
            CScript scriptSerializedCoin; 
            // opcode is inserted as 1 byte according to file script/script.h
            scriptSerializedCoin << OP_ZEROCOINMINTV3; 

            // MARTUN: Commenting this for now.
            // this one will probably be written as int64_t, which means it will be written in as few bytes as necessary, and one more byte for sign. In our case our 34 will take 2 bytes, 1 for the number 34 and another one for the sign.
            // scriptSerializedCoin << pubCoin.getValue().memoryRequired();
            
            // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
            std::vector<unsigned char> vch = pubCoin.getValue().getvch();
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

            CRecipient recipient = {scriptSerializedCoin, denominationValue, false};

            vecSend.push_back(recipient);
            privCoins.push_back(newCoin);
        }
    }

    stringError = pwalletMain->MintAndStoreZerocoinV3(vecSend, privCoins, wtx);

    if (stringError != "") {
        return false;
    }

    return true;
}

bool CWallet::CreateZerocoinMintModelV2(
        string &stringError,
        const std::vector<std::pair<int,int>>& denominationPairs) {
    libzerocoin::CoinDenomination denomination;
    // Always use modulus v2
    libzerocoin::Params *zcParams = ZCParamsV2;

    vector<CRecipient> vecSend;
    vector<libzerocoin::PrivateCoin> privCoins;
    CWalletTx wtx;

    std::pair<int,int> denominationPair;
    BOOST_FOREACH(denominationPair, denominationPairs){
        int denominationValue = denominationPair.first;
        switch(denominationValue){
            case 1:
                denomination = libzerocoin::ZQ_LOVELACE;
                break;
            case 10:
                denomination = libzerocoin::ZQ_GOLDWASSER;
                break;
            case 25:
                denomination = libzerocoin::ZQ_RACKOFF;
                break;
            case 50:
                denomination = libzerocoin::ZQ_PEDERSEN;
                break;
            case 100:
                denomination = libzerocoin::ZQ_WILLIAMSON;                                                
                break;
            default:
                throw runtime_error(
                    "mintzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
        }

        int64_t amount = denominationPair.second;

        LogPrintf("rpcWallet.mintzerocoin() denomination = %s, nAmount = %s \n", denominationValue, amount);
    
        if(amount < 0){
                throw runtime_error(
                    "mintzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
        }

        for(int64_t i=0; i<amount; i++){
            // The following constructor does all the work of minting a brand
            // new zerocoin. It stores all the private values inside the
            // PrivateCoin object. This includes the coin secrets, which must be
            // stored in a secure location (wallet) at the client.
            libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
            // Get a copy of the 'public' portion of the coin. You should
            // embed this into a Zerocoin 'MINT' transaction along with a series
            // of currency inputs totaling the assigned value of one zerocoin.
            
            libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();
            
            //Validate
            bool validCoin = pubCoin.validate();

            // loop until we find a valid coin
            while(!validCoin){
                libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
                libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();
                validCoin = pubCoin.validate();
            }

            // Create script for coin
            CScript scriptSerializedCoin =
                    CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

            CRecipient recipient = {scriptSerializedCoin, (denominationValue * COIN), false};

            vecSend.push_back(recipient);
            privCoins.push_back(newCoin);
        }
    }

    stringError = pwalletMain->MintAndStoreZerocoin(vecSend, privCoins, wtx);

    if (stringError != ""){
        return false;
    }

    return true;
}

bool CWallet::CreateZerocoinMintModel(string &stringError, const string& denomAmount, MintAlgorithm algo) {
    //TODO(martun) check if it is time to start minting v3 sigma mints. Not sure how we can 
    // access the current block number in the waller side, so adding an algo parameter.
    if(algo == SIGMA)
        return CreateZerocoinMintModelV3(stringError, denomAmount);
    else if (algo == ZEROCOIN)
        return CreateZerocoinMintModelV2(stringError, denomAmount);
    else
        return false;
}

bool CWallet::CreateZerocoinMintModelV3(string &stringError, const string& denomAmount) {
    if (!fFileBacked)
        return false;

    int64_t nAmount = 0;
    sigma::CoinDenominationV3 denomination;
    // Amount
    if (!StringToDenomination(denomAmount, denomination)) {
        return false;
    }
    DenominationToInteger(denomination, nAmount);

    // Set up the Zerocoin Params object
    sigma::ParamsV3 *zcParams = sigma::ParamsV3::get_default();
	
    // The following constructor does all the work of minting a brand
    // new zerocoin. It stores all the private values inside the
    // PrivateCoin object. This includes the coin secrets, which must be
    // stored in a secure location (wallet) at the client.
    sigma::PrivateCoinV3 newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_3);

    // Get a copy of the 'public' portion of the coin. You should
    // embed this into a Zerocoin 'MINT' transaction along with a series
    // of currency inputs totaling the assigned value of one zerocoin.
    sigma::PublicCoinV3 pubCoin = newCoin.getPublicCoin();

    // Validate
    if (pubCoin.validate()) {
        // Create script for coin
        CScript scriptSerializedCoin;
        // opcode is inserted as 1 byte according to file script/script.h
        scriptSerializedCoin << OP_ZEROCOINMINTV3;

        // MARTUN: Commenting this for now.
        // this one will probably be written as int64_t, which means it will be written in as few bytes as necessary, and one more byte for sign. In our case our 34 will take 2 bytes, 1 for the number 34 and another one for the sign.
        // scriptSerializedCoin << pubCoin.getValue().memoryRequired();

        // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
        std::vector<unsigned char> vch = pubCoin.getValue().getvch();
        scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

        // Wallet comments
        CWalletTx wtx;

        stringError = MintZerocoin(scriptSerializedCoin, nAmount, wtx);

        if (stringError != "")
            return false;

        // const unsigned char *ecdsaSecretKey = newCoin.getEcdsaSeckey();
        CZerocoinEntryV3 zerocoinTx;
        zerocoinTx.IsUsed = false;
        zerocoinTx.set_denomination(denomination);
        zerocoinTx.value = pubCoin.getValue();
        zerocoinTx.randomness = newCoin.getRandomness();
        zerocoinTx.serialNumber = newCoin.getSerialNumber();
        // TODO(martun): ecdsaSecretKey looks like unnecessary, but take another look.
        // zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        LogPrintf("CreateZerocoinMintModel() -> NotifyZerocoinChanged\n");
        LogPrintf("pubcoin=%s, isUsed=%s\n", zerocoinTx.value.GetHex(), zerocoinTx.IsUsed);
        LogPrintf("randomness=%s, serialNumber=%s\n", zerocoinTx.randomness, zerocoinTx.serialNumber);
        NotifyZerocoinChanged(
            this,
            zerocoinTx.value.GetHex(),
            "New (" + std::to_string(zerocoinTx.get_denomination_value() / COIN) + " mint)",
            CT_NEW);
        if (!CWalletDB(strWalletFile).WriteZerocoinEntry(zerocoinTx))
            return false;
        return true;
    } else {
        return false;
    }
}

bool CWallet::CreateZerocoinMintModelV2(string &stringError, const string& denomAmount) {

    if (!fFileBacked)
        return false;

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (denomAmount == "1") {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = roundint64(1 * COIN);
    } else if (denomAmount == "10") {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = roundint64(10 * COIN);
    } else if (denomAmount == "25") {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = roundint64(25 * COIN);
    } else if (denomAmount == "50") {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = roundint64(50 * COIN);
    } else if (denomAmount == "100") {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = roundint64(100 * COIN);
    } else {
        return false;
    }

    // Set up the Zerocoin Params object
    libzerocoin::Params *zcParams = ZCParamsV2;
	
	int mintVersion = ZEROCOIN_TX_VERSION_1;
	
	// do not use v2 mint until certain moment when it would be understood by peers
	{
		LOCK(cs_main);
        if (chainActive.Height() >= Params().GetConsensus().nSpendV15StartBlock)
			mintVersion = ZEROCOIN_TX_VERSION_2;
	}

    // The following constructor does all the work of minting a brand
    // new zerocoin. It stores all the private values inside the
    // PrivateCoin object. This includes the coin secrets, which must be
    // stored in a secure location (wallet) at the client.
    libzerocoin::PrivateCoin newCoin(zcParams, denomination, mintVersion);

    // Get a copy of the 'public' portion of the coin. You should
    // embed this into a Zerocoin 'MINT' transaction along with a series
    // of currency inputs totaling the assigned value of one zerocoin.
    libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();

    // Validate
    if (pubCoin.validate()) {
        //TODOS
        CScript scriptSerializedCoin =
                CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

        // Wallet comments
        CWalletTx wtx;

        stringError = MintZerocoin(scriptSerializedCoin, nAmount, wtx);

        if (stringError != "")
            return false;

        const unsigned char *ecdsaSecretKey = newCoin.getEcdsaSeckey();
        CZerocoinEntry zerocoinTx;
        zerocoinTx.IsUsed = false;
        zerocoinTx.denomination = denomination;
        zerocoinTx.value = pubCoin.getValue();
        zerocoinTx.randomness = newCoin.getRandomness();
        zerocoinTx.serialNumber = newCoin.getSerialNumber();
        zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        LogPrintf("CreateZerocoinMintModel() -> NotifyZerocoinChanged\n");
        LogPrintf("pubcoin=%s, isUsed=%s\n", zerocoinTx.value.GetHex(), zerocoinTx.IsUsed);
        LogPrintf("randomness=%s, serialNumber=%s\n", zerocoinTx.randomness, zerocoinTx.serialNumber);
        NotifyZerocoinChanged(this, zerocoinTx.value.GetHex(), "New (" + std::to_string(zerocoinTx.denomination) + " mint)", CT_NEW);
        if (!CWalletDB(strWalletFile).WriteZerocoinEntry(zerocoinTx))
            return false;
        return true;
    } else {
        return false;
    }
}

bool CWallet::CheckDenomination(string denomAmount, int64_t& nAmount, libzerocoin::CoinDenomination& denomination){
    // Amount
    if (denomAmount == "1") {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = roundint64(1 * COIN);
    } else if (denomAmount == "10") {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = roundint64(10 * COIN);
    } else if (denomAmount == "25") {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = roundint64(25 * COIN);
    } else if (denomAmount == "50") {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = roundint64(50 * COIN);
    } else if (denomAmount == "100") {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = roundint64(100 * COIN);
    } else {
        return false;
    }
    return true;
}

bool CWallet::CheckHasV2Mint(libzerocoin::CoinDenomination denomination, bool forceUsed){
    // Check if there is v2 mint, spend it first
    bool result = false;
    list <CZerocoinEntry> listPubCoin;
    CWalletDB(strWalletFile).ListPubCoin(listPubCoin);
    listPubCoin.sort(CompHeight);
    CZerocoinEntry coinToUse;
    bool fModulusV2 = chainActive.Height() >= Params().GetConsensus().nModulusV2StartBlock;
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    CBigNum accumulatorValue;
    uint256 accumulatorBlockHash;      // to be used in zerocoin spend v2

    int coinId = INT_MAX;
    int coinHeight;
    BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
        if (minIdPubcoin.denomination == denomination
            && ((minIdPubcoin.IsUsed == false && !forceUsed) || (minIdPubcoin.IsUsed == true && forceUsed))
            && minIdPubcoin.randomness != 0
            && minIdPubcoin.serialNumber != 0) {

            int id;
            coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
            if (coinHeight > 0
                && id < coinId
                && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()
                && zerocoinState->GetAccumulatorValueForSpend(
                    &chainActive,
                    chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                    denomination,
                    id,
                    accumulatorValue,
                    accumulatorBlockHash,
                    fModulusV2) > 1
                    ) {
                result = true;
            }
        }
    }
    return result;
}

bool CWallet::CreateZerocoinSpendModel(
        string &stringError, 
        string thirdPartyAddress,
        string denomAmount,
        bool forceUsed) {
    // Clean the stringError, otherwise even if the Spend passes, it returns false.
    stringError = "";

    if (!fFileBacked)
        return false;

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    bool v2MintFound = false;
    if (CheckDenomination(denomAmount, nAmount, denomination)) {
        // If requested denomination can be a V2 denomination, check if there is any
        // mint of given denomination. Mints which do not have 
        // 6 confirmations will NOT be considered.
        v2MintFound = CheckHasV2Mint(denomination, forceUsed);
    }

    // Wallet comments
    CWalletTx wtx;
    uint256 txHash;

    bool zcSelectedIsUsed;

    if (v2MintFound) {
        // Always spend V2 old mints first.
        CBigNum coinSerial;
        CBigNum zcSelectedValue;
        stringError = SpendZerocoin(
            thirdPartyAddress, nAmount, denomination, 
            wtx, coinSerial, txHash, zcSelectedValue,
            zcSelectedIsUsed, forceUsed);
    } else {
        sigma::CoinDenominationV3 denomination_v3; 
        if (!StringToDenomination(denomAmount, denomination_v3)) {
            return false;
        }
        // Spend V3 sigma mint.
        Scalar coinSerial;
        GroupElement zcSelectedValue;
        stringError = SpendZerocoinV3(
                thirdPartyAddress,
                denomination_v3,
                wtx,
                coinSerial,
                txHash,
                zcSelectedValue,
                zcSelectedIsUsed,
                forceUsed);
    }

    if (stringError != "")
        return false;

    return true;
}

bool CWallet::CreateZerocoinSpendModel(CWalletTx& wtx, string &stringError, string& thirdPartyAddress, const vector<string>& denomAmounts, bool forceUsed) {
    // try to spend V2 coins, if fails, try to spend V3 sigma coins.
    if (!CreateZerocoinSpendModelV2(wtx, stringError, thirdPartyAddress, denomAmounts, forceUsed)) {
        return CreateZerocoinSpendModelV3(wtx, stringError, thirdPartyAddress, denomAmounts, forceUsed);
    }
return true;
}

bool CWallet::CreateZerocoinSpendModelV2(
        CWalletTx& wtx,
        string &stringError,
        string& thirdPartyAddress,
        const vector<string>& denomAmounts,
        bool forceUsed) {
    if (!fFileBacked)
        return false;
     
    vector<pair<int64_t, libzerocoin::CoinDenomination>> denominations;
    for(vector<string>::const_iterator it = denomAmounts.begin(); it != denomAmounts.end(); it++){
        const string& denomAmount = *it;
        int64_t nAmount = 0;
        libzerocoin::CoinDenomination denomination;
        // Amount
        if (denomAmount == "1") {
            denomination = libzerocoin::ZQ_LOVELACE;
            nAmount = roundint64(1 * COIN);
        } else if (denomAmount == "10") {
            denomination = libzerocoin::ZQ_GOLDWASSER;
            nAmount = roundint64(10 * COIN);
        } else if (denomAmount == "25") {
            denomination = libzerocoin::ZQ_RACKOFF;
            nAmount = roundint64(25 * COIN);
        } else if (denomAmount == "50") {
            denomination = libzerocoin::ZQ_PEDERSEN;
            nAmount = roundint64(50 * COIN);
        } else if (denomAmount == "100") {
            denomination = libzerocoin::ZQ_WILLIAMSON;
            nAmount = roundint64(100 * COIN);
        } else {
            return false;
        }
        denominations.push_back(make_pair(nAmount, denomination));
    }
    vector<CBigNum> coinSerials;
    uint256 txHash;
    vector<CBigNum> zcSelectedValues;
    stringError = SpendMultipleZerocoin(thirdPartyAddress, denominations, wtx, coinSerials, txHash, zcSelectedValues, forceUsed);
    if (stringError != "")
        return false;
    return true;
 }

// TODO(martun): check this function. These string denominations which come from
// outside may not be parsed properly. 
bool CWallet::CreateZerocoinSpendModelV3(
        CWalletTx& wtx,
        string &stringError,
        string& thirdPartyAddress,
        const vector<string>& denomAmounts,
        bool forceUsed) {
    if (!fFileBacked)
        return false;

    vector<sigma::CoinDenominationV3> denominations;
    for(vector<string>::const_iterator it = denomAmounts.begin(); it != denomAmounts.end(); it++){
        const string& denomAmount = *it;
        sigma::CoinDenominationV3 denomination;
        // Amount
        if (!StringToDenomination(denomAmount, denomination)) {
            stringError = "Unable to convert denomination.";
            return false;
        }
        denominations.push_back(denomination);
    }
    vector<Scalar> coinSerials;
    uint256 txHash;
    vector<GroupElement> zcSelectedValues;
    stringError = SpendMultipleZerocoinV3(
        thirdPartyAddress, denominations, wtx, 
        coinSerials, txHash, zcSelectedValues, forceUsed);
    if (stringError != "")
        return false;
    return true;
}


/**
 * @brief CWallet::CreateZerocoinMintTransaction
 * @param vecSend
 * @param wtxNew
 * @param reservekey
 * @param nFeeRet
 * @param strFailReason
 * @param coinControl
 * @return
 */
bool CWallet::CreateZerocoinMintTransaction(const vector <CRecipient> &vecSend, CWalletTx &wtxNew,
                                            CReserveKey &reservekey,
                                            CAmount &nFeeRet, int &nChangePosInOut, std::string &strFailReason,
                                            const CCoinControl *coinControl, bool sign) {
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    BOOST_FOREACH(const CRecipient &recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;
//        if (recipient.fSubtractFeeFromAmount)
//            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int) txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            std::vector <COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, coinControl);


            nFeeRet = payTxFee.GetFeePerK();
            LogPrintf("nFeeRet=%s\n", nFeeRet);
            // Start with no fee and loop until there is enough fee
            while (true) {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                txNew.wit.SetNull();
                wtxNew.fFromMe = true;
//                bool fFirst = true;

                CAmount nValueToSelect = nValue + nFeeRet;
//                if (nSubtractFeeFromAmount == 0)
//                    nValueToSelect += nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH(const CRecipient &recipient, vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                    LogPrintf("txout:%s\n", txout.ToString());

//                    if (recipient.fSubtractFeeFromAmount) {
//                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

//                        if (fFirst) // first receiver pays the remainder not divisible by output count
//                        {
//                            fFirst = false;
//                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
//                        }
//                    }

                    if (txout.IsDust(::minRelayTxFee)) {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0) {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _(
                                        "The transaction amount is too small to send after the fee has been deducted");
                        } else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                set <pair<const CWalletTx *, unsigned int>> setCoins;
                CAmount nValueIn = 0;
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl)) {
                    if (nValueIn < nValueToSelect) {
                        strFailReason = _("Insufficient funds.");
                    }
                    return false;
                }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    assert(age >= 0);
                    if (age != 0)
                        age += 1;
                    dPriority += (double) nCredit * age;
                }

                CAmount nChange = nValueIn - nValueToSelect;
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < CTransaction::nMinTxFee && nChange > 0 && nChange < CENT) {
                    int64_t nMoveToFee = min(nChange, CTransaction::nMinTxFee - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }
                if (nChange > 0) {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange)) {
                        scriptChange = GetScriptForDestination(coinControl->destChange);
                    }
                        // send change to one of the specified change addresses
                    else if (mapArgs.count("-change") && mapMultiArgs["-change"].size() > 0) {
                        CBitcoinAddress
                        address(mapMultiArgs["-change"][GetRandInt(mapMultiArgs["-change"].size())]);
                        CKeyID keyID;
                        if (!address.GetKeyID(keyID)) {
                            strFailReason = _("Bad change address");
                            return false;
                        }
                        scriptChange = GetScriptForDestination(keyID);
                    }
                        // no coin control: send change to newly generated address
                    else {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        if (!ret) {
                            strFailReason = _("Keypool ran out, please call keypoolrefill first");
                            return false;
                        }

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(::minRelayTxFee)) {
                        CAmount nDust = newTxOut.GetDustThreshold(::minRelayTxFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount) {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust(::minRelayTxFee)) {
                                    strFailReason = _(
                                            "The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }
                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(::minRelayTxFee)) {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    } else {
                        if (nChangePosInOut == -1) {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                        } else if ((unsigned int) nChangePosInOut > txNew.vout.size()) {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                } else
                    reservekey.ReturnKey();
                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int) &coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second, CScript(),
                                          std::numeric_limits < unsigned int > ::max() - 1));

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int) &coin, setCoins)
                {
                    bool signSuccess;
                    const CScript &scriptPubKey = coin.first->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn,
                                                                                   coin.first->vout[coin.second].nValue,
                                                                                   SIGHASH_ALL), scriptPubKey,
                                                       sigdata);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata);

                    if (!signSuccess) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(txNew, nIn, sigdata);
                    }
                    nIn++;
                }
                unsigned int nBytes = GetVirtualTransactionSize(txNew);
                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) {
                    BOOST_FOREACH(CTxIn & vin, txNew.vin)
                    vin.scriptSig = CScript();
                    txNew.wit.SetNull();
                }
                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);

                // Limit size
                if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority = wtxNew.ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }
                int64_t nPayFee = payTxFee.GetFeePerK() * (1 + (int64_t) GetTransactionWeight(txNew) / 1000);
//                bool fAllowFree = false;					// No free TXs in XZC
                int64_t nMinFee = wtxNew.GetMinFee(1, false, GMF_SEND);

                int64_t nFeeNeeded = nPayFee;
                if (nFeeNeeded < nMinFee) {
                    nFeeNeeded = nMinFee;
                }
//                LogPrintf("nFeeNeeded=%s\n", nFeeNeeded);
//                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
//                    nFeeNeeded = coinControl->nMinimumTotalFee;
//                }
//                LogPrintf("nFeeNeeded=%s\n", nFeeNeeded);
//                if (coinControl && coinControl->fOverrideFeeRate)
//                    nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);
//                LogPrintf("nFeeNeeded=%s\n", nFeeNeeded);
//                LogPrintf("nFeeRet=%s\n", nFeeRet);
                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
//                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
//                    strFailReason = _("Transaction too large for fee policy");
//                    return false;
//                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(txNew, 0, 0, 0, 0, false, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }
    return true;
}

bool
CWallet::CreateZerocoinMintTransaction(CScript pubCoin, int64_t nValue, CWalletTx &wtxNew, CReserveKey &reservekey,
                                       int64_t &nFeeRet, std::string &strFailReason,
                                       const CCoinControl *coinControl) {
    vector <CRecipient> vecSend;
    CRecipient recipient = {pubCoin, nValue, false};
    vecSend.push_back(recipient);
    int nChangePosRet = -1;
    return CreateZerocoinMintTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason,
                                         coinControl);
}

/**
 * @brief CWallet::CreateZerocoinSpendTransaction
 * @param nValue
 * @param denomination
 * @param wtxNew
 * @param reservekey
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @param strFailReason
 * @return
 */
bool CWallet::CreateZerocoinSpendTransaction(std::string &thirdPartyaddress, int64_t nValue, libzerocoin::CoinDenomination denomination,
                                             CWalletTx &wtxNew, CReserveKey &reservekey, CBigNum &coinSerial,
                                             uint256 &txHash, CBigNum &zcSelectedValue, bool &zcSelectedIsUsed,
                                             std::string &strFailReason, bool forceUsed) {
    if (nValue <= 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();
            txNew.wit.SetNull();
            //wtxNew.fFromMe = true;


            CScript scriptChange;
            if(thirdPartyaddress == ""){
            	// Reserve a new key pair from key pool
            	CPubKey vchPubKey;
            	assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
            	scriptChange = GetScriptForDestination(vchPubKey.GetID());
            }else{

            	CBitcoinAddress address(thirdPartyaddress);
            	if (!address.IsValid()){
            		strFailReason = _("Invalid zcoin address");
            		return false;
            	}
            	// Parse Zcoin address
            	scriptChange = GetScriptForDestination(CBitcoinAddress(thirdPartyaddress).Get());
            }

            CTxOut newTxOut(nValue, scriptChange);

            // Insert change txn at random position:
            vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
            txNew.vout.insert(position, newTxOut);
//            LogPrintf("txNew:%s\n", txNew.ToString());
            LogPrintf("txNew.GetHash():%s\n", txNew.GetHash().ToString());

            // Fill vin

            // Set up the Zerocoin Params object
            bool fModulusV2 = chainActive.Height() >= Params().GetConsensus().nModulusV2StartBlock;
            libzerocoin::Params *zcParams = fModulusV2 ? ZCParamsV2 : ZCParams;

            // Select not yet used coin from the wallet with minimal possible id

            list <CZerocoinEntry> listPubCoin;
            CWalletDB(strWalletFile).ListPubCoin(listPubCoin);
            listPubCoin.sort(CompHeight);
            CZerocoinEntry coinToUse;
            CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

            CBigNum accumulatorValue;
            uint256 accumulatorBlockHash;      // to be used in zerocoin spend v2

            int coinId = INT_MAX;
            int coinHeight;

            BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
                if (minIdPubcoin.denomination == denomination
                        && ((minIdPubcoin.IsUsed == false && !forceUsed) || (minIdPubcoin.IsUsed == true && forceUsed))
                        && minIdPubcoin.randomness != 0
                        && minIdPubcoin.serialNumber != 0) {

                    int id;
                    coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
                    if (coinHeight > 0
                            && id < coinId
                            && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()
                            && zerocoinState->GetAccumulatorValueForSpend(
                                    &chainActive,
                                    chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                    denomination,
                                    id,
                                    accumulatorValue,
                                    accumulatorBlockHash,
                                    fModulusV2) > 1
                            ) {
                        coinId = id;
                        coinToUse = minIdPubcoin;
                    }
                }
            }

            if (coinId == INT_MAX){
                strFailReason = _("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin");
                return false;
            }

            libzerocoin::Accumulator accumulator(zcParams, accumulatorValue, denomination);
            // 2. Get pubcoin from the private coin
            libzerocoin::PublicCoin pubCoinSelected(zcParams, coinToUse.value, denomination);

            // Now make sure the coin is valid.
            if (!pubCoinSelected.validate()) {
                // If this returns false, don't accept the coin for any purpose!
                // Any ZEROCOIN_MINT with an invalid coin should NOT be
                // accepted as a valid transaction in the block chain.
                strFailReason = _("the selected mint coin is an invalid coin");
                return false;
            }

            // 4. Get witness from the index
            libzerocoin::AccumulatorWitness witness =
                    zerocoinState->GetWitnessForSpend(&chainActive,
                                                      chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                                      denomination, coinId,
                                                      coinToUse.value,
                                                      fModulusV2);

            int serializedId = coinId + (fModulusV2 ? ZC_MODULUS_V2_BASE_ID : 0);

            CTxIn newTxIn;
            newTxIn.nSequence = serializedId;
            newTxIn.scriptSig = CScript();
            newTxIn.prevout.SetNull();
            txNew.vin.push_back(newTxIn);

            bool useVersion2 = IsZerocoinTxV2(denomination, Params().GetConsensus(), coinId);

            // We use incomplete transaction hash for now as a metadata
            libzerocoin::SpendMetaData metaData(serializedId, txNew.GetHash());

            // Construct the CoinSpend object. This acts like a signature on the
            // transaction.
            libzerocoin::PrivateCoin privateCoin(zcParams, denomination);

            int txVersion = ZEROCOIN_TX_VERSION_1;
            if (useVersion2) {
                // Use version 2 if possible, for older mints stay with 1.5
                txVersion = coinToUse.IsCorrectV2Mint() ? ZEROCOIN_TX_VERSION_2 : ZEROCOIN_TX_VERSION_1_5;
            }
            else {
                int nHeight;
                {
                    LOCK(cs_main);
                    nHeight = chainActive.Height();
                }
                if (nHeight >= Params().GetConsensus().nSpendV15StartBlock)
                    txVersion = ZEROCOIN_TX_VERSION_1_5;
            }

            LogPrintf("CreateZerocoinSpendTransation: tx version=%d, tx metadata hash=%s\n", txVersion, txNew.GetHash().ToString());

            privateCoin.setVersion(txVersion);
            privateCoin.setPublicCoin(pubCoinSelected);
            privateCoin.setRandomness(coinToUse.randomness);
            privateCoin.setSerialNumber(coinToUse.serialNumber);
            privateCoin.setEcdsaSeckey(coinToUse.ecdsaSecretKey);

            libzerocoin::CoinSpend spend(zcParams, privateCoin, accumulator, witness, metaData, accumulatorBlockHash);
            spend.setVersion(txVersion);

            // This is a sanity check. The CoinSpend object should always verify,
            // but why not check before we put it onto the wire?
            if (!spend.Verify(accumulator, metaData)) {
                strFailReason = _("the spend coin transaction did not verify");
                return false;
            }

            // Serialize the CoinSpend object into a buffer.
            CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
            serializedCoinSpend << spend;

            CScript tmp = CScript() << OP_ZEROCOINSPEND << serializedCoinSpend.size();
            tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
            txNew.vin[0].scriptSig.assign(tmp.begin(), tmp.end());

            // Embed the constructed transaction data in wtxNew.
            *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);

            // Limit size
            if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                strFailReason = _("Transaction too large");
                return false;
            }

            /*zerocoinSelected.IsUsed = true;
        zerocoinSelected.randomness = 0;
        zerocoinSelected.serialNumber = 0;
        CWalletDB(strWalletFile).WriteZerocoinEntry(zerocoinSelected);*/

            std::list <CZerocoinSpendEntry> listCoinSpendSerial;
            CWalletDB(strWalletFile).ListCoinSpendSerial(listCoinSpendSerial);
            BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial){
                if (!forceUsed && spend.getCoinSerialNumber() == item.coinSerial) {
                    // THIS SELECEDTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                    CZerocoinEntry pubCoinTx;
                    pubCoinTx.nHeight = coinHeight;
                    pubCoinTx.denomination = coinToUse.denomination;
                    pubCoinTx.id = coinId;
                    pubCoinTx.IsUsed = true;
                    pubCoinTx.randomness = coinToUse.randomness;
                    pubCoinTx.serialNumber = coinToUse.serialNumber;
                    pubCoinTx.value = coinToUse.value;
                    pubCoinTx.ecdsaSecretKey = coinToUse.ecdsaSecretKey;
                    CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("CreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=Used\n", coinToUse.value.GetHex());
                    pwalletMain->NotifyZerocoinChanged(pwalletMain, coinToUse.value.GetHex(), "Used (" + std::to_string(coinToUse.denomination) + " mint)",
                                                       CT_UPDATED);
                    strFailReason = _("the coin spend has been used");
                    return false;
                }
            }

            coinSerial = spend.getCoinSerialNumber();
            txHash = wtxNew.GetHash();
            LogPrintf("txHash:\n%s", txHash.ToString());
            zcSelectedValue = coinToUse.value;
            zcSelectedIsUsed = coinToUse.IsUsed;

            CZerocoinSpendEntry entry;
            entry.coinSerial = coinSerial;
            entry.hashTx = txHash;
            entry.pubCoin = zcSelectedValue;
            entry.id = serializedId;
            entry.denomination = coinToUse.denomination;
            LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s\n", coinSerial.ToString());
            if (!CWalletDB(strWalletFile).WriteCoinSpendSerialEntry(entry)) {
                strFailReason = _("it cannot write coin serial number into wallet");
            }

            coinToUse.IsUsed = true;
            coinToUse.id = coinId;
            coinToUse.nHeight = coinHeight;
            CWalletDB(strWalletFile).WriteZerocoinEntry(coinToUse);
            pwalletMain->NotifyZerocoinChanged(pwalletMain, coinToUse.value.GetHex(), "Used (" + std::to_string(coinToUse.denomination) + " mint)",
                                               CT_UPDATED);
        }
    }

    return true;
}

bool CWallet::CreateZerocoinSpendTransactionV3(
        std::string &thirdPartyaddress, 
        sigma::CoinDenominationV3 denomination,
        CWalletTx &wtxNew, CReserveKey &reservekey, Scalar &coinSerial,
        uint256 &txHash, GroupElement &zcSelectedValue, bool &zcSelectedIsUsed,
        std::string &strFailReason, bool forceUsed) {
    int64_t nValue;
    if (!DenominationToInteger(denomination, nValue)) {
        strFailReason = _("Unable to convert denomination to integer.");
        return false;
    }

    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();
            txNew.wit.SetNull();

            CScript scriptChange;
            if(thirdPartyaddress == "") {
                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
                scriptChange = GetScriptForDestination(vchPubKey.GetID());
            } else {
                CBitcoinAddress address(thirdPartyaddress);
                if (!address.IsValid()){
                    strFailReason = _("Invalid zcoin address");
                    return false;
                }
                // Parse Zcoin address
                scriptChange = GetScriptForDestination(CBitcoinAddress(thirdPartyaddress).Get());
            }

            CTxOut newTxOut(nValue, scriptChange);

            // Insert change txn at random position:
            vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
            txNew.vout.insert(position, newTxOut);
//            LogPrintf("txNew:%s\n", txNew.ToString());
            LogPrintf("txNew.GetHash():%s\n", txNew.GetHash().ToString());

            // Fill vin

            // Set up the Zerocoin Params object
            sigma::ParamsV3* zcParams = sigma::ParamsV3::get_default();

            // Select not yet used coin from the wallet with minimal possible id

            list <CZerocoinEntryV3> listPubCoin;
            CWalletDB(strWalletFile).ListPubCoinV3(listPubCoin);
            listPubCoin.sort(CompHeightV3);
            CZerocoinEntryV3 coinToUse;
            CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();

            std::vector<PublicCoinV3> anonimity_set;
            uint256 blockHash;

            int coinId = INT_MAX;
            int coinHeight;

            BOOST_FOREACH(const CZerocoinEntryV3 &minIdPubcoin, listPubCoin) {
                if (minIdPubcoin.get_denomination() == denomination
                    && ((minIdPubcoin.IsUsed == false && !forceUsed) || (minIdPubcoin.IsUsed == true && forceUsed))
                    && minIdPubcoin.randomness != uint64_t(0)
                    && minIdPubcoin.serialNumber != uint64_t(0)) {

                    std::pair<int, int> coinHeightAndId = zerocoinState->GetMintedCoinHeightAndId(
                            PublicCoinV3(minIdPubcoin.value, denomination));
                    coinHeight = coinHeightAndId.first;
                    int coinGroupID = coinHeightAndId.second;
                    if (coinHeight > 0
                        && coinGroupID < coinId // Always spend coin with smallest ID that matches.
                        && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()
                        && zerocoinState->GetCoinSetForSpend(
                            &chainActive,
                            chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                            denomination,
                            coinGroupID,
                            blockHash,
                            anonimity_set) > 1 )  {
                        coinId = coinGroupID;
                        coinToUse = minIdPubcoin;
                    }
                }
            }

            if (coinId == INT_MAX) {
                strFailReason = _("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin");
                return false;
            }

            // 2. Get pubcoin from the private coin
            sigma::PublicCoinV3 pubCoinSelected(coinToUse.value, denomination);

            // Now make sure the coin is valid.
            if (!pubCoinSelected.validate()) {
                // If this returns false, don't accept the coin for any purpose!
                // Any ZEROCOIN_MINT with an invalid coin should NOT be
                // accepted as a valid transaction in the block chain.
                strFailReason = _("the selected mint coin is an invalid coin");
                return false;
            }

            int serializedId = coinId;

            CTxIn newTxIn;
            newTxIn.nSequence = serializedId;
            newTxIn.scriptSig = CScript();
            newTxIn.prevout.SetNull();
            txNew.vin.push_back(newTxIn);

            // Construct the CoinSpend object. This acts like a signature on the
            // transaction.
            sigma::PrivateCoinV3 privateCoin(zcParams, denomination);

            int txVersion = ZEROCOIN_TX_VERSION_3;

            LogPrintf("CreateZerocoinSpendTransation: tx version=%d, tx metadata hash=%s\n", txVersion, txNew.GetHash().ToString());

            privateCoin.setVersion(txVersion);
            privateCoin.setPublicCoin(pubCoinSelected);
            privateCoin.setRandomness(coinToUse.randomness);
            privateCoin.setSerialNumber(coinToUse.serialNumber);
            // We do NOT need an ecdsaSecretKey for V3 sigma mints.
//          privateCoin.setEcdsaSeckey(coinToUse.ecdsaSecretKey);

            sigma::CoinSpendV3 spend(zcParams, privateCoin, anonimity_set, blockHash);
            spend.setVersion(txVersion);

            // This is a sanity check. The CoinSpend object should always verify,
            // but why not check before we put it onto the wire?
            if (!spend.Verify(anonimity_set)) {
                strFailReason = _("the spend coin transaction did not verify");
                return false;
            }

            // Serialize the CoinSpend object into a buffer.
            CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
            serializedCoinSpend << spend;

            CScript tmp = CScript() << OP_ZEROCOINSPENDV3;
            // NOTE(martun): Do not write the size first, doesn't look like necessary. 
            // If we write it, it will get written in different number of bytes depending 
            // on the number itself, and "CScript" does not provide a function to read 
            // it back properly.
            // << serializedCoinSpend.size();             
            // NOTE(martun): "insert" is not the same as "operator<<", as operator<< 
            // also writes the vector size before the vector itself.
            tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
            txNew.vin[0].scriptSig.assign(tmp.begin(), tmp.end());

            // Embed the constructed transaction data in wtxNew.
            // NOTE(martun): change the next line, it's not good coding style.
            *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);

            // Limit size
            if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                strFailReason = _("Transaction too large");
                return false;
            }

            std::list <CZerocoinSpendEntryV3> listCoinSpendSerial;
            CWalletDB(strWalletFile).ListCoinSpendSerial(listCoinSpendSerial);
            BOOST_FOREACH(const CZerocoinSpendEntryV3 &item, listCoinSpendSerial) {
                if (!forceUsed && spend.getCoinSerialNumber() == item.coinSerial) {
                    // THIS SELECEDTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                    CZerocoinEntryV3 pubCoinTx;
                    pubCoinTx.nHeight = coinHeight;
                    pubCoinTx.set_denomination_value(coinToUse.get_denomination_value());
                    pubCoinTx.id = coinId;
                    pubCoinTx.IsUsed = true;
                    pubCoinTx.randomness = coinToUse.randomness;
                    pubCoinTx.serialNumber = coinToUse.serialNumber;
                    pubCoinTx.value = coinToUse.value;
//                    pubCoinTx.ecdsaSecretKey = coinToUse.ecdsaSecretKey;
                    CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("CreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=Used\n", coinToUse.value.GetHex());
                    pwalletMain->NotifyZerocoinChanged(
                        pwalletMain, 
                        coinToUse.value.GetHex(),
                        "Used (" + std::to_string(coinToUse.get_denomination_value() / COIN) + " mint)",
                        CT_UPDATED);
                    strFailReason = _("the coin spend has been used");
                    return false;
                }
            }

            coinSerial = spend.getCoinSerialNumber();
            txHash = wtxNew.GetHash();
            LogPrintf("txHash:\n%s", txHash.ToString());
            zcSelectedValue = coinToUse.value;
            zcSelectedIsUsed = coinToUse.IsUsed;

            CZerocoinSpendEntryV3 entry;
            entry.coinSerial = coinSerial;
            entry.hashTx = txHash;
            entry.pubCoin = zcSelectedValue;
            entry.id = serializedId;
            entry.set_denomination_value(coinToUse.get_denomination_value());
            LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s\n", coinSerial.tostring());
            if (!CWalletDB(strWalletFile).WriteCoinSpendSerialEntry(entry)) {
                strFailReason = _("it cannot write coin serial number into wallet");
            }

            coinToUse.IsUsed = true;
            coinToUse.id = coinId;
            coinToUse.nHeight = coinHeight;
            CWalletDB(strWalletFile).WriteZerocoinEntry(coinToUse);
            pwalletMain->NotifyZerocoinChanged(
                pwalletMain, coinToUse.value.GetHex(), 
                "Used (" + std::to_string(coinToUse.get_denomination_value() / COIN) + " mint)",
                CT_UPDATED);
        }
    }

    return true;
}

/**
 * @brief CWallet::CreateMultipleZerocoinSpendTransaction
 * @param thirdPartyaddress
 * @param denominations
 * @param wtxNew
 * @param reservekey
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @param strFailReason
 * @return
 */
bool CWallet::CreateMultipleZerocoinSpendTransaction(std::string &thirdPartyaddress, const std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>>& denominations,
                                             CWalletTx &wtxNew, CReserveKey &reservekey, vector<CBigNum> &coinSerials, uint256 &txHash, vector<CBigNum> &zcSelectedValues,
                                             std::string &strFailReason, bool forceUsed) 
{
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();
            txNew.wit.SetNull();
            wtxNew.fFromMe = true;
            CScript scriptChange;
            if(thirdPartyaddress == ""){
                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
                scriptChange = GetScriptForDestination(vchPubKey.GetID());
            }else{
                 CBitcoinAddress address(thirdPartyaddress);
                if (!address.IsValid()){
                    strFailReason = _("Invalid zcoin address");
                    return false;
                }
                // Parse Zcoin address
                scriptChange = GetScriptForDestination(CBitcoinAddress(thirdPartyaddress).Get());
            }

            // Set up the Zerocoin Params object
            bool fModulusV2 = chainActive.Height() >= Params().GetConsensus().nModulusV2StartBlock;
            libzerocoin::Params *zcParams = fModulusV2 ? ZCParamsV2 : ZCParams;
            // objects holding spend inputs & storage values while tx is formed
            struct TempStorage {
                libzerocoin::PrivateCoin privateCoin;
                libzerocoin::Accumulator accumulator;
                libzerocoin::CoinDenomination denomination;
                uint256 accumulatorBlockHash;
                CZerocoinEntry coinToUse;
                int serializedId;
                int txVersion;
                int coinHeight;
                int coinId;
            };
            vector<TempStorage> tempStorages;


            // object storing coins being used for this spend (to avoid duplicates being considered)
            set<CBigNum> tempCoinsToUse;

            // total value of all inputs. Iteritively created in the following loop
            int64_t nValue = 0;
            for (std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>>::const_iterator it = denominations.begin(); it != denominations.end(); it++)
            {
                if ((*it).first <= 0) {
                strFailReason = _("Transaction amounts must be positive");
                    return false;
                }
                nValue += (*it).first;
                libzerocoin::CoinDenomination denomination  = (*it).second;
                LogPrintf("denomination: %s\n", denomination);
            
                // Fill vin
                // Select not yet used coin from the wallet with minimal possible id
                list <CZerocoinEntry> listPubCoin;
                CWalletDB(strWalletFile).ListPubCoin(listPubCoin);
                listPubCoin.sort(CompHeight);
                CZerocoinEntry coinToUse;
                CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
                CBigNum accumulatorValue;
                uint256 accumulatorBlockHash;      // to be used in zerocoin spend v2
                int coinId = INT_MAX;
                int coinHeight;
                BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
                    if (minIdPubcoin.denomination == denomination
                        && ((minIdPubcoin.IsUsed == false && !forceUsed) || (minIdPubcoin.IsUsed == true && forceUsed))
                        && minIdPubcoin.randomness != 0
                        && minIdPubcoin.serialNumber != 0
                        && (tempCoinsToUse.find(minIdPubcoin.value)==tempCoinsToUse.end())) {
                        int id;
                        coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
                        if (coinHeight > 0
                            && id < coinId
                            && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()
                            && zerocoinState->GetAccumulatorValueForSpend(
                                    &chainActive,
                                    chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                    denomination,
                                    id,
                                    accumulatorValue,
                                    accumulatorBlockHash,
                                    fModulusV2) > 1) {
                            coinId = id;
                            coinToUse = minIdPubcoin;
                            tempCoinsToUse.insert(minIdPubcoin.value);
                            break;
                        }
                    }
                }

                // If no suitable coin found, fail.
                if (coinId == INT_MAX){
                    strFailReason = _("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin");
                    return false;
                }
                // 1. Get the current accumulator for denomination selected 
                libzerocoin::Accumulator accumulator(zcParams, accumulatorValue, denomination);
                // 2. Get pubcoin from the private coin
                libzerocoin::PublicCoin pubCoinSelected(zcParams, coinToUse.value, denomination);
                 // Now make sure the coin is valid.
                if (!pubCoinSelected.validate()) {
                    // If this returns false, don't accept the coin for any purpose!
                    // Any ZEROCOIN_MINT with an invalid coin should NOT be
                    // accepted as a valid transaction in the block chain.
                    strFailReason = _("the selected mint coin is an invalid coin");
                    return false;
                }
                 // 4. Get witness for the accumulator and selected coin
                libzerocoin::AccumulatorWitness witness =
                        zerocoinState->GetWitnessForSpend(&chainActive,
                                                          chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                                          denomination, coinId,
                                                          coinToUse.value,
                                                          fModulusV2);

                // Generate TxIn info
                int serializedId = coinId + (fModulusV2 ? ZC_MODULUS_V2_BASE_ID : 0);
                CTxIn newTxIn;
                newTxIn.nSequence = serializedId;
                newTxIn.scriptSig = CScript();
                newTxIn.prevout.SetNull();
                txNew.vin.push_back(newTxIn);
                bool useVersion2 = IsZerocoinTxV2(denomination, Params().GetConsensus(), coinId);

                // Construct the CoinSpend object. This acts like a signature on the
                // transaction.
                libzerocoin::PrivateCoin privateCoin(zcParams, denomination);
                int txVersion = ZEROCOIN_TX_VERSION_1;
                if (useVersion2) {
                    // Use version 2 if possible, for older mints stay with 1.5
                    txVersion = coinToUse.IsCorrectV2Mint() ? ZEROCOIN_TX_VERSION_2 : ZEROCOIN_TX_VERSION_1_5;
                }
                else {
                    int nHeight;
                    {
                        LOCK(cs_main);
                        nHeight = chainActive.Height();
                    }
                    if (nHeight >= Params().GetConsensus().nSpendV15StartBlock){
                        txVersion = ZEROCOIN_TX_VERSION_1_5;
                    }
                }
                LogPrintf("CreateZerocoinSpendTransaction: tx version=%d, tx metadata hash=%s\n", txVersion, txNew.GetHash().ToString());

                // Set all values in the private coin object
                privateCoin.setVersion(txVersion);
                privateCoin.setPublicCoin(pubCoinSelected);
                privateCoin.setRandomness(coinToUse.randomness);
                privateCoin.setSerialNumber(coinToUse.serialNumber);
                privateCoin.setEcdsaSeckey(coinToUse.ecdsaSecretKey);


                LogPrintf("creating tempStorage object..\n");
                // Push created TxIn values into a tempStorage object (used in the next loop)
                TempStorage tempStorage {
                    privateCoin,
                    accumulator,
                    denomination,
                    accumulatorBlockHash,
                    coinToUse,
                    serializedId,
                    txVersion,
                    coinHeight,
                    coinId,
                };
                tempStorages.push_back(tempStorage);
            }

            // We now have the total coin amount to send. Create a single TxOut with this value.
            CTxOut newTxOut(nValue, scriptChange);
            // Insert single txout
            vector<CTxOut>::iterator position = txNew.vout.begin();
            txNew.vout.insert(position, newTxOut);

            /* We split the processing of the transaction into two loops. 
             * The metaData hash is the hash of the transaction sans the zerocoin-related info (spend info).
             * Transaction processing is split to have the same txHash in every metaData object - 
             * if the hash is different (as it would be if we did all steps for a TxIn in one loop) the transaction creation will fail.
            */ 

            // Remove all zerocoin related info
            CMutableTransaction txTemp = txNew;
            BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
                txTempIn.scriptSig.clear();
                txTempIn.prevout.SetNull();
            }

            uint256 txHashForMetadata = txTemp.GetHash();
            LogPrintf("txNew.GetHash: %s\n", txHashForMetadata.ToString());

            for (std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>>::const_iterator it = denominations.begin(); it != denominations.end(); it++)
            {
                unsigned index = it - denominations.begin();

                TempStorage tempStorage = tempStorages.at(index);
                libzerocoin::SpendMetaData metaData(tempStorage.serializedId, txHashForMetadata);
                CZerocoinEntry coinToUse = tempStorage.coinToUse;

                 //have to recreate coin witness as it can't be stored in an object, hence we can't store it in tempStorage..
                CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
                libzerocoin::AccumulatorWitness witness =
                zerocoinState->GetWitnessForSpend(&chainActive,
                                                  chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                                  tempStorage.denomination, tempStorage.coinId,
                                                  coinToUse.value,
                                                  fModulusV2);

                // Recreate CoinSpend object
                 libzerocoin::CoinSpend spend(zcParams, 
                                             tempStorage.privateCoin, 
                                             tempStorage.accumulator, 
                                             witness, 
                                             metaData,
                                             tempStorage.accumulatorBlockHash);
                spend.setVersion(tempStorage.txVersion);
                
                // Verify the coinSpend
                if (!spend.Verify(tempStorage.accumulator, metaData)) {
                    strFailReason = _("the spend coin transaction did not verify");
                    return false;
                }
                 // Serialize the CoinSpend object into a buffer.
                CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
                serializedCoinSpend << spend;

                // Insert the spend script into the tx object
                CScript tmp = CScript() << OP_ZEROCOINSPEND << serializedCoinSpend.size();
                tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
                txNew.vin[index].scriptSig.assign(tmp.begin(), tmp.end());

                // Try to find this coin in the list of spent coin serials.
                // If found, notify that a coin that was previously thought to be available is actually used, and fail.
                std::list <CZerocoinSpendEntry> listCoinSpendSerial;
                CWalletDB(strWalletFile).ListCoinSpendSerial(listCoinSpendSerial);
                BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial){
                    if (!forceUsed && spend.getCoinSerialNumber() == item.coinSerial) {
                        // THIS SELECTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                        CZerocoinEntry pubCoinTx;
                        pubCoinTx.nHeight = tempStorage.coinHeight;
                        pubCoinTx.denomination = coinToUse.denomination;
                        pubCoinTx.id = tempStorage.coinId;
                        pubCoinTx.IsUsed = true;
                        pubCoinTx.randomness = coinToUse.randomness;
                        pubCoinTx.serialNumber = coinToUse.serialNumber;
                        pubCoinTx.value = coinToUse.value;
                        pubCoinTx.ecdsaSecretKey = coinToUse.ecdsaSecretKey;
                        CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                        LogPrintf("CreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                        LogPrintf("pubcoin=%s, isUsed=Used\n", coinToUse.value.GetHex());
                        pwalletMain->NotifyZerocoinChanged(pwalletMain, coinToUse.value.GetHex(), "Used (" + std::to_string(coinToUse.denomination) + " mint)",
                                                           CT_UPDATED);
                        strFailReason = _("the coin spend has been used");
                        return false;
                    }
                }
            }

            txHash = wtxNew.GetHash();
            LogPrintf("wtxNew.txHash:%s\n", txHash.ToString());

            // Embed the constructed transaction data in wtxNew.
            *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);
             // Limit size
            if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                strFailReason = _("Transaction too large");
                return false;
            }

            // After transaction creation and verification, this last loop is to notify the wallet of changes to zerocoin spend info.
            for (std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>>::const_iterator it = denominations.begin(); it != denominations.end(); it++)
            {
                unsigned index = it - denominations.begin();
                TempStorage tempStorage = tempStorages.at(index);
                CZerocoinEntry coinToUse = tempStorage.coinToUse;

                // Update the wallet with info on this zerocoin spend
                coinSerials.push_back(tempStorage.privateCoin.getSerialNumber());
                zcSelectedValues.push_back(coinToUse.value);

                CZerocoinSpendEntry entry;
                entry.coinSerial = coinSerials[index];
                entry.hashTx = txHash;
                entry.pubCoin = coinToUse.value;
                entry.id = tempStorage.serializedId;
                entry.denomination = coinToUse.denomination;
                LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s\n", entry.coinSerial.ToString());
                if (!CWalletDB(strWalletFile).WriteCoinSpendSerialEntry(entry)) {
                    strFailReason = _("it cannot write coin serial number into wallet");
                }
                coinToUse.IsUsed = true;
                coinToUse.id = tempStorage.coinId;
                coinToUse.nHeight = tempStorage.coinHeight;
                CWalletDB(strWalletFile).WriteZerocoinEntry(coinToUse);
                pwalletMain->NotifyZerocoinChanged(pwalletMain, coinToUse.value.GetHex(), "Used (" + std::to_string(coinToUse.denomination) + " mint)", CT_UPDATED);
            }
        }
    }
     return true;
}

bool CWallet::CreateMultipleZerocoinSpendTransactionV3(
        std::string &thirdPartyaddress, 
        const std::vector<sigma::CoinDenominationV3>& denominations,
        CWalletTx &wtxNew,
        CReserveKey &reservekey,
        vector<Scalar> &coinSerials,
        uint256 &txHash,
        vector<GroupElement> &zcSelectedValues,
        std::string &strFailReason,
        bool forceUsed)
{
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();
            txNew.wit.SetNull();
            wtxNew.fFromMe = true;
            CScript scriptChange;
            if(thirdPartyaddress == "") {
                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
                scriptChange = GetScriptForDestination(vchPubKey.GetID());
            }else{
                CBitcoinAddress address(thirdPartyaddress);
                if (!address.IsValid()) {
                    strFailReason = _("Invalid zcoin address");
                    return false;
                }
                // Parse Zcoin address
                scriptChange = GetScriptForDestination(CBitcoinAddress(thirdPartyaddress).Get());
            }

            // Set up the Zerocoin Params object
            sigma::ParamsV3* zcParams = sigma::ParamsV3::get_default();
//             objects holding spend inputs & storage values while tx is formed
            struct TempStorage {
                sigma::PrivateCoinV3 privateCoin;
                std::vector<PublicCoinV3> anonimity_set;
                sigma::CoinDenominationV3 denomination;
                uint256 blockHash;
                CZerocoinEntryV3 coinToUse;
                int serializedId;
                int txVersion;
                int coinHeight;
                int coinId;
            };
            vector<TempStorage> tempStorages;

            // object storing coins being used for this spend (to avoid duplicates being considered)
            unordered_set<GroupElement, GroupElement::hasher> tempCoinsToUse;

            // Total value of all inputs. Iteritively created in the following loop
            // The value is in multiples of COIN = 100 mln.
            int64_t nValue = 0;
            for (std::vector<sigma::CoinDenominationV3>::const_iterator it = denominations.begin(); 
                 it != denominations.end();
                 it++)
            {
                sigma::CoinDenominationV3 denomination = *it;
                int64_t denomination_value;
                if (!DenominationToInteger(denomination, denomination_value)) {
                    strFailReason = _("Unable to convert denomination to integer.");
                    return false;
                }

                if (denomination_value <= 0) {
                    strFailReason = _("Transaction amounts must be positive");
                    return false;
                }
                nValue += denomination_value;
                LogPrintf("denomination: %s\n", *it);

                // Fill vin
                // Select not yet used coin from the wallet with minimal possible id
                list <CZerocoinEntryV3> listPubCoin;
                CWalletDB(strWalletFile).ListPubCoinV3(listPubCoin);
                listPubCoin.sort(CompHeightV3);
                CZerocoinEntryV3 coinToUse;
                CZerocoinStateV3 *zerocoinState = CZerocoinStateV3::GetZerocoinState();
                std::vector<PublicCoinV3> anonimity_set;
                uint256 blockHash;
                int coinId = INT_MAX;
                int coinHeight;
                BOOST_FOREACH(const CZerocoinEntryV3 &minIdPubcoin, listPubCoin) {
                    if (minIdPubcoin.get_denomination() == (*it)
                        && ((minIdPubcoin.IsUsed == false && !forceUsed) || (minIdPubcoin.IsUsed == true && forceUsed))
                        && minIdPubcoin.randomness != uint64_t(0)
                        && minIdPubcoin.serialNumber != uint64_t(0)
                        && (tempCoinsToUse.find(minIdPubcoin.value)==tempCoinsToUse.end())) {
                        int id;
                        std::pair<int, int> coinHeightAndId = 
                            zerocoinState->GetMintedCoinHeightAndId(
                                PublicCoinV3(minIdPubcoin.value, denomination));
                        coinHeight = coinHeightAndId.first;
                        id = coinHeightAndId.second;
                        if (coinHeight > 0
                            && id < coinId
                            && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()
                            && zerocoinState->GetCoinSetForSpend(
                                &chainActive,
                                chainActive.Height()-(ZC_MINT_CONFIRMATIONS-1),
                                denomination,
                                id,
                                blockHash,
                                anonimity_set) > 1 ) {
                            coinId = id;
                            coinToUse = minIdPubcoin;
                            tempCoinsToUse.insert(minIdPubcoin.value);
                            break;
                        }
                    }
                }

                // If no suitable coin found, fail.
                if (coinId == INT_MAX) {
                    strFailReason = _("it has to have at least two mint coins with at least 6 confirmation in order to spend a coin");
                    return false;
                }
                // 2. Get pubcoin from the private coin
                sigma::PublicCoinV3 pubCoinSelected(coinToUse.value, denomination);
                // Now make sure the coin is valid.
                if (!pubCoinSelected.validate()) {
                    // If this returns false, don't accept the coin for any purpose!
                    // Any ZEROCOIN_MINT with an invalid coin should NOT be
                    // accepted as a valid transaction in the block chain.
                    strFailReason = _("the selected mint coin is an invalid coin");
                    return false;
                }

                // Generate TxIn info
                int serializedId = coinId;
                CTxIn newTxIn;
                newTxIn.nSequence = serializedId;
                newTxIn.scriptSig = CScript();
                newTxIn.prevout.SetNull();
                txNew.vin.push_back(newTxIn);

                // Construct the CoinSpend object. This acts like a signature on the
                // transaction.
                sigma::PrivateCoinV3 privateCoin(zcParams, denomination);
                int txVersion = ZEROCOIN_TX_VERSION_3;

                LogPrintf("CreateZerocoinSpendTransaction: tx version=%d, tx metadata hash=%s\n", txVersion, txNew.GetHash().ToString());

                // Set all values in the private coin object
                privateCoin.setVersion(txVersion);
                privateCoin.setPublicCoin(pubCoinSelected);
                privateCoin.setRandomness(coinToUse.randomness);
                privateCoin.setSerialNumber(coinToUse.serialNumber);
//                privateCoin.setEcdsaSeckey(coinToUse.ecdsaSecretKey);

                LogPrintf("creating tempStorage object..\n");
                // Push created TxIn values into a tempStorage object (used in the next loop)
                TempStorage tempStorage {
                        privateCoin,
                        anonimity_set,
                        denomination,
                        blockHash,
                        coinToUse,
                        serializedId,
                        txVersion,
                        coinHeight,
                        coinId,
                };
                tempStorages.push_back(tempStorage);
            }

            // We now have the total coin amount to send. Create a single TxOut with this value.
            CTxOut newTxOut(nValue, scriptChange);
            // Insert single txout
            vector<CTxOut>::iterator position = txNew.vout.begin();
            txNew.vout.insert(position, newTxOut);

            /* We split the processing of the transaction into two loops.
             * The metaData hash is the hash of the transaction sans the zerocoin-related info (spend info).
             * Transaction processing is split to have the same txHash in every metaData object -
             * if the hash is different (as it would be if we did all steps for a TxIn in one loop) the transaction creation will fail.
            */

            // Remove all zerocoin related info
            CMutableTransaction txTemp = txNew;
            BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
                txTempIn.scriptSig.clear();
                txTempIn.prevout.SetNull();
            }

            uint256 txHashForMetadata = txTemp.GetHash();
            LogPrintf("txNew.GetHash: %s\n", txHashForMetadata.ToString());

            // Iterator of std::vector<std::pair<int64_t, sigma::CoinDenominationV3>>::const_iterator
            for (auto it = denominations.begin(); it != denominations.end(); it++)
            {
                unsigned index = it - denominations.begin();

                TempStorage tempStorage = tempStorages.at(index);
                CZerocoinEntryV3 coinToUse = tempStorage.coinToUse;

                //have to recreate coin witness as it can't be stored in an object, hence we can't store it in tempStorage..
                CZerocoinStateV3* zerocoinState = CZerocoinStateV3::GetZerocoinState();

                // Recreate CoinSpend object
                sigma::CoinSpendV3 spend(zcParams,
                                         tempStorage.privateCoin,
                                         tempStorage.anonimity_set,
                                         tempStorage.blockHash);
                spend.setVersion(tempStorage.txVersion);

                // Verify the coinSpend
                if (!spend.Verify(tempStorage.anonimity_set)) {
                    strFailReason = _("the spend coin transaction did not verify");
                    return false;
                }
                // Serialize the CoinSpend object into a buffer.
                CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
                serializedCoinSpend << spend;

                // Insert the spend script into the tx object
                CScript tmp = CScript() << OP_ZEROCOINSPENDV3;

                // NOTE(martun): Do not write the size first, doesn't look like necessary. 
                // If we write it, it will get written in different number of bytes depending 
                // on the number itself, and "CScript" does not provide a function to read 
                // it back properly.
                // << serializedCoinSpend.size();
                // NOTE(martun): "insert" is not the same as "operator<<", as operator<< 
                // also writes the vector size before the vector itself.
                tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
                txNew.vin[index].scriptSig.assign(tmp.begin(), tmp.end());

                // Try to find this coin in the list of spent coin serials.
                // If found, notify that a coin that was previously thought to be available is actually used, and fail.
                std::list <CZerocoinSpendEntryV3> listCoinSpendSerial;
                CWalletDB(strWalletFile).ListCoinSpendSerial(listCoinSpendSerial);
                BOOST_FOREACH(const CZerocoinSpendEntryV3 &item, listCoinSpendSerial){
                    if (!forceUsed && spend.getCoinSerialNumber() == item.coinSerial) {
                        // THIS SELECTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                        CZerocoinEntryV3 pubCoinTx;
                        pubCoinTx.nHeight = tempStorage.coinHeight;
                        pubCoinTx.set_denomination_value(coinToUse.get_denomination_value());
                        pubCoinTx.id = tempStorage.coinId;
                        pubCoinTx.IsUsed = true;
                        pubCoinTx.randomness = coinToUse.randomness;
                        pubCoinTx.serialNumber = coinToUse.serialNumber;
                        pubCoinTx.value = coinToUse.value;
//                        pubCoinTx.ecdsaSecretKey = coinToUse.ecdsaSecretKey;
                        CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                        LogPrintf("CreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                        LogPrintf("pubcoin=%s, isUsed=Used\n", coinToUse.value.GetHex());
                        pwalletMain->NotifyZerocoinChanged(
                            pwalletMain, 
                            coinToUse.value.GetHex(),
                            "Used ("+std::to_string(coinToUse.get_denomination_value() / COIN) + " mint)",
                            CT_UPDATED);
                        strFailReason = _("the coin spend has been used");
                        return false;
                    }
                }
            }

            txHash = wtxNew.GetHash();
            LogPrintf("wtxNew.txHash:%s\n", txHash.ToString());

            // Embed the constructed transaction data in wtxNew.
            *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);
            // Limit size
            if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                strFailReason = _("Transaction too large");
                return false;
            }

            // After transaction creation and verification, this last loop is to notify the wallet of changes to zerocoin spend info.
            for (auto it = denominations.begin(); it != denominations.end(); it++)
            {
                unsigned index = it - denominations.begin();
                TempStorage tempStorage = tempStorages.at(index);
                CZerocoinEntryV3 coinToUse = tempStorage.coinToUse;

                // Update the wallet with info on this zerocoin spend
                coinSerials.push_back(tempStorage.privateCoin.getSerialNumber());
                zcSelectedValues.push_back(coinToUse.value);

                CZerocoinSpendEntryV3 entry;
                entry.coinSerial = coinSerials[index];
                entry.hashTx = txHash;
                entry.pubCoin = coinToUse.value;
                entry.id = tempStorage.serializedId;
                entry.set_denomination_value(coinToUse.get_denomination_value());
                LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s\n", entry.coinSerial.tostring());
                if (!CWalletDB(strWalletFile).WriteCoinSpendSerialEntry(entry)) {
                    strFailReason = _("it cannot write coin serial number into wallet");
                }
                coinToUse.IsUsed = true;
                coinToUse.id = tempStorage.coinId;
                coinToUse.nHeight = tempStorage.coinHeight;
                CWalletDB(strWalletFile).WriteZerocoinEntry(coinToUse);
                pwalletMain->NotifyZerocoinChanged(
                    pwalletMain,
                    coinToUse.value.GetHex(),
                    "Used (" + std::to_string(coinToUse.get_denomination_value()) + " mint)",
                    CT_UPDATED);
            }
        }
    }
    return true;
}

bool CWallet::CommitZerocoinSpendTransaction(CWalletTx &wtxNew, CReserveKey &reservekey) {
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitZerocoinSpendTransaction:\n%s", wtxNew.ToString());
        LogPrintf("Transaction ID:%s\n", wtxNew.GetHash().ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB *pwalletdb = fFileBacked ? new CWalletDB(strWalletFile, "w") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew, false, pwalletdb);

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        if (fBroadcastTransactions) {
            CValidationState state;
            // Broadcast
            if (!wtxNew.AcceptToMemoryPool(false, maxTxFee, state, false, true)) {
                LogPrintf("CommitZerocoinSpendTransaction(): Transaction cannot be broadcast immediately, %s\n",
                          state.GetRejectReason());
                // TODO: if we expect the failure to be long term or permanent, 
                // instead delete wtx from the wallet and return failure.
            } else {
                wtxNew.RelayWalletTransaction(false);
            }
        }
    }
    return true;
}

string CWallet::MintAndStoreZerocoin(vector<CRecipient> vecSend, 
                                     vector<libzerocoin::PrivateCoin> privCoins, 
                                     CWalletTx &wtxNew, bool fAskFee) {
    string strError;
    if (IsLocked()) {
        strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError);
        return strError;
    }

    int totalValue = 0;
    BOOST_FOREACH(CRecipient recipient, vecSend){
        // Check amount
        if (recipient.nAmount <= 0)
            return _("Invalid amount");

        LogPrintf("MintZerocoin: value = %s\n", recipient.nAmount);
        totalValue += recipient.nAmount;

    }
    if ((totalValue + payTxFee.GetFeePerK()) > GetBalance())
        return _("Insufficient funds");

    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    CReserveKey reservekey(this);
    int64_t nFeeRequired;
    
    int nChangePosRet = -1;    

    if (!CreateZerocoinMintTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (totalValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired)){
        LogPrintf("MintZerocoin: returning aborted..\n");
        return "ABORTED";
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);
    libzerocoin::Params *zcParams = ZCParamsV2;

    BOOST_FOREACH(libzerocoin::PrivateCoin privCoin, privCoins){
        CZerocoinEntry zerocoinTx;
        zerocoinTx.IsUsed = false;                         
        zerocoinTx.denomination = privCoin.getPublicCoin().getDenomination();
        zerocoinTx.value = privCoin.getPublicCoin().getValue();
        libzerocoin::PublicCoin checkPubCoin(zcParams, zerocoinTx.value, privCoin.getPublicCoin().getDenomination());
        if (!checkPubCoin.validate()) {
            return "error: pubCoin not validated.";
        }
        zerocoinTx.randomness = privCoin.getRandomness();
        zerocoinTx.serialNumber = privCoin.getSerialNumber();
        const unsigned char *ecdsaSecretKey = privCoin.getEcdsaSeckey();
        zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        walletdb.WriteZerocoinEntry(zerocoinTx);
    }

    if (!CommitTransaction(wtxNew, reservekey)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
    }

    return "";
}

string CWallet::MintAndStoreZerocoinV3(vector<CRecipient> vecSend,
                                     vector<sigma::PrivateCoinV3> privCoins,
                                     CWalletTx &wtxNew, bool fAskFee) {
    string strError;
    if (IsLocked()) {
        strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError);
        return strError;
    }

    int totalValue = 0;
    BOOST_FOREACH(CRecipient recipient, vecSend){
        // Check amount
        if (recipient.nAmount <= 0)
            return _("Invalid amount");

        LogPrintf("MintZerocoin: value = %s\n", recipient.nAmount);
        totalValue += recipient.nAmount;

    }
    if ((totalValue + payTxFee.GetFeePerK()) > GetBalance())
        return _("Insufficient funds");

    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    int nChangePosRet = -1;

    if (!CreateZerocoinMintTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (totalValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired)){
        LogPrintf("MintZerocoin: returning aborted..\n");
        return "ABORTED";
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);
    sigma::ParamsV3* zcParams = sigma::ParamsV3::get_default();

    BOOST_FOREACH(sigma::PrivateCoinV3 privCoin, privCoins){
        CZerocoinEntryV3 zerocoinTx;
        zerocoinTx.IsUsed = false;
        zerocoinTx.set_denomination(privCoin.getPublicCoin().getDenomination());
        zerocoinTx.value = privCoin.getPublicCoin().getValue();
        sigma::PublicCoinV3 checkPubCoin(zerocoinTx.value, privCoin.getPublicCoin().getDenomination());
        if (!checkPubCoin.validate()) {
            return "error: pubCoin not validated.";
        }
        zerocoinTx.randomness = privCoin.getRandomness();
        zerocoinTx.serialNumber = privCoin.getSerialNumber();
        // TODO(martun): check this again, but looks like in Sigma we do not need ecdsaSecretKey.
//        const unsigned char *ecdsaSecretKey = privCoin.getEcdsaSeckey();
//        zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        walletdb.WriteZerocoinEntry(zerocoinTx);
    }

    if (!CommitTransaction(wtxNew, reservekey)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
    }

    return "";
}

/**
 * @brief CWallet::MintZerocoin
 * @param pubCoin
 * @param nValue
 * @param wtxNew
 * @param fAskFee
 * @return
 */
string CWallet::MintZerocoin(CScript pubCoin, int64_t nValue, CWalletTx &wtxNew, bool fAskFee) {

    LogPrintf("MintZerocoin: value = %s\n", nValue);
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    LogPrintf("CWallet.MintZerocoin() nValue = %s, payTxFee.GetFee(1000) = %s, GetBalance() = %s \n", nValue,
              payTxFee.GetFee(1000), GetBalance());
    if (nValue + payTxFee.GetFeePerK() > GetBalance())
        return _("Insufficient funds");
    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    if (!CreateZerocoinMintTransaction(pubCoin, nValue, wtxNew, reservekey, nFeeRequired, strError)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (nValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
//        //TODO :
//        // 1. In this case, we already have pubcoin that just committed to network.
//        // 2. what we can do is <pubcoin><isOur><isUsed> storing in wallet
//        // 3. We will store pubcoin, yes, no
    }

    return "";
}

/**
 * @brief CWallet::SpendZerocoin
 * @param nValue
 * @param denomination
 * @param wtxNew
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @return
 */
string CWallet::SpendZerocoin(std::string &thirdPartyaddress, int64_t nValue, libzerocoin::CoinDenomination denomination, CWalletTx &wtxNew,
                              CBigNum &coinSerial, uint256 &txHash, CBigNum &zcSelectedValue,
                              bool &zcSelectedIsUsed, bool forceUsed) {
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");

    CReserveKey reservekey(this);

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    if (!CreateZerocoinSpendTransaction(thirdPartyaddress, nValue, denomination, wtxNew, reservekey, coinSerial, txHash,
                                        zcSelectedValue, zcSelectedIsUsed, strError, forceUsed)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey)) {
        LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
        CZerocoinEntry pubCoinTx;
        list <CZerocoinEntry> listPubCoin;
        listPubCoin.clear();

        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.ListPubCoin(listPubCoin);
        BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
            if (zcSelectedValue == pubCoinItem.value) {
                pubCoinTx.id = pubCoinItem.id;
                pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                pubCoinTx.value = pubCoinItem.value;
                pubCoinTx.nHeight = pubCoinItem.nHeight;
                pubCoinTx.randomness = pubCoinItem.randomness;
                pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                pubCoinTx.denomination = pubCoinItem.denomination;
                pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                pwalletMain->NotifyZerocoinChanged(pwalletMain, pubCoinItem.value.GetHex(), "New", CT_UPDATED);
            }
        }
        CZerocoinSpendEntry entry;
        entry.coinSerial = coinSerial;
        entry.hashTx = txHash;
        entry.pubCoin = zcSelectedValue;
        if (!CWalletDB(strWalletFile).EraseCoinSpendSerialEntry(entry)) {
            return _("Error: It cannot delete coin serial number in wallet");
        }
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }
    return "";
}

string CWallet::SpendZerocoinV3(
        std::string &thirdPartyaddress, 
        sigma::CoinDenominationV3 denomination,
        CWalletTx &wtxNew,
        Scalar &coinSerial,
        uint256 &txHash,
        GroupElement &zcSelectedValue,
        bool &zcSelectedIsUsed,
        bool forceUsed) {
    CReserveKey reservekey(this);

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    if (!CreateZerocoinSpendTransactionV3(
            thirdPartyaddress, denomination, wtxNew, reservekey, coinSerial, txHash,
            zcSelectedValue, zcSelectedIsUsed, strError, forceUsed)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey)) {
        LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
        CZerocoinEntryV3 pubCoinTx;
        list <CZerocoinEntryV3> listPubCoin;
        listPubCoin.clear();

        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.ListPubCoinV3(listPubCoin);
        BOOST_FOREACH(const CZerocoinEntryV3 &pubCoinItem, listPubCoin) {
            if (zcSelectedValue == pubCoinItem.value) {
                pubCoinTx.id = pubCoinItem.id;
                pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                pubCoinTx.value = pubCoinItem.value;
                pubCoinTx.nHeight = pubCoinItem.nHeight;
                pubCoinTx.randomness = pubCoinItem.randomness;
                pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                pubCoinTx.set_denomination_value(pubCoinItem.get_denomination_value());
//                pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                pwalletMain->NotifyZerocoinChanged(pwalletMain, pubCoinItem.value.GetHex(), "New", CT_UPDATED);
            }
        }
        CZerocoinSpendEntryV3 entry;
        entry.coinSerial = coinSerial;
        entry.hashTx = txHash;
        entry.pubCoin = zcSelectedValue;
        if (!CWalletDB(strWalletFile).EraseCoinSpendSerialEntry(entry)) {
            return _("Error: It cannot delete coin serial number in wallet");
        }
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }
    return "";
}


/**
 * @brief CWallet::SpendZerocoin
 * @param thirdPartyaddress
 * @param nValue
 * @param denomination
 * @param wtxNew
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @return
 */
string CWallet::SpendMultipleZerocoin(std::string &thirdPartyaddress, const std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>>& denominations, CWalletTx &wtxNew,
                              vector<CBigNum> &coinSerials, uint256 &txHash, vector<CBigNum> &zcSelectedValues, bool forceUsed) {
     CReserveKey reservekey(this);
     string strError = "";
     if (IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }
    
    if (!CreateMultipleZerocoinSpendTransaction(thirdPartyaddress, denominations, wtxNew, reservekey, coinSerials, txHash, zcSelectedValues, strError, forceUsed)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey)) {
        LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
        CZerocoinEntry pubCoinTx;
        list <CZerocoinEntry> listPubCoin;
        listPubCoin.clear();
        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.ListPubCoin(listPubCoin);

        for (std::vector<CBigNum>::iterator it = coinSerials.begin(); it != coinSerials.end(); it++){
            unsigned index = it - coinSerials.begin();
            CBigNum zcSelectedValue = zcSelectedValues[index];
            BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
                if (zcSelectedValue == pubCoinItem.value) {
                    pubCoinTx.id = pubCoinItem.id;
                    pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                    pubCoinTx.value = pubCoinItem.value;
                    pubCoinTx.nHeight = pubCoinItem.nHeight;
                    pubCoinTx.randomness = pubCoinItem.randomness;
                    pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                    pubCoinTx.denomination = pubCoinItem.denomination;
                    pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                    CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                }
            }
            CZerocoinSpendEntry entry;
            entry.coinSerial = coinSerials[index];
            entry.hashTx = txHash;
            entry.pubCoin = zcSelectedValue;
            if (!CWalletDB(strWalletFile).EraseCoinSpendSerialEntry(entry)) {
                strError.append("Error: It cannot delete coin serial number in wallet.\n");
            }
        }
        strError.append("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        return strError;
    }

     return "";
 }

string CWallet::SpendMultipleZerocoinV3(
        std::string &thirdPartyaddress,
        const std::vector<sigma::CoinDenominationV3>& denominations,
        CWalletTx &wtxNew,
        vector<Scalar> &coinSerials,
        uint256 &txHash,
        vector<GroupElement> &zcSelectedValues,
        bool forceUsed) {
    CReserveKey reservekey(this);
    string strError = "";
    if (IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }

    if (!CreateMultipleZerocoinSpendTransactionV3(thirdPartyaddress, denominations, wtxNew, reservekey, coinSerials, txHash, zcSelectedValues, strError, forceUsed)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey)) {
        LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
        CZerocoinEntryV3 pubCoinTx;
        list <CZerocoinEntryV3> listPubCoin;
        listPubCoin.clear();
        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.ListPubCoinV3(listPubCoin);

        for (std::vector<Scalar>::iterator it = coinSerials.begin(); it != coinSerials.end(); it++){
            unsigned index = it - coinSerials.begin();
            GroupElement zcSelectedValue = zcSelectedValues[index];
            BOOST_FOREACH(const CZerocoinEntryV3 &pubCoinItem, listPubCoin) {
                if (zcSelectedValue == pubCoinItem.value) {
                    pubCoinTx.id = pubCoinItem.id;
                    pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                    pubCoinTx.value = pubCoinItem.value;
                    pubCoinTx.nHeight = pubCoinItem.nHeight;
                    pubCoinTx.randomness = pubCoinItem.randomness;
                    pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                    pubCoinTx.set_denomination_value(pubCoinItem.get_denomination_value());
//                    pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                    CWalletDB(strWalletFile).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                }
            }
            CZerocoinSpendEntryV3 entry;
            entry.coinSerial = coinSerials[index];
            entry.hashTx = txHash;
            entry.pubCoin = zcSelectedValue;
            if (!CWalletDB(strWalletFile).EraseCoinSpendSerialEntry(entry)) {
                strError.append("Error: It cannot delete coin serial number in wallet.\n");
            }
        }
        strError.append("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        return strError;
    }

    return "";
}

bool CWallet::AddAccountingEntry(const CAccountingEntry &acentry, CWalletDB &pwalletdb) {
    if (!pwalletdb.WriteAccountingEntry_Backend(acentry))
        return false;

    laccentries.push_back(acentry);
    CAccountingEntry &entry = laccentries.back();
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx *) 0, &entry)));

    return true;
}

CAmount CWallet::GetRequiredFee(unsigned int nTxBytes) {
    return std::max(minTxFee.GetFee(nTxBytes), ::minRelayTxFee.GetFee(nTxBytes));
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool &pool) {
    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0) {
        int estimateFoundTarget = nConfirmTarget;
        nFeeNeeded = pool.estimateSmartFee(nConfirmTarget, &estimateFoundTarget).GetFee(nTxBytes);
        // ... unless we don't have enough mempool data for estimatefee, then use fallbackFee
        if (nFeeNeeded == 0)
            nFeeNeeded = fallbackFee.GetFee(nTxBytes);
    }
    // prevent user from paying a fee below minRelayTxFee or minTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));
    // But always obey the maximum
    if (nFeeNeeded > maxTxFee)
        nFeeNeeded = maxTxFee;
    return nFeeNeeded;
}


DBErrors CWallet::LoadWallet(bool &fFirstRunRet) {
    LogPrintf("LoadWallet, firstRun = %s\n", fFirstRunRet);
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile, "cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE) {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapSelectTx(vector <uint256> &vHashIn, vector <uint256> &vHashOut) {
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapSelectTxRet = CWalletDB(strWalletFile, "cr+").ZapSelectTx(this, vHashIn, vHashOut);
    if (nZapSelectTxRet == DB_NEED_REWRITE) {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;

}

DBErrors CWallet::ZapWalletTx(std::vector <CWalletTx> &vWtx) {
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile, "cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE) {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination &address, const string &strName, const string &strPurpose) {
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW));
    if (!fFileBacked)
        return false;
    if (!strPurpose.empty() &&
        !CWalletDB(strWalletFile).WritePurpose(CBitcoinAddress(address).ToString(), strPurpose))
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBook(const CTxDestination &address) {
    {
        LOCK(cs_wallet); // mapAddressBook

        if (fFileBacked) {
            // Delete destdata tuples associated with address
            std::string strAddress = CBitcoinAddress(address).ToString();
            BOOST_FOREACH(const PAIRTYPE(string, string) &item, mapAddressBook[address].destdata)
            {
                CWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CWalletDB(strWalletFile).ErasePurpose(CBitcoinAddress(address).ToString());
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey) {
    if (fFileBacked) {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool() {
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
        walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);
        for (int i = 0; i < nKeys; i++) {
            int64_t nIndex = i + 1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize) {
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        while (setKeyPool.size() < (nTargetSize + 1)) {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error(std::string(__func__) + ": writing generated key failed");
            setKeyPool.insert(nEnd);
            LogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t &nIndex, CKeyPool &keypool) {
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if (setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error(std::string(__func__) + ": read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error(std::string(__func__) + ": unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex) {
    // Remove from key pool
    if (fFileBacked) {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex) {
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey &result) {
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1) {
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime() {
    LOCK(cs_wallet);

    // if the keypool is empty, return <NOW>
    if (setKeyPool.empty())
        return GetTime();

    // load oldest key from keypool, get time and return
    CKeyPool keypool;
    CWalletDB walletdb(strWalletFile);
    int64_t nIndex = *(setKeyPool.begin());
    if (!walletdb.ReadPool(nIndex, keypool))
        throw runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

std::map <CTxDestination, CAmount> CWallet::GetAddressBalances() {
    map <CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!CheckFinalTx(*pcoin) || !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if (!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set <set<CTxDestination>> CWallet::GetAddressGroupings() {
    AssertLockHeld(cs_wallet); // mapWallet
    set <set<CTxDestination>> groupings;
    set <CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0) {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if (!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if (!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) {
                BOOST_FOREACH(CTxOut txout, pcoin->vout)
                if (IsChange(txout)) {
                    CTxDestination txoutAddr;
                    if (!ExtractDestination(txout.scriptPubKey, txoutAddr))
                        continue;
                    grouping.insert(txoutAddr);
                }
            }
            if (grouping.size() > 0) {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i])) {
                CTxDestination address;
                if (!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set < set < CTxDestination > * > uniqueGroupings; // a set of pointers to groups of addresses
    map < CTxDestination, set < CTxDestination > * > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set < CTxDestination > grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set < set < CTxDestination > * > hits;
        map < CTxDestination, set < CTxDestination > * > ::iterator
        it;
        BOOST_FOREACH(CTxDestination address, grouping)
        if ((it = setmap.find(address)) != setmap.end())
            hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set <CTxDestination> *merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set < CTxDestination > *hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
        setmap[element] = merged;
    }

    set <set<CTxDestination>> ret;
    BOOST_FOREACH(set < CTxDestination > *uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

CAmount CWallet::GetAccountBalance(const std::string &strAccount, int nMinDepth, const isminefilter &filter) {
    CWalletDB walletdb(strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter);
}

CAmount CWallet::GetAccountBalance(CWalletDB &walletdb, const std::string &strAccount, int nMinDepth,
                                   const isminefilter &filter) {
    CAmount nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;
        if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
            continue;

        CAmount nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee, filter);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance -= nSent + nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

std::set <CTxDestination> CWallet::GetAccountAddresses(const std::string &strAccount) const {
    LOCK(cs_wallet);
    set <CTxDestination> result;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)&item, mapAddressBook)
    {
        const CTxDestination &address = item.first;
        const string &strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey &pubkey) {
    if (nIndex == -1) {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey() {
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey() {
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set <CKeyID> &setAddress) const {
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t &id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error(std::string(__func__) + ": read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error(std::string(__func__) + ": unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx) {
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::GetScriptForMining(boost::shared_ptr <CReserveScript> &script) {
    boost::shared_ptr <CReserveKey> rKey(new CReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

void CWallet::LockCoin(const COutPoint &output) {
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint &output) {
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins() {
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const {
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector <COutPoint> &vOutpts) {
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector <CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector <CKeyID> &vKeysIn) : keystore(keystoreIn),
                                                                                       vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector <CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            BOOST_FOREACH(const CTxDestination &dest, vDest)
            boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map <CKeyID, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin();
         it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() -
                                                     144)]; // the tip can be reorganized; use a 144-block safety margin
    std::map < CKeyID, CBlockIndex * > mapKeyFirstBlock;
    std::set <CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector <CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex *>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex *>::const_iterator it = mapKeyFirstBlock.begin();
         it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value) {
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteDestData(CBitcoinAddress(dest).ToString(), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key) {
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).EraseDestData(CBitcoinAddress(dest).ToString(), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value) {
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const {
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if (i != mapAddressBook.end()) {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if (j != i->second.destdata.end()) {
            if (value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::string CWallet::GetWalletHelpString(bool showDebug) {
    std::string strUsage = HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-keypool=<n>",
                               strprintf(_("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-fallbackfee=<amt>", strprintf(
            _("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
            CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-mintxfee=<amt>", strprintf(
            _("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage += HelpMessageOpt("-paytxfee=<amt>",
                               strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
                                         CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions on startup"));
    strUsage += HelpMessageOpt("-salvagewallet",
                               _("Attempt to recover private keys from a corrupt wallet on startup"));
    if (showDebug)
        strUsage += HelpMessageOpt("-sendfreetransactions",
                                   strprintf(
                                           _("Send transactions as zero-fee transactions if possible (default: %u)"),
                                           DEFAULT_SEND_FREE_TRANSACTIONS));
    strUsage += HelpMessageOpt("-spendzeroconfchange",
                               strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"),
                                         DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt("-txconfirmtarget=<n>", strprintf(
            _("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"),
            DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-usehd",
                               _("Use hierarchical deterministic key generation (HD) after BIP32. Only has effect during wallet creation/first start") +
                               " " + strprintf(_("(default: %u)"), DEFAULT_USE_HD_WALLET));
    strUsage += HelpMessageOpt("-upgradewallet", _("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", _("Specify wallet file (within data directory)") + " " +
                                                 strprintf(_("(default: %s)"), DEFAULT_WALLET_DAT));
    strUsage += HelpMessageOpt("-walletbroadcast", _("Make the wallet broadcast transactions") + " " +
                                                   strprintf(_("(default: %u)"), DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt("-walletnotify=<cmd>",
                               _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>",
                               _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
                               " " +
                               _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));

    if (showDebug) {
        strUsage += HelpMessageGroup(_("Wallet debugging/testing options:"));

        strUsage += HelpMessageOpt("-dblogsize=<n>", strprintf(
                "Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)",
                DEFAULT_WALLET_DBLOGSIZE));
        strUsage += HelpMessageOpt("-flushwallet",
                                   strprintf("Run a thread to flush wallet periodically (default: %u)",
                                             DEFAULT_FLUSHWALLET));
        strUsage += HelpMessageOpt("-privdb",
                                   strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)",
                                             DEFAULT_WALLET_PRIVDB));
        strUsage += HelpMessageOpt("-walletrejectlongchains", strprintf(
                _("Wallet will not create transactions that violate mempool chain limits (default: %u"),
                DEFAULT_WALLET_REJECT_LONG_CHAINS));
    }

    return strUsage;
}


bool CWallet::InitLoadWallet() {
    LogPrintf("InitLoadWallet()\n");
    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector <CWalletTx> vWtx;

    if (GetBoolArg("-zapwallettxes", false)) {
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        CWallet *tempWallet = new CWallet(walletFile);
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK) {
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        }

        delete tempWallet;
        tempWallet = NULL;
    }

    uiInterface.InitMessage(_("Loading wallet..."));
    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    CWallet *walletInstance = new CWallet(walletFile);
    pwalletMain = walletInstance;

    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    LogPrintf("Load done!\n");
    if (nLoadWalletRet != DB_LOAD_OK) {
        if (nLoadWalletRet == DB_CORRUPT)
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR) {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                            " or address book entries might be missing or incorrect."),
                                  walletFile));
        } else if (nLoadWalletRet == DB_TOO_NEW)
            return InitError(strprintf(_("Error loading %s: Wallet requires newer version of %s"),
                                       walletFile, _(PACKAGE_NAME)));
        else if (nLoadWalletRet == DB_NEED_REWRITE) {
            return InitError(
                    strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
        } else
            return InitError(strprintf(_("Error loading %s"), walletFile));
    }

    if (GetBoolArg("-upgradewallet", fFirstRun)) {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        } else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion()) {
            return InitError(_("Cannot downgrade wallet"));
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun) {
        // Create new keyUser and set as default key
        if (GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET) && walletInstance->hdChain.masterKeyID.IsNull()) {
            // generate a new master key
            CPubKey masterPubKey = walletInstance->GenerateNewHDMasterKey();
            if (!walletInstance->SetHDMasterKey(masterPubKey))
                throw std::runtime_error(std::string(__func__) + ": Storing master key failed");
        }
        CPubKey newDefaultKey;
        if (walletInstance->GetKeyFromPool(newDefaultKey)) {
            walletInstance->SetDefaultKey(newDefaultKey);
            if (!walletInstance->SetAddressBook(walletInstance->vchDefaultKey.GetID(), "", "receive"))
                return InitError(_("Cannot write default address") += "\n");
        }

        walletInstance->SetBestChain(chainActive.GetLocator());
    } else if (mapArgs.count("-usehd")) {
        bool useHD = GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET);
        if (!walletInstance->hdChain.masterKeyID.IsNull() && !useHD)
            return InitError(
                    strprintf(_("Error loading %s: You can't disable HD on a already existing HD wallet"),
                              walletFile));
        if (walletInstance->hdChain.masterKeyID.IsNull() && useHD)
            return InitError(
                    strprintf(_("Error loading %s: You can't enable HD on a already existing non-HD wallet"),
                              walletFile));
    }

    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);

    RegisterValidationInterface(walletInstance);

    CBlockIndex *pindexRescan = chainActive.Tip();
    if (GetBoolArg("-rescan", false))
        pindexRescan = chainActive.Genesis();
    else {
        CWalletDB walletdb(walletFile);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = FindForkInGlobalIndex(chainActive, locator);
        else
            pindexRescan = chainActive.Genesis();
    }
    if (chainActive.Tip() && chainActive.Tip() != pindexRescan) {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses a old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (fPruneMode) {
            CBlockIndex *block = chainActive.Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 &&
                   pindexRescan != block)
                block = block->pprev;

            if (pindexRescan != block)
                return InitError(
                        _("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
        }

        uiInterface.InitMessage(_("Rescanning..."));
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight,
                  pindexRescan->nHeight);
        nStart = GetTimeMillis();
        walletInstance->ScanForWalletTransactions(pindexRescan, true);
        LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(chainActive.GetLocator());
        nWalletDBUpdated++;

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (GetBoolArg("-zapwallettxes", false) && GetArg("-zapwallettxes", "1") != "2") {
            CWalletDB walletdb(walletFile);

            BOOST_FOREACH(const CWalletTx &wtxOld, vWtx)
            {
                uint256 hash = wtxOld.GetHash();
                std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end()) {
                    const CWalletTx *copyFrom = &wtxOld;
                    CWalletTx *copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    walletdb.WriteTx(*copyTo);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    pwalletMain = walletInstance;
    return true;
}

bool CWallet::ParameterInteraction() {
    if (mapArgs.count("-mintxfee")) {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-mintxfee"], n) && n > 0)
            CWallet::minTxFee = CFeeRate(n);
        else
            return InitError(AmountErrMsg("mintxfee", mapArgs["-mintxfee"]));
    }
    if (mapArgs.count("-fallbackfee")) {
        CAmount nFeePerK = 0;
        if (!ParseMoney(mapArgs["-fallbackfee"], nFeePerK))
            return InitError(
                    strprintf(_("Invalid amount for -fallbackfee=<amount>: '%s'"), mapArgs["-fallbackfee"]));
//        if (nFeePerK > HIGH_TX_FEE_PER_KB)
//            InitWarning(
//                    _("-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available."));
        CWallet::fallbackFee = CFeeRate(nFeePerK);
    }
    if (mapArgs.count("-paytxfee")) {
        CAmount nFeePerK = 0;
        if (!ParseMoney(mapArgs["-paytxfee"], nFeePerK))
            return InitError(AmountErrMsg("paytxfee", mapArgs["-paytxfee"]));
//        if (nFeePerK > HIGH_TX_FEE_PER_KB)
//            InitWarning(_("-paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee) {
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                       mapArgs["-paytxfee"], ::minRelayTxFee.ToString()));
        }
    }
    if (mapArgs.count("-maxtxfee")) {
        CAmount nMaxFee = 0;
        if (!ParseMoney(mapArgs["-maxtxfee"], nMaxFee))
            return InitError(AmountErrMsg("maxtxfee", mapArgs["-maxtxfee"]));
//        if (nMaxFee > HIGH_MAX_TX_FEE)
//            InitWarning(_("-maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee) {
            return InitError(strprintf(
                    _("Invalid amount for -maxtxfee=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                    mapArgs["-maxtxfee"], ::minRelayTxFee.ToString()));
        }
    }

    if (mapArgs.count("-mininput")) {
        if (!ParseMoney(mapArgs["-mininput"], nMinimumInputValue))
            return InitError(
                    strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), mapArgs["-mininput"].c_str()));
    }

    nTxConfirmTarget = GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    fSendFreeTransactions = GetBoolArg("-sendfreetransactions", DEFAULT_SEND_FREE_TRANSACTIONS);

    return true;
}

bool CWallet::BackupWallet(const std::string &strDest) {
    if (!fFileBacked)
        return false;
    while (true) {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strWalletFile) || bitdb.mapFileUseCount[strWalletFile] == 0) {
                // Flush log data to the dat file
                bitdb.CloseDb(strWalletFile);
                bitdb.CheckpointLSN(strWalletFile);
                bitdb.mapFileUseCount.erase(strWalletFile);

                // Copy wallet file
                boost::filesystem::path pathSrc = GetDataDir() / strWalletFile;
                boost::filesystem::path pathDest(strDest);
                if (boost::filesystem::is_directory(pathDest))
                    pathDest /= strWalletFile;

                try {
#if BOOST_VERSION >= 104000
                    boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists);
#else
                    boost::filesystem::copy_file(pathSrc, pathDest);
#endif
                    LogPrintf("copied %s to %s\n", strWalletFile, pathDest.string());
                    return true;
                } catch (const boost::filesystem::filesystem_error &e) {
                    LogPrintf("error copying %s to %s - %s\n", strWalletFile, pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

CKeyPool::CKeyPool() {
    nTime = GetTime();
}

CKeyPool::CKeyPool(const CPubKey &vchPubKeyIn) {
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t
                       nExpires) {
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

int CMerkleTx::SetMerkleBranch(const CBlock &block) {
    AssertLockHeld(cs_main);
    CBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int) block.vtx.size(); nIndex++)
        if (block.vtx[nIndex] == *(CTransaction * )this)
    break;
    if (nIndex == (int) block.vtx.size()) {
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch(): couldn't find tx in block\n");
        return 0;
    }

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    const CBlockIndex *pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    return chainActive.Height() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet, bool enableIX) const {
    int nResult;

    if (hashUnset())
        nResult = 0;
    else {
        AssertLockHeld(cs_main);

        // Find the block it claims to be in
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi == mapBlockIndex.end())
            nResult = 0;
        else {
            CBlockIndex *pindex = (*mi).second;
            if (!pindex || !chainActive.Contains(pindex))
                nResult = 0;
            else {
                pindexRet = pindex;
                nResult = ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);

                if (nResult == 0 && !mempool.exists(GetHash()))
                    return -1; // Not in chain, not in mempool
            }
        }
    }

    if (enableIX && nResult < 6 && instantsend.IsLockedInstantSendTransaction(GetHash()))
        return nInstantSendDepth + nResult;

    return nResult;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet) const {
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;
    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const {
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY + 1) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(
        bool fLimitFree, 
        CAmount nAbsurdFee, 
        CValidationState &state, 
        bool fCheckInputs,
        bool isCheckWalletTransaction,
        bool markZcoinSpendTransactionSerial) {
    LogPrintf("CMerkleTx::AcceptToMemoryPool(), transaction %s, fCheckInputs=%s\n", 
              GetHash().ToString(), 
              fCheckInputs);
    if (GetBoolArg("-dandelion", true)) {
        bool res = ::AcceptToMemoryPool(
            stempool, 
            state, 
            *this, 
            fCheckInputs, 
            fLimitFree, 
            NULL, /* pfMissingInputs */
            false, /* fOverrideMempoolLimit */
            nAbsurdFee, 
            isCheckWalletTransaction,
            false /* markZcoinSpendTransactionSerial */
        );
        if (!res) {
            LogPrintf(
                "CMerkleTx::AcceptToMemoryPool, failed to add txn %s to dandelion stempool: %s.\n", 
                GetHash().ToString(), 
                state.GetRejectReason());
        }
        return res;
    } else {
        // Changes to mempool should also be made to Dandelion stempool
        CValidationState dummyState;
        ::AcceptToMemoryPool(
            stempool, 
            dummyState, 
            *this, 
            fCheckInputs, 
            fLimitFree, 
            NULL, /* pfMissingInputs */ 
            false, /* fOverrideMempoolLimit */
            nAbsurdFee, 
            isCheckWalletTransaction,
            false /* markZcoinSpendTransactionSerial */
        );
        return ::AcceptToMemoryPool(
            mempool, 
            state, 
            *this, 
            fCheckInputs, 
            fLimitFree, 
            NULL, /* pfMissingInputs */
            false, /* fOverrideMempoolLimit */
            nAbsurdFee, 
            isCheckWalletTransaction, 
            markZcoinSpendTransactionSerial);
    }
}

bool CompHeight(const CZerocoinEntry &a, const CZerocoinEntry &b) { return a.nHeight < b.nHeight; }
bool CompHeightV3(const CZerocoinEntryV3 &a, const CZerocoinEntryV3 &b) { return a.nHeight < b.nHeight; }

bool CompID(const CZerocoinEntry &a, const CZerocoinEntry &b) { return a.id < b.id; }
bool CompIDV3(const CZerocoinEntryV3 &a, const CZerocoinEntryV3 &b) { return a.id < b.id; }

bool CompDenominationHeightV3(const CZerocoinEntryV3 &a, const CZerocoinEntryV3 &b) { 
    return a.denomination != b.denomination? a.denomination > b.denomination : a.nHeight < b.nHeight; 
}

