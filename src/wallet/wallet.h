// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLET_H
#define BITCOIN_WALLET_WALLET_H

#include "amount.h"
#include "../sigma/coin.h"
#include "../liblelantus/coin.h"
#include "libspark/keys.h"
#include "streams.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "script/ismine.h"
#include "script/sign.h"
#include "wallet/crypter.h"
#ifdef ENABLE_WALLET
#include "wallet/walletdb.h"
#endif // ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/mnemoniccontainer.h"
#include "../spark/sparkwallet.h"
#include "../base58.h"
#include "firo_params.h"
#include "univalue.h"

#include "hdmint/tracker.h"
#include "hdmint/wallet.h"

#include "primitives/mint_spend.h"

#include "bip47/paymentcode.h"


#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

extern CWallet* pwalletMain;

/**
 * Settings
 */
extern CFeeRate payTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool fSendFreeTransactions;
extern bool fWalletRbf;

static const unsigned int DEFAULT_KEYPOOL_SIZE = 100;
//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0;
//! -fallbackfee default
static const CAmount DEFAULT_FALLBACK_FEE = 20000;
//! -mintxfee default
static const CAmount DEFAULT_TRANSACTION_MINFEE = 1000;
//! minimum recommended increment for BIP 125 replacement txs
static const CAmount WALLET_INCREMENTAL_RELAY_FEE = 5000;
//! target minimum change amount
static const CAmount MIN_CHANGE = CENT;
//! final minimum change amount after paying for fees
static const CAmount MIN_FINAL_CHANGE = MIN_CHANGE/2;
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -sendfreetransactions
static const bool DEFAULT_SEND_FREE_TRANSACTIONS = false;
//! Default for -walletrejectlongchains
static const bool DEFAULT_WALLET_REJECT_LONG_CHAINS = false;
//! -txconfirmtarget default
static const unsigned int DEFAULT_TX_CONFIRM_TARGET = 6;
//! -walletrbf default
static const bool DEFAULT_WALLET_RBF = false;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;
static const bool DEFAULT_WALLETBROADCAST = true;
static const bool DEFAULT_DISABLE_WALLET = false;

static const bool DEFAULT_UPGRADE_CHAIN = false;

//! if set, all keys will be derived by using BIP32
static const bool DEFAULT_USE_HD_WALLET = true;

//! if set, all keys will be derived by using BIP39
static const bool DEFAULT_USE_MNEMONIC = true;

extern const char * DEFAULT_WALLET_DAT;

const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;
const uint32_t BIP44_INDEX = 0x2C;
const uint32_t BIP44_TEST_INDEX = 0x1;   // https://github.com/satoshilabs/slips/blob/master/slip-0044.md#registered-coin-types
const uint32_t BIP44_FIRO_INDEX = 0x88; // https://github.com/satoshilabs/slips/blob/master/slip-0044.md#registered-coin-types
const uint32_t BIP44_MINT_INDEX = 0x2;

const uint32_t BIP44_MINT_VALUE_INDEX = 0x5;

class CBlockIndex;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CTxMemPool;
class CWalletTx;
namespace bip47 {
class CPaymentChannel;
}


namespace bip47 {
    class CPaymentCode;
    class CWallet;
}

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_HD = 130000, // Hierarchical key derivation after BIP32 (HD Wallet)
    FEATURE_LATEST = FEATURE_COMPRPUBKEY // HD is optional, use FEATURE_COMPRPUBKEY as latest version
};

struct CompactTallyItem
{
    CBitcoinAddress address;
    CAmount nAmount;
    std::vector<CTxIn> vecTxIn;
    CompactTallyItem()
    {
        nAmount = 0;
    }
};


/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

struct CRecipient
{
    CScript scriptPubKey;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
    std::string address {};
    std::string memo {};
};

typedef std::map<std::string, std::string> mapValue_t;


static inline void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static inline void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx
{
private:
  /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    CTransactionRef tx;
    uint256 hashBlock;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CMerkleTx()
    {
        SetTx(MakeTransactionRef());
        Init();
    }

    CMerkleTx(CTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    /** Helper conversion operator to allow passing CMerkleTx where CTransaction is expected.
     *  TODO: adapt callers and remove this operator. */
    operator const CTransaction&() const { return *tx; }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    void SetMerkleBranch(const CBlockIndex* pIndex, int posInBlock);

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }

    int GetDepthInMainChain(const CBlockIndex* &pindexRet, bool enableIX) const;
    int GetDepthInMainChain(bool enableIX) const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet, enableIX); }

    bool IsInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet) > 0; }
    bool IsLockedByLLMQInstantSend() const;
    bool IsChainLocked() const;
    int GetBlocksToMaturity() const;

    bool AcceptToMemoryPool(const CAmount& nAbsurdFee, CValidationState& state);
    bool hashUnset() const { return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); }
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }

    const uint256& GetHash() const { return tx->GetHash(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //!< time received by this node
    unsigned int nTimeSmart;
    /**
     * From me flag is set to 1 for transactions that were created by the wallet
     * on this bitcoin node, and set to 0 for transactions that were created
     * externally and came in through the network or sendrawtransaction RPC.
     */
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //!< position in ordered transaction list
    std::unordered_set<uint32_t> changes; //!< positions of changes in vout

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(const CWallet* pwalletIn, CTransactionRef arg) : CMerkleTx(std::move(arg))
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
        changes.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        constexpr uint32_t FLAG_WITH_CHANGES = 0x00000001;

        if (ser_action.ForRead())
            Init(NULL);

        char fSpent = false;
        uint32_t flags = 0;

        if (!ser_action.ForRead())
        {
            flags = FLAG_WITH_CHANGES;

            mapValue["fromaccount"] = strFromAccount;
            mapValue["flags"] = strprintf("0x%x", flags);

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //!< Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;

            auto it = mapValue.find("flags");
            if (it != mapValue.end()) {
                flags = static_cast<uint32_t>(std::strtoul(it->second.c_str(), nullptr, 0));
            }
        }

        if (flags & FLAG_WITH_CHANGES) {
            READWRITE(changes);
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
        mapValue.erase("flags");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fImmatureCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache=true, bool fExcludeLocked = false) const;
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAnonymizedCredit(bool fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    // True if only scriptSigs are different
    bool IsEquivalentTo(const CWalletTx& tx) const;

    bool InMempool() const;
    bool InStempool() const;
    bool IsTrusted() const;

    bool IsChange(uint32_t out) const;
    bool IsChange(const CTxOut& out) const;

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    bool RelayWalletTransaction(CConnman* connman);

    std::set<uint256> GetConflicts() const;
};




class COutput
{
public:
    const CWalletTx *tx;
    int i;
    int nDepth;
    bool fSpendable;
    bool fSolvable;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn, bool fSolvableIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn; fSolvable = fSolvableIn;
    }

    std::string ToString() const;
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires=0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};

/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos; //!< position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(s.GetType(), s.GetVersion());
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), s.GetType(), s.GetVersion());
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

class LelantusJoinSplitBuilder;


/**Open unlock wallet window**/
//static boost::signals2::signal<void (CWallet *wallet)> UnlockWallet;
extern boost::signals2::signal<void (CWallet *wallet)> UnlockWallet;

/**
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    friend class CSparkWallet;

    static std::atomic<bool> fFlushThreadRunning;

    /**
     * Select a set of coins such that nValueRet >= nTargetValue and at least
     * all coins from coinControl are selected; Never select unconfirmed coins
     * if they are not ours
     */
    bool SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl *coinControl = NULL, bool fForUseInInstantSend = true) const;

    CWalletDB *pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions;

    mutable bool fAnonymizableTallyCached;
    mutable std::vector<CompactTallyItem> vecAnonymizableTallyCached;
    mutable bool fAnonymizableTallyCachedNonDenom;
    mutable std::vector<CompactTallyItem> vecAnonymizableTallyCachedNonDenom;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    std::set<COutPoint> setWalletUTXO;

    /* Mark a transaction (and its in-wallet descendants) as conflicting with a particular block. */
    void MarkConflicted(const uint256& hashBlock, const uint256& hashTx);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

    /* the HD chain data model (external chain counters) */
    CHDChain hdChain;
    MnemonicContainer mnemonicContainer;

    bool fFileBacked;

    std::set<int64_t> setKeyPool;

    std::map<CKeyID, int64_t> m_pool_key_to_index;

    int64_t nTimeFirstKey;

    std::shared_ptr<bip47::CWallet> bip47wallet;

    /**
     * Private version of AddWatchOnly method which does not accept a
     * timestamp, and which will reset the wallet's nTimeFirstKey value to 1 if
     * the watch key did not previously have a timestamp associated with it.
     * Because this is an inherited virtual method, it is accessible despite
     * being marked private, but it is marked private anyway to encourage use
     * of the other AddWatchOnly which accepts a timestamp and sets
     * nTimeFirstKey more intelligently for more efficient rescans.
     */
    bool AddWatchOnly(const CScript& dest) override;

public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

    const std::string strWalletFile;

    void LoadKeyPool(int nIndex, const CKeyPool &keypool)
    {
        setKeyPool.insert(nIndex);

        m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;
        // If no metadata exists yet, create a default with the pool key's
        // creation time. Note that this may be overwritten by actually
        // stored metadata for that key later, which is fine.
        CKeyID keyid = keypool.vchPubKey.GetID();
        if (mapKeyMetadata.count(keyid) == 0)
            mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
    }

    // Map from Key ID (for regular keys) or Script ID (for watch-only keys) to
    // key metadata.
    std::map<CTxDestination, CKeyMetadata> mapKeyMetadata;
    //znode
    int64_t nKeysLeftSinceAutoBackup;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    std::unique_ptr<CHDMintWallet> zwallet;

    std::unique_ptr<CSparkWallet> sparkWallet;

    std::atomic<bool> fUnlockRequested;

    CWallet()
    {
        SetNull();
    }

    CWallet(const std::string& strWalletFileIn) : strWalletFile(strWalletFileIn)
    {
        SetNull();
        fFileBacked = true;
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        nTimeFirstKey = 0;
        fBroadcastTransactions = false;
        fAnonymizableTallyCached = false;
        fAnonymizableTallyCachedNonDenom = false;
        vecAnonymizableTallyCached.clear();
        vecAnonymizableTallyCachedNonDenom.clear();
        zwallet = NULL;
        bip47wallet.reset();
    }

    std::map<uint256, CWalletTx> mapWallet;
    std::list<CAccountingEntry> laccentries;
    bool EraseFromWallet(uint256 hash);
    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered;

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;
    std::map<std::string, CAddressBookData> mapSparkAddressBook;
    std::map<std::string, CAddressBookData> mapRAPAddressBook;
    std::multimap<std::string, std::string> mapCustomKeyValues;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { AssertLockHeld(cs_wallet); return nWalletMaxVersion >= wf; }

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = NULL, bool fIncludeZeroValue=false, bool fForUseInInstantSend = false) const;

    void AvailableCoinsForLMint(std::vector<std::pair<CAmount, std::vector<COutput>>>& valueAndUTXO, const CCoinControl *coinControl) const;

    bool IsHDSeedAvailable() { return !hdChain.masterKeyID.IsNull(); }

    /**
     * Shuffle and select coins until nTargetValue is reached while avoiding
     * small change; This method is stochastic for some inputs and upon
     * completion the coin set and corresponding actual target value is
     * assembled
     */
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, uint64_t nMaxAncestors, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, bool fForUseInInstantSend = false) const;

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(const COutPoint& output);
    void UnlockCoin(const COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);
    void ListProTxCoins(std::vector<COutPoint>& vOutpts);

    bool HasMasternode();

    // znode
    /// Get 1000 FIRO output and keys which can be used for the Znode
    bool GetZnodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash = "", std::string strOutputIndex = "");
    /// Extract txin information and keys from output
    bool GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet);

    CPubKey GetKeyFromKeypath(uint32_t nChange, uint32_t nChild, CKey& secret);
    /**
     * keystore implementation
     * Generate a new key
     */
    CPubKey GenerateNewKey(uint32_t nChange=0, bool fWriteChain=true);
    void DeriveNewChildKey(CKeyMetadata& metadata, CKey& secret);
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey) override;
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CTxDestination& pubKey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) { AssertLockHeld(cs_wallet); nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }
    void UpdateTimeFirstKey(int64_t nCreateTime);

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) override;
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript) override;
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    bool AddDestData(const std::string &dest, const std::string &key, const std::string &value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination &dest, const std::string &key);
    bool EraseDestData(const std::string &dest, const std::string &key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    bool LoadDestData(const std::string &dest, const std::string &key, const std::string &value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest, int64_t nCreateTime);
    bool RemoveWatchOnly(const CScript &dest) override;
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    //! Holds a timestamp at which point the wallet is scheduled (externally) to be relocked. Caller must arrange for actual relocking to occur via Lock().
    int64_t nRelockTime;

    bool Unlock(const SecureString& strWalletPassphrase, const bool& fFirstUnlock=false);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void RequestUnlock();
    bool WaitForUnlock();

    void GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const;

    /**
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);
    DBErrors ReorderTransactions();
    bool AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment = "");
    bool GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew = false);

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose=true);
    bool LoadToWallet(const CWalletTx& wtxIn);
    void SyncTransaction(const CTransaction& tx, const CBlockIndex *pindex, int posInBlock) override;
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate);
    CBlockIndex* ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false, bool fRecoverMnemonic = false);
    CBlockIndex* GetBlockByDate(CBlockIndex* pindexStart, const std::string& dateStr);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) override;
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime, CConnman* connman);
    CAmount GetBalance(bool fExcludeLocked = false) const;
    std::pair<CAmount, CAmount> GetPrivateBalance() const;
    std::pair<CAmount, CAmount> GetPrivateBalance(size_t &confirmed, size_t &unconfirmed) const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;
    CAmount GetLegacyBalance(const isminefilter& filter, int minDepth, const std::string* account, bool fAddLocked = false) const;

    static std::vector<CRecipient> CreateSigmaMintRecipients(
        std::vector<sigma::PrivateCoin>& coins,
        std::vector<CHDMint>& vDMints);

    static CRecipient CreateLelantusMintRecipient(
        lelantus::PrivateCoin& coin,
        CHDMint& vDMint,
        bool generate = true);

    static int GetRequiredCoinCountForAmount(
        const CAmount& required,
        const std::vector<sigma::CoinDenomination>& denominations);

    static CAmount SelectMintCoinsForAmount(
        const CAmount& required,
        const std::vector<sigma::CoinDenomination>& denominations,
        std::vector<sigma::CoinDenomination>& coinsOut);

    static CAmount SelectSpendCoinsForAmount(
        const CAmount& required,
        const std::list<CSigmaEntry>& coinsIn,
        std::vector<CSigmaEntry>& coinsOut);

    // Returns a list of unspent and verified coins, I.E. coins which are ready
    // to be spent.
    std::list<CSigmaEntry> GetAvailableCoins(const CCoinControl *coinControl = NULL, bool includeUnsafe = false, bool forEstimation = false) const;

    std::list<CLelantusEntry> GetAvailableLelantusCoins(const CCoinControl *coinControl = NULL, bool includeUnsafe = false, bool forEstimation = false) const;

    // Returns the list of pairs of coins and meta data for that coin,
    std::list<CSparkMintMeta> GetAvailableSparkCoins(const CCoinControl *coinControl = NULL) const;

    std::vector<unsigned char> EncryptMintAmount(uint64_t amount, const secp_primitives::GroupElement& pubcoin) const;

    bool DecryptMintAmount(const std::vector<unsigned char>& encryptedValue, const secp_primitives::GroupElement& pubcoin, uint64_t& amount) const;


    /** \brief Selects coins to spend, and coins to re-mint based on the required amount to spend, provided by the user. As the lower denomination now is 0.1 firo, user's request will be rounded up to the nearest 0.1. This difference between the user's requested value, and the actually spent value will be left to the miners as a fee.
     * \param[in] required Required amount to spend.
     * \param[out] coinsToSpend_out Coins which user needs to spend.
     * \param[out] coinsToMint_out Coins which will be re-minted by the user to get the change back.
     * \returns true, if it was possible to spend exactly required(rounded up to 0.1 firo) amount using coins we have.
     */
    bool GetCoinsToSpend(
        CAmount required,
        std::vector<CSigmaEntry>& coinsToSpend_out,
        std::vector<sigma::CoinDenomination>& coinsToMint_out,
        std::list<CSigmaEntry>& coins,
        const size_t coinsLimit = SIZE_MAX,
        const CAmount amountLimit = MAX_MONEY,
        const CCoinControl *coinControl = NULL) const;

    bool GetCoinsToJoinSplit(
            CAmount required,
            std::vector<CLelantusEntry>& coinsToSpend_out,
            CAmount& changeToMint,
            std::list<CLelantusEntry> coins,
            const size_t coinsToSpendLimit = SIZE_MAX,
            const CAmount amountToSpendLimit = MAX_MONEY,
            const CCoinControl *coinControl = NULL) const;

    std::vector<unsigned char> ProvePrivateTxOwn(const uint256& txid, const std::string& message) const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, bool overrideEstimatedFeeRate, const CFeeRate& specificFeeRate, int& nChangePosInOut, std::string& strFailReason, bool includeWatching, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, bool keepReserveKey = true, const CTxDestination& destChange = CNoDestination());

    /**
     * Create a new transaction paying the recipients with a set of coins
     * selected by SelectCoins(); Also create the change output, when needed
     * @note passing nChangePosInOut as -1 will result in setting a random position
     */
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl *coinControl = NULL, bool sign = true, int nExtraPayloadSize = 0, bool fUseInstantSend=false);

    /**
     * Add Mint and Spend functions
     */
    void ListAvailableSigmaMintCoins(std::vector <COutput> &vCoins, bool fOnlyConfirmed) const;
    void ListAvailableLelantusMintCoins(std::vector<COutput> &vCoins, bool fOnlyConfirmed) const;

    bool CreateMintTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl *coinControl = NULL, bool sign = true);
    bool CreateMintTransaction(CScript pubCoin, int64_t nValue,
                                       CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, std::string& strFailReason, const CCoinControl *coinControl=NULL);
    bool CreateLelantusMintTransactions(CAmount valueToMint, std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
                                        CAmount& nAllFeeRet, std::vector<CHDMint>& dMints,
                                        std::list<CReserveKey>& reservekeys, int& nChangePosInOut,
                                        std::string& strFailReason, const CCoinControl *coinControl, bool autoMintAll = false, bool sign = true);

    std::pair<CAmount, CAmount> GetSparkBalance();
    bool IsSparkAddressMine(const std::string& address);

    bool CreateSparkMintTransactions(
        const std::vector<spark::MintedCoinData>& outputs,
        std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
        CAmount& nAllFeeRet,
        std::list<CReserveKey>& reservekeys,
        int& nChangePosInOut,
        bool subtractFeeFromAmount,
        std::string& strFailReason,
        bool fSplit,
        const CCoinControl *coinControl,
        bool autoMintAll = false);

    CWalletTx CreateSigmaSpendTransaction(
        const std::vector<CRecipient>& recipients,
        CAmount& fee,
        std::vector<CSigmaEntry>& selected,
        std::vector<CHDMint>& changes,
        bool& fChangeAddedToFee,
        const CCoinControl *coinControl = NULL);

    CWalletTx CreateLelantusJoinSplitTransaction(
        const std::vector<CRecipient>& recipients,
        CAmount& fee,
        const std::vector<CAmount>& newMints,
        std::vector<CLelantusEntry>& spendCoins,
        std::vector<CSigmaEntry>& sigmaSpendCoins,
        std::vector<CHDMint>& mintCoins,
        const CCoinControl *coinControl = NULL,
        std::function<void(CTxOut & , LelantusJoinSplitBuilder const &)> modifier = nullptr);

    bool CommitSigmaTransaction(CWalletTx& wtxNew, std::vector<CSigmaEntry>& selectedCoins, std::vector<CHDMint>& changes);
    bool CommitLelantusTransaction(CWalletTx& wtxNew, std::vector<CLelantusEntry>& spendCoins, std::vector<CSigmaEntry>& sigmaSpendCoins, std::vector<CHDMint>& mintCoins);
    std::string SendMoney(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, bool fAskFee=false);
    std::string SendMoneyToDestination(const CTxDestination &address, int64_t nValue, CWalletTx& wtxNew, bool fAskFee=false);

    std::string MintAndStoreSigma(
        const std::vector<CRecipient>& vecSend,
        const std::vector<sigma::PrivateCoin>& privCoins,
        std::vector<CHDMint> vDMints,
        CWalletTx &wtxNew,
        bool fAskFee=false,
        const CCoinControl *coinControl = NULL);

    std::string MintAndStoreLelantus(
            const CAmount& value,
            std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
            std::vector<CHDMint>& mints,
            bool autoMintAll = false,
            bool fAskFee = false,
            const CCoinControl *coinControl = NULL);

    std::string MintAndStoreSpark(
            const std::vector<spark::MintedCoinData>& outputs,
            std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
            bool subtractFeeFromAmount,
            bool fSplit,
            bool autoMintAll = false,
            bool fAskFee = false,
            const CCoinControl *coinControl = NULL);

    CWalletTx CreateSparkSpendTransaction(
            const std::vector<CRecipient>& recipients,
            const std::vector<std::pair<spark::OutputCoinData, bool>>&  privateRecipients,
            CAmount &fee,
            const CCoinControl *coinControl = NULL);

    CWalletTx CreateSparkNameTransaction(
            CSparkNameTxData &sparkNameData,
            CAmount sparkNameFee,
            CAmount &txFee,
            const CCoinControl *coinControl = NULL);

    CWalletTx SpendAndStoreSpark(
            const std::vector<CRecipient>& recipients,
            const std::vector<std::pair<spark::OutputCoinData, bool>>&  privateRecipients,
            CAmount &fee,
            const CCoinControl *coinControl = NULL);

    bool LelantusToSpark(std::string& strFailReason);

    std::vector<CSigmaEntry> SpendSigma(const std::vector<CRecipient>& recipients, CWalletTx& result);
    std::vector<CSigmaEntry> SpendSigma(const std::vector<CRecipient>& recipients, CWalletTx& result, CAmount& fee);

    std::vector<CLelantusEntry> JoinSplitLelantus(const std::vector<CRecipient>& recipients, const std::vector<CAmount>& newMints, CWalletTx& result,  const CCoinControl *coinControl = NULL);

    std::pair<CAmount, unsigned int> EstimateJoinSplitFee(CAmount required, bool subtractFeeFromAmount, std::list<CSigmaEntry> sigmaCoins, std::list<CLelantusEntry> coins, const CCoinControl *coinControl);

    bool GetMint(const uint256& hashSerial, CSigmaEntry& sigmaEntry, bool forEstimation = false) const;

    bool GetMint(const uint256& hashSerial, CLelantusEntry& mint, bool forEstimation = false) const;

    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state);


    bool CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason);
    bool ConvertList(std::vector<CTxIn> vecTxIn, std::vector<CAmount>& vecAmounts);

    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries);
    bool AddAccountingEntry(const CAccountingEntry&);
    bool AddAccountingEntry(const CAccountingEntry&, CWalletDB *pwalletdb);
    template <typename ContainerType>
    bool DummySignTx(CMutableTransaction &txNew, const ContainerType &coins);

    static CFeeRate minTxFee;
    static CFeeRate fallbackFee;
    /**
     * Estimate the minimum fee considering user set parameters
     * and the required fee
     */
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);
    /**
     * Estimate the minimum fee considering required fee and targetFee or if 0
     * then fee estimation for nConfirmTarget
     */
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool, CAmount targetFee);
    /**
     * Return the minimum required fee taking into account the
     * floating relay fee and user set minimum transaction fee
     */
    static CAmount GetRequiredFee(unsigned int nTxBytes);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex, const CPubKey& pubkey);
    bool GetKeyFromPool(CPubKey &key);
    int64_t GetOldestKeyPoolTime();
    /**
     * Marks all keys in the keypool up to and including reserve_key as used.
     */
    void MarkReserveKeysAsUsed(int64_t keypool_id);
    const std::map<CKeyID, int64_t>& GetAllReserveKeys() const { return m_pool_key_to_index; }

    spark::FullViewKey GetSparkViewKey();
    std::string GetSparkViewKeyStr();

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    std::set<CTxDestination> GetAccountAddresses(const std::string& strAccount) const;

    isminetype IsMine(const CTxIn& txin, const CTransaction& tx) const;
    /**
     * Returns amount of debit if the input matches the
     * filter, otherwise returns 0
     */
    CAmount GetDebit(const CTxIn& txin, const CTransaction&tx, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const;
    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const;
    bool IsChange(const uint256& tx, const CTxOut& txout) const;
    CAmount GetChange(const uint256& tx, const CTxOut& txout) const;
    bool IsMine(const CTransaction& tx) const;
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const;
    /** Returns whether all of the inputs match the filter */
    bool IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetChange(const CTransaction& tx) const;
    void SetBestChain(const CBlockLocator& loc) override;

    DBErrors LoadWallet(bool& fFirstRunRet);
    void AutoLockMasternodeCollaterals();
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);

    // Remove all CSigmaEntry and CHDMint objects from WalletDB.
    DBErrors ZapSigmaMints();
    // Remove all Lelantus HDMint objects from WalletDB
    DBErrors ZapLelantusMints();
    // Remove all Spark Mint objects from WalletDB
    DBErrors ZapSparkMints();

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);
    bool SetSparkAddressBook(const std::string& address, const std::string& strName, const std::string& purpose);
    bool SetRAPAddressBook(const std::string& address, const std::string& strName, const std::string& purpose);
    bool DelAddressBook(const CTxDestination& address);
    bool DelAddressBook(const std::string& address);

    bool UpdatedTransaction(const uint256 &hashTx) override;
    const std::string& GetAccountName(const CScript& scriptPubKey) const;

    void Inventory(const uint256 &hash) override
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    void GetScriptForMining(boost::shared_ptr<CReserveScript> &script) override;
    void ResetRequestCount(const uint256 &hash) override
    {
        LOCK(cs_wallet);
        mapRequestCount[hash] = 0;
    };

    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size();
    }

    bool SetDefaultKey(const CPubKey &vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { LOCK(cs_wallet); return nWalletVersion; }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Check if a given transaction has any of its outputs spent by another transaction in the wallet
    bool HasWalletSpend(const uint256& txid) const;

    //! Flush wallet (bitdb flush)
    void Flush(bool shutdown=false);

    //! Verify the wallet database and perform salvage if required
    static bool Verify();

    /**
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyAddressBookChanged;

    boost::signals2::signal<void (CWallet *wallet, const std::string
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifySparkAddressBookChanged;

    boost::signals2::signal<void (CWallet *wallet, const std::string
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyRAPAddressBookChanged;
            
    /**
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx,
            ChangeType status)> NotifyTransactionChanged;
    /**
     * sigma/lelantus entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const std::string &pubCoin, const std::string &isUsed, ChangeType status)> NotifyZerocoinChanged;


    /** Show progress e.g. for rescan */
    boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Payment code added */
    boost::signals2::signal<void (bip47::CPaymentCodeDescription)> NotifyPcodeCreated;

    /** Payment code labeled */
    boost::signals2::signal<void (std::string pcode, std::string label, bool removed)> NotifyPcodeLabeled;

    /** Unlock required (for example for adding a privkey to the wallet),  */
    boost::signals2::signal<void (int receiverAccountNum, CBlockIndex* pBlockIndex)> NotifyBip47KeysChanged;

    /** IS-lock received */
    boost::signals2::signal<void ()> NotifyISLockReceived;

    /** ChainLock received */
    boost::signals2::signal<void (int height)> NotifyChainLockReceived;

    /** Inquire whether this wallet broadcasts transactions. */
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }
    /** Set whether this wallet broadcasts transactions. */
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(const uint256& hashTx);

    /** Mark a transaction as replaced by another transaction (e.g., BIP 125). */
    bool MarkReplaced(const uint256& originalHash, const uint256& newHash);

    /* Returns the wallets help message */
    static std::string GetWalletHelpString(bool showDebug);

    /* Initializes the wallet, returns a new CWallet instance or a null pointer in case of an error */
    static CWallet* CreateWalletFromFile(const std::string walletFile);
    static bool InitLoadWallet();

    /**
     * Wallet post-init setup
     * Gives the wallet a chance to register repetitive tasks and complete post-init tasks
     */
    void postInitProcess(boost::thread_group& threadGroup);

    /* Wallets parameter interaction */
    static bool ParameterInteraction();

    bool BackupWallet(const std::string& strDest);

    /* Set the HD chain model (chain child index counters) */
    bool SetHDChain(const CHDChain& chain, bool memonly, bool& upgradeChain, bool genNewKeyPool = true);
    bool SetHDChain(const CHDChain& chain, bool memonly) { bool upgradeChain = DEFAULT_UPGRADE_CHAIN; return SetHDChain(chain, memonly, upgradeChain); }
    const CHDChain& GetHDChain() { return hdChain; }

    bool SetMnemonicContainer(const MnemonicContainer& mnContainer, bool memonly);
    const MnemonicContainer& GetMnemonicContainer() { return mnemonicContainer; }

    bool EncryptMnemonicContainer(const CKeyingMaterial& vMasterKeyIn);
    bool DecryptMnemonicContainer(MnemonicContainer& mnContainer);

    void GenerateNewMnemonic();

    /* Returns true if HD is enabled */
    bool IsHDEnabled();

    /* Generates a new HD master key (will not be activated) */
    CPubKey GenerateNewHDMasterKey();

    /* Set the current HD master key (will reset the chain child index counters) */
    bool SetHDMasterKey(const CPubKey& key, const int cHDChainVersion=CHDChain().CURRENT_VERSION);

    /**************************************************************************/
    /* bip47 */
    /* Generates and strores a new payment code for receiving*/
    bip47::CPaymentCode GeneratePcode(std::string const & label);

    /*Prepares and sends a notification tx using Lelantus facilities*/
    CWalletTx PrepareAndSendNotificationTx(bip47::CPaymentCode const & theirPcode);

    /* Lists all receiving pcodes as tuples of (pcode, label, notification address) */
    std::vector<bip47::CPaymentCodeDescription> ListPcodes();

    /* Creates a payment channel for their payment code. */
    bip47::CPaymentChannel & SetupPchannel(bip47::CPaymentCode const & theirPcode);

    /* Stores the notification tx id into the wallet database */
    void SetNotificationTxId(bip47::CPaymentCode const & theirPcode, uint256 const & txid);

    /* Returns next unused address for their payment code. Throws if no payment channel was setup */
    CBitcoinAddress GetTheirNextAddress(bip47::CPaymentCode const & theirPcode) const;

    /* Returns and stores a next unused address for their payment code. Throws if no payment channel was setup */
    CBitcoinAddress GenerateTheirNextAddress(bip47::CPaymentCode const & theirPcode);

    /*Loads previously stored bip47 accounts */
    void LoadBip47Wallet();

    std::shared_ptr<bip47::CWallet const>  GetBip47Wallet() const;

    boost::optional<bip47::CPaymentCodeDescription> FindPcode(bip47::CPaymentCode const & pcode) const;
    boost::optional<bip47::CPaymentCodeDescription> FindPcode(CBitcoinAddress const & address) const;

    /*Marks address as used for a receiving bip47 account. Returns the account if found*/
    bip47::CAccountReceiver const * AddressUsed(CBitcoinAddress const & address);

    /*Checks if this is a BIP47 transaction and handles it. May send an unlock request if wallet is locked.*/
    void HandleBip47Transaction(CWalletTx const & wtx);

    // Checks if this is a spark transaction and handles it.
    void HandleSparkTransaction(CWalletTx const & wtx);

    /*Attaches a new label to a sending payment code.*/
    void LabelSendingPcode(bip47::CPaymentCode const & pcode, std::string const & label, bool remove = false);
    std::string GetSendingPcodeLabel(bip47::CPaymentCode const & pcode) const;

    /*Relabels an existing receiving payment code*/
    void LabelReceivingPcode(bip47::CPaymentCode const & pcode, std::string const & label);

    /*Sets used address number for a sending or receiving payment channel*/
    size_t SetUsedAddressNumber(bip47::CPaymentCode const & pcode, size_t number);

    void NotifyTransactionLock(const CTransaction &tx) override;
    void NotifyChainLock(const CBlockIndex* pindexChainLock) override;

    bool validateAddress(const std::string& address);
    bool validateSparkAddress(const std::string& address) const;
    bool GetSparkOutputTx(const CScript& scriptPubKey, CSparkOutputTx& output) const;
};

/** A key allocated from the key pool. */
class CReserveKey : public CReserveScript
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey &pubkey);
    void KeepKey();
    void KeepScript() override { KeepKey(); }
};


/**
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};

bool CompSigmaHeight(const CSigmaEntry& a, const CSigmaEntry& b);
bool CompSigmaID(const CSigmaEntry& a, const CSigmaEntry& b);
void ShutdownWallet();

// Helper for producing a bunch of max-sized low-S signatures (eg 72 bytes)
// ContainerType is meant to hold pair<CWalletTx *, int>, and be iterable
// so that each entry corresponds to each vIn, in order.
template <typename ContainerType>
bool CWallet::DummySignTx(CMutableTransaction &txNew, const ContainerType &coins)
{
    // Fill in dummy signatures for fee calculation.
    int nIn = 0;
    for (const auto& coin : coins)
    {
        const CScript& scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
        SignatureData sigdata;

        if (!ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata))
        {
            return false;
        } else {
            UpdateTransaction(txNew, nIn, sigdata);
        }

        nIn++;
    }
    return true;
}

CWalletTx PrepareAndSendNotificationTx(CWallet* pwallet, bip47::CPaymentCode const & theirPcode);

#endif // BITCOIN_WALLET_WALLET_H
