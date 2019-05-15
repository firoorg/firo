// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETDB_H
#define BITCOIN_WALLET_WALLETDB_H
//#define loop                for (;;)

#include "amount.h"
#include "primitives/transaction.h"
#include "primitives/zerocoin.h"
#include "hdmint/hdmint.h"
#include "wallet/db.h"
#include "key.h"

#include "../secp256k1/include/GroupElement.h"
#include "../secp256k1/include/Scalar.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include "libzerocoin/Zerocoin.h"

static const bool DEFAULT_FLUSHWALLET = true;

class CAccount;
class CAccountingEntry;
struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
class uint160;
class uint256;
class CZerocoinEntry;
class CZerocoinEntryV3;
class CZerocoinSpendEntry;
class CZerocoinSpendEntryV3;

/** Error statuses for the wallet database */
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter; // VERSION_BASIC
    vector<uint32_t> nExternalChainCounters; // VERSION_WITH_BIP44: vector index corresponds to account value
    CKeyID masterKeyID; //!< master key hash160

    static const int VERSION_BASIC = 1;
    static const int VERSION_WITH_BIP44 = 10;
    static const int N_CHANGES = 3; // standard = 0/1, mint = 2
    int nVersion;

    CHDChain() { SetNull(); }
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        if(nVersion == VERSION_BASIC){
            READWRITE(nExternalChainCounter);
        }else{
            READWRITE(nExternalChainCounters);
        }
        READWRITE(masterKeyID);
    }

    void SetNull()
    {
        nVersion = CHDChain::VERSION_WITH_BIP44;
        masterKeyID.SetNull();
        for(int index=0;index<N_CHANGES;index++){
            nExternalChainCounters.push_back(0);
        }
    }
};

class CKeyMetadata
{
public:
    static const int VERSION_BASIC=1;
    static const int VERSION_WITH_HDDATA=10;
    static const int CURRENT_VERSION=VERSION_WITH_HDDATA;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    std::string hdKeypath; //optional HD/bip32 keypath
    int64_t nChild; // HD/bip32 keypath child counter
    CKeyID hdMasterKeyID; //id of the HD masterkey used to derive this key

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nCreateTime);
        if (this->nVersion >= VERSION_WITH_HDDATA)
        {
            READWRITE(hdKeypath);
            READWRITE(hdMasterKeyID);
        }
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        hdKeypath.clear();
        nChild = 0;
        hdMasterKeyID.SetNull();
    }
};

/** Access to the wallet database */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool fFlushOnClose = true) : CDB(strFilename, pszMode, fFlushOnClose)
    {
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript &script);
    bool EraseWatchOnly(const CScript &script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// This writes directly to the database, and will not update the CWallet's cached accounting entries!
    /// Use wallet.AddAccountingEntry instead, to write *and* update its caches.
    bool WriteAccountingEntry_Backend(const CAccountingEntry& acentry);
    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string &address, const std::string &key, const std::string &value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string &address, const std::string &key);

    CAmount GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    bool WriteZerocoinEntry(const CZerocoinEntry& zerocoin);
    bool WriteZerocoinEntry(const CZerocoinEntryV3& zerocoin);
    bool ReadZerocoinEntry(const Bignum& pub, CZerocoinEntry& entry);
    bool ReadZerocoinEntry(const secp_primitives::GroupElement& pub, CZerocoinEntryV3& entry);
    bool HasZerocoinEntry(const Bignum& pub);
    bool HasZerocoinEntry(const secp_primitives::GroupElement& pub);
    bool EraseZerocoinEntry(const CZerocoinEntry& zerocoin);
    bool EraseZerocoinEntry(const CZerocoinEntryV3& zerocoin);
    void ListPubCoin(std::list<CZerocoinEntry>& listPubCoin);
    void ListPubCoinV3(std::list<CZerocoinEntryV3>& listPubCoin);
    void ListCoinSpendSerial(std::list<CZerocoinSpendEntry>& listCoinSpendSerial);
    void ListCoinSpendSerial(std::list<CZerocoinSpendEntryV3>& listCoinSpendSerial);
    bool WriteCoinSpendSerialEntry(const CZerocoinSpendEntry& zerocoinSpend);
    bool WriteCoinSpendSerialEntry(const CZerocoinSpendEntryV3& zerocoinSpend);
    bool HasCoinSpendSerialEntry(const Bignum& serial);
    bool HasCoinSpendSerialEntry(const secp_primitives::Scalar& serial);
    bool EraseCoinSpendSerialEntry(const CZerocoinSpendEntry& zerocoinSpend);
    bool EraseCoinSpendSerialEntry(const CZerocoinSpendEntryV3& zerocoinSpend);
    bool WriteZerocoinAccumulator(libzerocoin::Accumulator accumulator, libzerocoin::CoinDenomination denomination, int pubcoinid);
    bool ReadZerocoinAccumulator(libzerocoin::Accumulator& accumulator, libzerocoin::CoinDenomination denomination, int pubcoinid);
    // bool EraseZerocoinAccumulator(libzerocoin::Accumulator& accumulator, libzerocoin::CoinDenomination denomination, int pubcoinid);

    bool ReadCalculatedZCBlock(int& height);
    bool WriteCalculatedZCBlock(int height);

    DBErrors ReorderTransactions(CWallet* pwallet);
    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTx(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(CWallet* pwallet, std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);
    static bool Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, const std::string& filename);

    bool ReadCurrentSeedHash(uint160& hashSeed);
    bool WriteCurrentSeedHash(const uint160& hashSeed);

    bool ReadZerocoinCount(uint32_t& nCount);
    bool WriteZerocoinCount(const uint32_t& nCount);

    bool ArchiveMintOrphan(const CZerocoinEntry& zerocoin);
    bool ArchiveDeterministicOrphan(const CHDMint& dMint);
    bool UnarchiveZerocoinMint(const uint256& hashPubcoin, CZerocoinEntryV3& zerocoin);
    bool UnarchiveHDMint(const uint256& hashPubcoin, CHDMint& dMint);

    bool WriteHDMint(const CHDMint& dMint);
    bool ReadHDMint(const uint256& hashPubcoin, CHDMint& dMint);

     std::list<CHDMint> ListHDMints();

     std::map<uint160, std::vector<pair<CKeyID, uint32_t> > > MapMintPool();
    bool WriteMintPoolPair(const uint160& hashMasterSeed, const CKeyID& seedId, const uint32_t& nCount);

    //! write the hdchain model (external chain child index counter)
    bool WriteHDChain(const CHDChain& chain);

    //! erase the hdchain model (Used for removal of old versions)
    bool EraseHDChain(const CHDChain& chain);

private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);

    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry);
};

void ThreadFlushWalletDB(const std::string& strFile);
bool AutoBackupWallet (CWallet* wallet, std::string strWalletFile, std::string& strBackupWarning, std::string& strBackupError);

#endif // BITCOIN_WALLET_WALLETDB_H
