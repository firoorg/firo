// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include "coins.h"
#include "dbwrapper.h"
#include "chain.h"
#include "spentindex.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <boost/function.hpp>

class CBlockIndex;
class CCoinsViewDBCursor;
class uint256;

//! Compensate for extra memory peak (x1.5-x1.9) at flush time.
static constexpr int DB_PEAK_USAGE_FACTOR = 2;
//! Factor to estimate actual memory usage.
static constexpr int EVO_DB_USAGE_FACTOR = 30;
//! No need to periodic flush if at least this much space still available.
static constexpr int MAX_BLOCK_COINSDB_USAGE = 10 * DB_PEAK_USAGE_FACTOR;
//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 450;
//! max. -dbcache (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache (MiB)
static const int64_t nMinDbCache = 4;
//! Max memory allocated to block tree DB specific cache, if no -txindex (MiB)
static const int64_t nMaxBlockDBCache = 2;
//! Max memory allocated to block tree DB specific cache, if -txindex (MiB)
// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
static const int64_t nMaxBlockDBAndTxIndexCache = 1024;
//! Max memory allocated to coin DB specific cache (MiB)
static const int64_t nMaxCoinsDBCache = 8;

//! By default don't check block index PoW on client startup
static const bool DEFAULT_FULL_BLOCKINDEX_CHECK = false;
//! If not doing full check of block index, check only N of the latest blocks
static const int DEFAULT_BLOCKINDEX_NUMBER_OF_BLOCKS_TO_CHECK = 10000;
//! Check fewer blocks if low on memory
static const int DEFAULT_BLOCKINDEX_LOWMEM_NUMBER_OF_BLOCKS_TO_CHECK = 50;

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CDiskBlockPos*)this);
        READWRITE(VARINT(nTxOffset));
    }

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB : public CCoinsView
{
protected:
    CDBWrapper db;
public:
    CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) override;
    CCoinsViewCursor *Cursor() const override;

    //! Attempt to update from an older database format. Returns whether an error occurred.
    bool Upgrade();
    size_t EstimateSize() const override;
};

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    ~CCoinsViewDBCursor() {}

    bool GetKey(COutPoint &key) const;
    bool GetValue(Coin &coin) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();

private:
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256 &hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CDBWrapper
{
public:
    CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CBlockTreeDB(const CBlockTreeDB&);
    void operator=(const CBlockTreeDB&);
public:
    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &fileinfo);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool &fReindex);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &list);
    bool ReadSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value);
    bool UpdateSpentIndex(const std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> >&vect);
    bool UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue > >&vect);
    bool ReadAddressUnspentIndex(uint160 addressHash, AddressType type,
                                 std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &vect);
    bool WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount> > &vect);
    bool EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount> > &vect);
    bool ReadAddressIndex(uint160 addressHash, AddressType type,
                          std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                          int start = 0, int end = 0);
    size_t findAddressNumWBalance();

    bool WriteTimestampIndex(const CTimestampIndexKey &timestampIndex);
    bool ReadTimestampIndex(const unsigned int &high, const unsigned int &low, std::vector<uint256> &vect);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts(boost::function<CBlockIndex*(const uint256&)> insertBlockIndex);
    int GetBlockIndexVersion();
    int GetBlockIndexVersion(uint256 const & blockHash);
    bool AddTotalSupply(CAmount const & supply);
    bool ReadTotalSupply(CAmount & supply);
};


/**
 * This class was introduced as the logic for address and tx indices became too intricate.
 *
 * @param addressIndex, spentIndex - true if to update the corresponding index
 *
 * It is undefined behavior if the helper was created with addressIndex == false
 * and getAddressIndex was called later (same for spentIndex and unspentIndex).
 */
class CDbIndexHelper : boost::noncopyable
{
public:
    CDbIndexHelper(bool addressIndex, bool spentIndex);

    void ConnectTransaction(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view);
    void DisconnectTransactionInputs(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view);
    void DisconnectTransactionOutputs(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view);

    using AddressIndex = std::vector<std::pair<CAddressIndexKey, CAmount> >;
    using AddressUnspentIndex = std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >;
    using SpentIndex = std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> >;

    AddressIndex const & getAddressIndex() const;
    AddressUnspentIndex const & getAddressUnspentIndex() const;
    SpentIndex const & getSpentIndex() const;

private:
    boost::optional<AddressIndex> addressIndex;
    boost::optional<AddressUnspentIndex> addressUnspentIndex;
    boost::optional<SpentIndex> spentIndex;
};

#endif // BITCOIN_TXDB_H
