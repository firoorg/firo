// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"

#include "chainparams.h"
#include "hash.h"
#include "pow.h"
#include "uint256.h"
#include "validation.h"
#include "consensus/consensus.h"
#include "base58.h"

#include <stdint.h>

#include <boost/thread.hpp>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

static const char DB_COIN = 'C';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_ADDRESSINDEX = 'a';
static const char DB_ADDRESSUNSPENTINDEX = 'u';
static const char DB_TIMESTAMPINDEX = 's';
static const char DB_SPENTINDEX = 'p';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';
static const char DB_TOTAL_SUPPLY = 'S';

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent())
                batch.Erase(entry);
            else
                batch.Write(entry, it->second.coin);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (!hashBlock.IsNull())
        batch.Write(DB_BEST_BLOCK, hashBlock);

    bool ret = db.WriteBatch(batch);
    LogPrint("coindb", "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper*>(&db)->NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(std::make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value) {
    return Read(std::make_pair(DB_SPENTINDEX, key), value);
}

bool CBlockTreeDB::UpdateSpentIndex(const std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<CSpentIndexKey,CSpentIndexValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(std::make_pair(DB_SPENTINDEX, it->first));
        } else {
            batch.Write(std::make_pair(DB_SPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue > >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first));
        } else {
            batch.Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressUnspentIndex(uint160 addressHash, AddressType type,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash) {
            CAddressUnspentValue nValue;
            if (pcursor->GetValue(nValue)) {
                unspentOutputs.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        batch.Write(std::make_pair(DB_ADDRESSINDEX, it->first), it->second);
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
    batch.Erase(std::make_pair(DB_ADDRESSINDEX, it->first));
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressIndex(uint160 addressHash, AddressType type,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    if (start > 0 && end > 0) {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorHeightKey(type, addressHash, start)));
    } else {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash)));
    }

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressIndexKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSINDEX && key.second.hashBytes == addressHash && key.second.type == type) {
            if (end > 0 && key.second.blockHeight > end) {
                break;
            }
            CAmount nValue;
            if (pcursor->GetValue(nValue)) {
                addressIndex.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address index value");
            }
        } else {
            break;
        }
    }

    return true;
}

size_t CBlockTreeDB::findAddressNumWBalance() {
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->SeekToFirst();
    std::unordered_map<uint160, CAmount> addrMap;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressIndexKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSINDEX && (key.second.type == AddressType::payToPubKeyHash || key.second.type == AddressType::payToExchangeAddress)) {
            CAmount nValue;
            // Retrieve the associated value
            if (pcursor->GetValue(nValue) && nValue != 0) { // Only process non-zero values
                addrMap[key.second.hashBytes] += nValue; // Accumulate balance for the address
            }
        }
        pcursor->Next();
    }

    size_t counter = 0;
    for (auto& itr : addrMap) {
        if (itr.second > 0) {
            ++counter;
        }
    }

    return counter;
}

bool CBlockTreeDB::WriteTimestampIndex(const CTimestampIndexKey &timestampIndex) {
    CDBBatch batch(*this);
    batch.Write(std::make_pair(DB_TIMESTAMPINDEX, timestampIndex), 0);
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadTimestampIndex(const unsigned int &high, const unsigned int &low, std::vector<uint256> &hashes) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_TIMESTAMPINDEX, CTimestampIndexIteratorKey(low)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, CTimestampIndexKey> key;
        if (pcursor->GetKey(key) && key.first == DB_TIMESTAMPINDEX && key.second.timestamp <= high) {
            hashes.push_back(key.second.blockHash);
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(boost::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    const auto &consensusParams = Params().GetConsensus();
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex

    // We need to check PoW for the last N blocks. To do so we can't just save a pointer to the last block and go back 
    // from it because of possible forks. This multimap is used to track the most recent blocks (by height) saved in 
    // the block index on disk
    std::multimap<int, CBlockIndex*> lastNBlocks;
    // lowest height of all the elements in lastNBlocks
    int firstInLastNBlocksHeight = 0;

    bool fCheckPoWForAllBlocks = GetBoolArg("-fullblockindexcheck", DEFAULT_FULL_BLOCKINDEX_CHECK);
    int64_t nBlocksToCheck = GetArg("-numberofblockstocheckonstartup", DEFAULT_BLOCKINDEX_NUMBER_OF_BLOCKS_TO_CHECK);

#ifdef __linux__
    struct sysinfo sysInfo;

    if (sysinfo(&sysInfo) == 0 && sysInfo.freeram < 2ul*1024ul*1024ul*1024ul)
        nBlocksToCheck = DEFAULT_BLOCKINDEX_LOWMEM_NUMBER_OF_BLOCKS_TO_CHECK;
#endif

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                // Firo - ProgPoW
                if (diskindex.nTime > ZC_GENESIS_BLOCK_TIME && diskindex.nTime >= consensusParams.nPPSwitchTime) {
                    pindexNew->nNonce64 = diskindex.nNonce64;
                    pindexNew->mix_hash = diskindex.mix_hash;
                }

                // Firo - MTP
                else if (diskindex.nTime > ZC_GENESIS_BLOCK_TIME && diskindex.nTime >= consensusParams.nMTPSwitchTime) {
                    pindexNew->nVersionMTP = diskindex.nVersionMTP;
                    pindexNew->mtpHashValue = diskindex.mtpHashValue;
                    pindexNew->reserved[0] = diskindex.reserved[0];
                    pindexNew->reserved[1] = diskindex.reserved[1];
                }

                pindexNew->sigmaMintedPubCoins   = diskindex.sigmaMintedPubCoins;
                pindexNew->sigmaSpentSerials     = diskindex.sigmaSpentSerials;

                pindexNew->lelantusMintedPubCoins   = diskindex.lelantusMintedPubCoins;
                pindexNew->lelantusMintData         = diskindex.lelantusMintData;
                pindexNew->lelantusSpentSerials     = diskindex.lelantusSpentSerials;
                pindexNew->anonymitySetHash         = diskindex.anonymitySetHash;

                pindexNew->sparkMintedCoins   = diskindex.sparkMintedCoins;
                pindexNew->sparkSetHash       = diskindex.sparkSetHash;
                pindexNew->spentLTags         = diskindex.spentLTags;
                pindexNew->sparkTxHashContext = diskindex.sparkTxHashContext;
                pindexNew->ltagTxhash         = diskindex.ltagTxhash;

                pindexNew->activeDisablingSporks = diskindex.activeDisablingSporks;

                pindexNew->addedSparkNames = diskindex.addedSparkNames;
                pindexNew->removedSparkNames = diskindex.removedSparkNames;

                if (fCheckPoWForAllBlocks) {
                    if (!CheckProofOfWork(pindexNew->GetBlockPoWHash(), pindexNew->nBits, consensusParams))
                        return error("LoadBlockIndex(): CheckProofOfWork failed: %s", pindexNew->ToString());
                }
                else {
                    if (pindexNew->nHeight >= firstInLastNBlocksHeight) {
                        lastNBlocks.insert(std::pair<int, CBlockIndex*>(pindexNew->nHeight, pindexNew));
                        if (cmp::greater(lastNBlocks.size(), nBlocksToCheck)) {
                            // pop the first element from the map
                            auto firstElement = lastNBlocks.begin();
                            auto elementToPop = firstElement++;
                            lastNBlocks.erase(elementToPop);
                            firstInLastNBlocksHeight = firstElement->first;
                        }
                    }
                }

                pcursor->Next();
            } else {
                return error("LoadBlockIndex() : failed to read value");
            }
        } else {
            break;
        }
    }

    if (!fCheckPoWForAllBlocks) {
        // delayed check for all the blocks
        for (const auto &blockIndex: lastNBlocks) {
            if (!CheckProofOfWork(blockIndex.second->GetBlockPoWHash(), blockIndex.second->nBits, consensusParams))
                return error("LoadBlockIndex(): CheckProofOfWork failed: %s", blockIndex.second->ToString());
        }
    }

    return true;
}

int CBlockTreeDB::GetBlockIndexVersion()
{
    // Get random block index entry, check its version. The only reason for these functions to exist
    // is to check if the index is from previous version and needs to be rebuilt. Comparison of ANY
    // record version to threshold value would be enough to decide if reindex is needed.

    return GetBlockIndexVersion(uint256());
}

int CBlockTreeDB::GetBlockIndexVersion(uint256 const & blockHash)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, blockHash));
    uint256 const zero_hash = uint256();
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            if (blockHash != zero_hash && key.second != blockHash) {
                pcursor->Next();
                continue;
            }
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex))
                return diskindex.nDiskBlockVersion;
        } else {
	    break;
        }
    }
    return -1;
}


bool CBlockTreeDB::AddTotalSupply(CAmount const & supply)
{
    CAmount current = 0;
    Read(DB_TOTAL_SUPPLY, current);
    current += supply;
    return Write(DB_TOTAL_SUPPLY, current);
}

bool CBlockTreeDB::ReadTotalSupply(CAmount & supply)
{
    CAmount current = 0;
    if(Read(DB_TOTAL_SUPPLY, current)) {
        supply = current;
        return true;
    }
    return false;
}

/******************************************************************************/

CDbIndexHelper::CDbIndexHelper(bool addressIndex_, bool spentIndex_)
{
    if (addressIndex_) {
        addressIndex.reset(AddressIndex());
        addressUnspentIndex.reset(AddressUnspentIndex());
    }

    if (spentIndex_)
        spentIndex.reset(SpentIndex());
}

namespace {

using AddressIndexPtr = boost::optional<CDbIndexHelper::AddressIndex>;
using AddressUnspentIndexPtr = boost::optional<CDbIndexHelper::AddressUnspentIndex>;
using SpentIndexPtr = boost::optional<CDbIndexHelper::SpentIndex>;

std::pair<AddressType, uint160> classifyAddress(txnouttype type, std::vector<std::vector<unsigned char> > const & addresses)
{
    std::pair<AddressType, uint160> result(AddressType::unknown, uint160());
    if(type == TX_PUBKEY) {
        result.first = AddressType::payToPubKeyHash;
        CPubKey pubKey(addresses.front().begin(), addresses.front().end());
        result.second = pubKey.GetID();
    } else if(type == TX_SCRIPTHASH) {
        result.first = AddressType::payToScriptHash;
        result.second = uint160(std::vector<unsigned char>(addresses.front().begin(), addresses.front().end()));
    } else if(type == TX_PUBKEYHASH) {
        result.first = AddressType::payToPubKeyHash;
        result.second = uint160(std::vector<unsigned char>(addresses.front().begin(), addresses.front().end()));
    } else if(type == TX_EXCHANGEADDRESS) {
        result.first = AddressType::payToExchangeAddress;
        result.second = uint160(std::vector<unsigned char>(addresses.front().begin(), addresses.front().end()));
    }
    return result;
}

void handleInput(CTxIn const & input, size_t inputNo, uint256 const & txHash, int height, int txNumber, CCoinsViewCache const & view,
        AddressIndexPtr & addressIndex, AddressUnspentIndexPtr & addressUnspentIndex, SpentIndexPtr & spentIndex)
{
    const Coin coin = view.AccessCoin(input.prevout);
    const CTxOut &prevout = coin.out;

    txnouttype type;
    std::vector<std::vector<unsigned char> > addresses;

    if(!Solver(prevout.scriptPubKey, type, addresses)) {
        LogPrint("CDbIndexHelper", "Encountered an unsoluble script in block:%i, txHash: %s, inputNo: %i\n", height, txHash.ToString().c_str(), inputNo);
        return;
    }

    std::pair<AddressType, uint160> addrType = classifyAddress(type, addresses);

    if(addrType.first == AddressType::unknown) {
        return;
    }

    if (addressIndex) {
        addressIndex->push_back(std::make_pair(CAddressIndexKey(addrType.first, addrType.second, height, txNumber, txHash, inputNo, true), prevout.nValue * -1));
        addressUnspentIndex->push_back(std::make_pair(CAddressUnspentKey(addrType.first, addrType.second, input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
    }

    if (spentIndex)
        spentIndex->push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(txHash, inputNo, height, prevout.nValue, addrType.first, addrType.second)));
}

void handleRemint(CTxIn const & input, uint256 const & txHash, int height, int txNumber, CAmount nValue,
        AddressIndexPtr & addressIndex, AddressUnspentIndexPtr & addressUnspentIndex, SpentIndexPtr & spentIndex)
{
    if(!input.IsZerocoinRemint())
        return;

    if (addressIndex) {
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::zerocoinRemint, uint160(), height, txNumber, txHash, 0, true), nValue * -1));
        addressUnspentIndex->push_back(std::make_pair(CAddressUnspentKey(AddressType::zerocoinRemint, uint160(), input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
    }

    if (spentIndex)
        spentIndex->push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(txHash, 0, height, nValue, AddressType::zerocoinRemint, uint160())));
}


template <class Iterator>
void handleZerocoinSpend(Iterator const begin, Iterator const end, uint256 const & txHash, int height, int txNumber, CCoinsViewCache const & view,
        AddressIndexPtr & addressIndex, CTransaction const & tx)
{
    if(!addressIndex)
        return;

    CAmount spendAmount = 0;
    for(Iterator iter = begin; iter != end; ++iter)
        spendAmount += iter->nValue;

    AddressType addrType = AddressType::lelantusJSplit;
    if(tx.IsZerocoinSpend()) {
        addrType = AddressType::zerocoinSpend;
    } else if(tx.IsSigmaSpend()){
        addrType = AddressType::sigmaSpend;
    }  else if(tx.IsSparkSpend()){
        addrType = AddressType::sparkSpend;

        if (height >= Params().GetConsensus().nSparkNamesStartBlock) {
            spark::SpendTransaction spendTx(spark::Params::get_default());
            CSparkNameTxData sparkNameData;
            size_t pos;
            CSparkNameManager* sparkNameManager = CSparkNameManager::GetInstance();

            if (sparkNameManager->ParseSparkNameTxData(tx, spendTx, sparkNameData, pos))
                addressIndex->push_back(std::make_pair(
                    CAddressIndexKey(AddressType::sparkName, uint160(), height, txNumber, txHash, 0, true), -spendAmount));
        }
    }

    addressIndex->push_back(std::make_pair(CAddressIndexKey(addrType, uint160(), height, txNumber, txHash, 0, true), -spendAmount));
}

void handleOutput(const CTxOut &out, size_t outNo, uint256 const & txHash, int height, int txNumber, CCoinsViewCache const & view, bool coinbase,
        AddressIndexPtr & addressIndex, AddressUnspentIndexPtr & addressUnspentIndex, SpentIndexPtr & spentIndex)
{
    if(!addressIndex)
        return;

    if(out.scriptPubKey.IsZerocoinMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::zerocoinMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    if(out.scriptPubKey.IsSigmaMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::sigmaMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    if(out.scriptPubKey.IsLelantusMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::lelantusMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    if(out.scriptPubKey.IsLelantusJMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::lelantusJMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    if(out.scriptPubKey.IsSparkMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::sparkMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    if(out.scriptPubKey.IsSparkSMint())
        addressIndex->push_back(std::make_pair(CAddressIndexKey(AddressType::sparksMint, uint160(), height, txNumber, txHash, outNo, false), out.nValue));

    txnouttype type;
    std::vector<std::vector<unsigned char> > addresses;

    if(!Solver(out.scriptPubKey, type, addresses)) {
        LogPrint("CDbIndexHelper", "Encountered an unsoluble script in block:%i, txHash: %s, outNo: %i\n", height, txHash.ToString().c_str(), outNo);
        return;
    }

    std::pair<AddressType, uint160> addrType = classifyAddress(type, addresses);

    if(addrType.first == AddressType::unknown) {
        return;
    }

    addressIndex->push_back(std::make_pair(CAddressIndexKey(addrType.first, addrType.second, height, txNumber, txHash, outNo, false), out.nValue));
    addressUnspentIndex->push_back(std::make_pair(CAddressUnspentKey(addrType.first, addrType.second, txHash, outNo), CAddressUnspentValue(out.nValue, out.scriptPubKey, height)));
}
}


void CDbIndexHelper::ConnectTransaction(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view)
{
    size_t no = 0;
    if(!tx.IsCoinBase() && !tx.HasNoRegularInputs()) {
        for (CTxIn const & input : tx.vin) {
            handleInput(input, no++, tx.GetHash(), height, txNumber, view, addressIndex, addressUnspentIndex, spentIndex);
        }
    }

    if(tx.IsZerocoinRemint()) {
        CAmount remintValue = 0;
        for (CTxOut const & out : tx.vout) {
            remintValue += out.nValue;
        }
        if (tx.vin.size() != 1) {
           error("A Zerocoin to Sigma remint tx shoud have just 1 input");
           return;
        }
        handleRemint(tx.vin[0], tx.GetHash(), height, txNumber, remintValue, addressIndex, addressUnspentIndex, spentIndex);
    }

    if(tx.IsZerocoinSpend() || tx.IsSigmaSpend() || tx.IsLelantusJoinSplit() || tx.IsSparkSpend())
        handleZerocoinSpend(tx.vout.begin(), tx.vout.end(), tx.GetHash(), height, txNumber, view, addressIndex, tx);

    no = 0;
    bool const txIsCoinBase = tx.IsCoinBase();
    for (CTxOut const & out : tx.vout) {
        handleOutput(out, no++, tx.GetHash(), height, txNumber, view, txIsCoinBase, addressIndex, addressUnspentIndex, spentIndex);
    }
}


void CDbIndexHelper::DisconnectTransactionInputs(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view)
{
    size_t pAddressBegin{0}, pUnspentBegin{0}, pSpentBegin{0};

    if(addressIndex){
        pAddressBegin = addressIndex->size();
        pUnspentBegin = addressUnspentIndex->size();
    }

    if(spentIndex)
        pSpentBegin = spentIndex->size();

    if(tx.IsZerocoinRemint()) {
        CAmount remintValue = 0;
        for (CTxOut const & out : tx.vout) {
            remintValue += out.nValue;
        }
        if (tx.vin.size() != 1) {
           error("A Zerocoin to Sigma remint tx shoud have just 1 input");
           return;
        }
        handleRemint(tx.vin[0], tx.GetHash(), height, txNumber, remintValue, addressIndex, addressUnspentIndex, spentIndex);
    }

    size_t no = 0;

    if(!tx.IsCoinBase() && !tx.HasNoRegularInputs())
        for (CTxIn const & input : tx.vin) {
            handleInput(input, no++, tx.GetHash(), height, txNumber, view, addressIndex, addressUnspentIndex, spentIndex);
        }

    if(addressIndex){
        std::reverse(addressIndex->begin() + pAddressBegin, addressIndex->end());
        std::reverse(addressUnspentIndex->begin() + pUnspentBegin, addressUnspentIndex->end());

        for(AddressUnspentIndex::iterator iter = addressUnspentIndex->begin(); iter != addressUnspentIndex->end(); ++iter)
            iter->second = CAddressUnspentValue();
    }

    if(spentIndex)
        std::reverse(spentIndex->begin() + pSpentBegin, spentIndex->end());
}

void CDbIndexHelper::DisconnectTransactionOutputs(CTransaction const & tx, int height, int txNumber, CCoinsViewCache const & view)
{
    if(tx.IsZerocoinSpend() || tx.IsSigmaSpend() || tx.IsLelantusJoinSplit() || tx.IsSparkSpend())
        handleZerocoinSpend(tx.vout.begin(), tx.vout.end(), tx.GetHash(), height, txNumber, view, addressIndex, tx);

    size_t no = 0;
    bool const txIsCoinBase = tx.IsCoinBase();
    for (CTxOut const & out : tx.vout) {
        handleOutput(out, no++, tx.GetHash(), height, txNumber, view, txIsCoinBase, addressIndex, addressUnspentIndex, spentIndex);
    }

    if(addressIndex)
    {
        std::reverse(addressIndex->begin(), addressIndex->end());
        std::reverse(addressUnspentIndex->begin(), addressUnspentIndex->end());
    }

    if(spentIndex)
        std::reverse(spentIndex->begin(), spentIndex->end());
}

CDbIndexHelper::AddressIndex const & CDbIndexHelper::getAddressIndex() const
{
    return *addressIndex;
}


CDbIndexHelper::AddressUnspentIndex const & CDbIndexHelper::getAddressUnspentIndex() const
{
    return *addressUnspentIndex;
}


CDbIndexHelper::SpentIndex const & CDbIndexHelper::getSpentIndex() const
{
    return *spentIndex;
}

namespace {

//! Legacy class to deserialize pre-pertxout database entries without reindex.
class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! empty constructor
    CCoins() : fCoinBase(false), vout(0), nHeight(0) { }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        // version
        int nVersionDummy = 0;
        ::Unserialize(s, VARINT(nVersionDummy));
        // header code
        ::Unserialize(s, VARINT(nCode));
        fCoinBase = nCode & 1;
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
    }
};

}

/** Upgrade the database from older formats.
 *
 * Currently implemented: from the per-tx utxo model (0.8..0.14.x) to per-txout.
 */
bool CCoinsViewDB::Upgrade() {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    pcursor->Seek(std::make_pair(DB_COINS, uint256()));
    if (!pcursor->Valid()) {
        return true;
    }

    LogPrintf("Upgrading database...\n");
    size_t batch_size = 1 << 24;
    CDBBatch batch(db);
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<unsigned char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_COINS) {
            CCoins old_coins;
            if (!pcursor->GetValue(old_coins)) {
                return error("%s: cannot parse CCoins record", __func__);
            }
            COutPoint outpoint(key.second, 0);
            for (size_t i = 0; i < old_coins.vout.size(); ++i) {
                if (!old_coins.vout[i].IsNull() && !old_coins.vout[i].scriptPubKey.IsUnspendable()) {
                    Coin newcoin(std::move(old_coins.vout[i]), old_coins.nHeight, old_coins.fCoinBase);
                    outpoint.n = i;
                    CoinEntry entry(&outpoint);
                    batch.Write(entry, newcoin);
                }
            }
            batch.Erase(key);
            if (batch.SizeEstimate() > batch_size) {
                db.WriteBatch(batch);
                batch.Clear();
            }
            pcursor->Next();
        } else {
            break;
        }
    }
    db.WriteBatch(batch);
    return true;
}
