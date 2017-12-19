// Copyright (c) 2014-2017 The Bitcoin Core developers
// Copyright (c) 2017 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coinsbyscript.h"
#include "hash.h"
#include "main.h"
#include "rpc/server.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"

#include <assert.h>

#include <boost/thread.hpp>

static const char DB_COINS_BYSCRIPT = 'd';
static const char DB_FLAG = 'F';
static const char DB_BEST_BLOCK = 'B';


bool fUTXOIndex = false;
CCoinsByScriptViewDB *pCoinsByScriptViewDB = nullptr;
CCoinsByScriptView *pCoinsByScriptView = nullptr;



static size_t CalculateSize(coinsbyscriptmap_t& map)
{
    size_t result = 0;
    for (const auto& it : map) {
        if (!it.second.empty()) {
            for (size_t i = 0; i < it.second.size(); i++) {
                result += sizeof(COutPoint);
            }
        }
    }
    return result;
}

CCoinsByScriptView::CCoinsByScriptView(CCoinsByScriptViewDB* viewIn) 
    : base(viewIn) 
{ 
    uint256 bestBlockHash;
    if (base->ReadBestBlock(bestBlockHash))
    {
        SetBestBlock(bestBlockHash);
    }
}

bool CCoinsByScriptView::GetCoinsByScript(const CScript& scriptIn, unspentcoins_t& coinsOut) 
{

    const scripthash_t key = GetScriptHash(scriptIn);
    if (cacheCoinsByScript.count(key)) 
    {
        coinsOut = cacheCoinsByScript[key];
        return true;
    }
    if (base->GetCoinsByScriptHash(key, coinsOut))
    {
        cacheCoinsByScript[key] = coinsOut;
        return true;
    }
    return false;
}

unspentcoins_t &CCoinsByScriptView::GetCoinsByScript(const CScript& script, bool fRequireExisting) 
{
    const scripthash_t key = GetScriptHash(script);
    coinsbyscriptmap_t::iterator it = cacheCoinsByScript.find(key);
    if (it == cacheCoinsByScript.end())
    {
        unspentcoins_t tmp;
        bool foundInDb = base->GetCoinsByScriptHash(key, tmp);

        if(foundInDb || !fRequireExisting)
            it = cacheCoinsByScript.emplace_hint(it, key, tmp);
    }


    assert(it != cacheCoinsByScript.end());
    return it->second;
}

uint256 CCoinsByScriptView::GetBestBlock() const 
{
    return hashBlock;
}

void CCoinsByScriptView::SetBestBlock(const uint256& hashBlockIn) 
{
    hashBlock = hashBlockIn;
}

bool CCoinsByScriptView::Flush() 
{
    bool fOk = base->BatchWrite(this, hashBlock);
    return fOk;
}

bool CCoinsByScriptViewDBCursor::GetKey(scripthash_t& keyOut) const
{
    // Return cached key
    if (keyTmp.first == DB_COINS_BYSCRIPT)
    {
        keyOut = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsByScriptViewDBCursor::GetValue(unspentcoins_t& coinsOut) const
{
    return pcursor->GetValue(coinsOut);
}

unsigned int CCoinsByScriptViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsByScriptViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COINS_BYSCRIPT;
}

void CCoinsByScriptViewDBCursor::Next()
{
    pcursor->Next();
    if (!pcursor->Valid() || !pcursor->GetKey(keyTmp))
    {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    }
}


CCoinsByScriptViewDB::CCoinsByScriptViewDB(size_t nCacheSize, bool fMemory, bool fWipe) 
    : db(GetDataDir() / "coinsbyscript", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsByScriptViewDB::GetCoinsByScriptHash(const scripthash_t& scriptHash, unspentcoins_t& coins) const
{
    return db.Read(std::make_pair(DB_COINS_BYSCRIPT, scriptHash), coins);
}

bool CCoinsByScriptViewDB::BatchWrite(CCoinsByScriptView* pcoinsViewByScriptIn, const uint256& hashBlock) 
{
    CDBBatch batch(db);
    size_t count = 0;
    for(const auto& it : pcoinsViewByScriptIn->cacheCoinsByScript)
    {
        if (it.second.empty())
            batch.Erase(std::make_pair(DB_COINS_BYSCRIPT, it.first));
        else
            batch.Write(std::make_pair(DB_COINS_BYSCRIPT, it.first), it.second);
        count++;
    }

    LogPrintf("CCoinsByScriptViewDB::BatchWrite:  pcoinsViewByScriptIn->cacheCoinsByScript size in bytes: %u", CalculateSize(pcoinsViewByScriptIn->cacheCoinsByScript));
    pcoinsViewByScriptIn->cacheCoinsByScript.clear();

    if (!hashBlock.IsNull())
    {
        batch.Write(DB_BEST_BLOCK, hashBlock);
    }

    LogPrintf("Committing %u coin address indexes to coin database...\n", (unsigned int)count);
    return db.WriteBatch(batch);
}

bool CCoinsByScriptViewDB::WriteFlag(const std::string& name, bool fValue) 
{
    return db.Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CCoinsByScriptViewDB::ReadFlag(const std::string& name, bool &fValue)
{
    char ch;
    if (!db.Read(std::make_pair(DB_FLAG, name), ch))
    {
        return false;
    }
    fValue = ch == '1';
    return true;
}

bool CCoinsByScriptViewDB::ReadBestBlock(uint256& bestBlock)
{
    return db.Read(DB_BEST_BLOCK, bestBlock);
}

CCoinsByScriptViewDBCursor* CCoinsByScriptViewDB::Cursor() const
{
    CCoinsByScriptViewDBCursor *i = new CCoinsByScriptViewDBCursor(const_cast<CDBWrapper*>(&db)->NewIterator());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COINS_BYSCRIPT);
    if (!i->pcursor->Valid())
    {
        // If db empty then set this cursor invalid
        i->keyTmp.first = 0;
    }
    else
    {
        // Cache key of first record
        i->pcursor->GetKey(i->keyTmp);
    }
    return i;
}


bool CCoinsByScriptViewDB::DeleteAllCoinsByScript()
{
    std::unique_ptr<CCoinsByScriptViewDBCursor> pcursor(Cursor());

    std::vector<scripthash_t> v;
    int64_t i = 0;
    while (pcursor->Valid()) 
    {
        boost::this_thread::interruption_point();
        try 
        {
            scripthash_t hash;
            if (!pcursor->GetKey(hash))
                break;
            v.push_back(hash);
            if (v.size() >= 10000)
            {
                i += v.size();
                CDBBatch batch(db);
                for(auto& av: v)
                {
                    const scripthash_t& _hash = av;
                    batch.Erase(make_pair(DB_COINS_BYSCRIPT, _hash)); // delete
                }
                db.WriteBatch(batch);
                v.clear();
            }

            pcursor->Next();
        } 
        catch (std::exception &e) 
        {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }
    if (!v.empty())
    {
        i += v.size();
        CDBBatch batch(db);
        for(auto& av: v)
        {
            const scripthash_t& hash = av;
            batch.Erase(make_pair(DB_COINS_BYSCRIPT, hash)); // delete
        }
        db.WriteBatch(batch);
    }
    db.Write(DB_BEST_BLOCK, uint256());
    if (i > 0)
        LogPrintf("Address index with %d addresses successfully deleted.\n", i);

    return true;
}

bool CCoinsByScriptViewDB::GenerateAllCoinsByScript(CCoinsViewDB* coinsIn)
{
    LogPrintf("Building address index for -utxoindex. Be patient...\n");
    int64_t nTxCount = coinsIn->CountCoins();

    std::unique_ptr<CCoinsViewCursor> pcursor(coinsIn->Cursor());

    coinsbyscriptmap_t mapCoinsByScript;
    int64_t i = 0;
    int64_t progress = 0;
    while (pcursor->Valid()) 
    {
        boost::this_thread::interruption_point();
        try 
        {
            if (progress % 1000 == 0 && nTxCount > 0)
                uiInterface.ShowProgress(_("Building address index..."), (int)(((double)progress / (double)nTxCount) * (double)100));
            progress++;

            uint256 txhash;
            CCoins coins;
            if (!pcursor->GetKey(txhash) || !pcursor->GetValue(coins))
            {
                break;
            }

            for (size_t j = 0; j < coins.vout.size(); j++)
            {
                if (coins.vout[j].IsNull() || coins.vout[j].scriptPubKey.IsUnspendable())
                    continue;

                const scripthash_t key = GetScriptHash(coins.vout[j].scriptPubKey);
                if (!mapCoinsByScript.count(key))
                {
                    unspentcoins_t coins;
                    GetCoinsByScriptHash(key, coins);
                    mapCoinsByScript.insert(make_pair(key, coins));
                }
                mapCoinsByScript[key].insert(COutPoint(txhash, (uint32_t)j));
                i++;
            }

            if (mapCoinsByScript.size() >= 10000)
            {
                
                LogPrintf("CCoinsByScriptViewDB::GenerateAllCoinsByScript: mapCoinsByScript.size() >= 10000; size in bytes: %u", CalculateSize(mapCoinsByScript));
                CDBBatch batch(db);
                for(const auto& it : mapCoinsByScript) {
                    if (it.second.empty())
                        batch.Erase(make_pair(DB_COINS_BYSCRIPT, it.first));
                    else
                        batch.Write(make_pair(DB_COINS_BYSCRIPT, it.first), it.second);
                }
                db.WriteBatch(batch);
                mapCoinsByScript.clear();
            }

            pcursor->Next();
        } 
        catch (std::exception &e) 
        {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }
    if (!mapCoinsByScript.empty())
    {
       CDBBatch batch(db);
       for (const auto& it : mapCoinsByScript) {
           if (it.second.empty())
               batch.Erase(make_pair(DB_COINS_BYSCRIPT, it.first));
           else
               batch.Write(make_pair(DB_COINS_BYSCRIPT, it.first), it.second);
       }
       db.WriteBatch(batch);
    }
    uint256 bb = coinsIn->GetBestBlock();
    if (!bb.IsNull())
    {
        db.Write(DB_BEST_BLOCK, bb);
    }
    LogPrintf("Address index with %d outputs successfully built.\n", i);
    return true;
}

scripthash_t GetScriptHash(const CScript& in)
{
    return uint160(Hash160(in.begin(), in.end()));
}

UniValue ValueFromUnspentCoins(const unspentcoins_t& unspentCoins, const int64_t nMaxOutputs)
{
    UniValue jObjResult(UniValue::VOBJ);

    UniValue jArrOutpoints(UniValue::VARR);

    CAmount balance = 0;
    int64_t nOutputs = 0;
    for (const COutPoint &outpoint : unspentCoins)
    {
        CCoins coins;
        if (!pcoinsTip->GetCoins(outpoint.hash, coins))
            continue;

        if (outpoint.n < coins.vout.size() && !coins.vout[outpoint.n].IsNull() && !coins.vout[outpoint.n].scriptPubKey.IsUnspendable() )
        {
            CAmount coinValue = coins.vout[outpoint.n].nValue;
            balance += coinValue;

            if (nOutputs < nMaxOutputs)
            {
                UniValue jOutpoint(UniValue::VOBJ);
                jOutpoint.push_back(Pair("value", ValueFromAmount(coinValue)));
                jOutpoint.push_back(Pair("txid", outpoint.hash.GetHex()));
                jOutpoint.push_back(Pair("vout", (int)outpoint.n));

                jArrOutpoints.push_back(jOutpoint);
            }
            nOutputs++;
        }
    }
    jObjResult.push_back(Pair("outputs", jArrOutpoints));
    jObjResult.push_back(Pair("balance", ValueFromAmount(balance)));

    return jObjResult;
}


static void CoinsByScriptIndex_UpdateTx(const CTxOut& txout, const COutPoint& outpoint, bool fInsert)
{
    if (!txout.IsNull() && !txout.scriptPubKey.IsUnspendable())
    {
        unspentcoins_t &coins = pCoinsByScriptView->GetCoinsByScript(txout.scriptPubKey, !fInsert);
        if (fInsert)
            coins.insert(outpoint);
        else
            coins.erase(outpoint);
    }
}

void CoinsByScriptIndex_UpdateBlock(const CBlock& block, CBlockUndo& blockundo, bool fBlockConnected)
{
    if (!fUTXOIndex)
        return;

    assert(block.vtx.size() > 0);

    if (block.vtx.size() < 1)
    {
        throw std::runtime_error(std::string(__func__) + "CoinsByScriptIndex_UpdateBlock failed - block.vtx.size() < 1");
    }

    if (fBlockConnected)
    {
        for (size_t i = 0; i < block.vtx.size(); i++)
        {
            const CTransaction& tx = block.vtx[i];
        
            if (i>0 && !tx.IsCoinBase() && !tx.IsZerocoinSpend())
            {
                for (size_t j = 0; j < tx.vin.size(); j++)
                {
                    const CTxIn& txin = tx.vin[j];
                    const CTxOut& txout = blockundo.vtxundo[i - 1].vprevout[j].txout;
                    CoinsByScriptIndex_UpdateTx(txout, txin.prevout, false);
                }
            }

            for (unsigned int j = 0; j < tx.vout.size(); j++)
            {
                CTxOut& txout = const_cast<CTxOut&>(tx.vout[j]);
                const COutPoint outpoint(tx.GetHash(), ((uint32_t)j));
                CoinsByScriptIndex_UpdateTx(txout, outpoint, true);
            }
        }
    }
    else
    {
        for (size_t i = block.vtx.size(); i--; )
        {
            const CTransaction &tx = block.vtx[i];

            if (i>0 && !tx.IsCoinBase() && !tx.IsZerocoinSpend())
            {
                for (size_t j = 0; j < tx.vin.size(); j++)
                {
                    const CTxIn& txin = tx.vin[j];
                    const CTxOut& txout = blockundo.vtxundo[i - 1].vprevout[j].txout;
                    CoinsByScriptIndex_UpdateTx(txout, txin.prevout, true);
                }
            }

            for (unsigned int j = 0; j < tx.vout.size(); j++)
            {
                CTxOut& txout = const_cast<CTxOut&>(tx.vout[j]);
                const COutPoint outpoint(tx.GetHash(), ((uint32_t)j));
                CoinsByScriptIndex_UpdateTx(txout, outpoint, false);
            }

        }
    }

    pCoinsByScriptView->SetBestBlock(block.GetHash());
}

bool CoinsByScriptIndex_Rebuild(std::string& error)
{
    if (!pCoinsByScriptViewDB->DeleteAllCoinsByScript())
    {
        error = _("Error deleting utxoindex");
        return false;
    }
    if (!pCoinsByScriptViewDB->GenerateAllCoinsByScript(GetCoinsViewDB()))
    {
        error = _("Error building utxoindex");
        return false;
    }
    return true;
}

bool CoinsByScriptIndex_Delete(std::string& error)
{
    if (!pCoinsByScriptViewDB->DeleteAllCoinsByScript())
    {
        error = _("Error deleting utxoindex");
        return false;
    }
    
    return true;
}