// Copyright (c) 2014-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coinsbyscript.h"
#include "txdb.h"
#include "hash.h"
#include "ui_interface.h"

#include <assert.h>

#include <boost/thread.hpp>

static const char DB_COINS_BYSCRIPT = 'd';
static const char DB_FLAG = 'F';
static const char DB_BEST_BLOCK = 'B';


bool fUTXOIndex = false;
CCoinsByScriptViewDB *pCoinsByScriptViewDB = NULL;
CCoinsByScriptView *pCoinsByScriptView = NULL;



CCoinsByScriptView::CCoinsByScriptView(CCoinsByScriptViewDB* viewIn) 
	: base(viewIn) 
{ 
	uint256 bestBlockHash;
	if (base->ReadBestBlock(bestBlockHash))
	{
		SetBestBlock(bestBlockHash);
	}
}

bool CCoinsByScriptView::GetCoinsByScript(const CScript &scriptIn, unspentcoins_t &coinsOut) 
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

unspentcoins_t &CCoinsByScriptView::GetCoinsByScript(const CScript &script, bool fRequireExisting) 
{

	const scripthash_t key = GetScriptHash(script);
	coinsbyscriptmap_t::iterator it = cacheCoinsByScript.find(key);
	if (it == cacheCoinsByScript.end())
	{
		unspentcoins_t tmp;
		bool foundInDb = base->GetCoinsByScriptHash(key, tmp);

		assert(foundInDb || !fRequireExisting);

		if(!fRequireExisting)
			it = cacheCoinsByScript.emplace_hint(it, key, tmp);
	}


    assert(it != cacheCoinsByScript.end());
    return it->second;
}

uint256 CCoinsByScriptView::GetBestBlock() const 
{
    return hashBlock;
}

void CCoinsByScriptView::SetBestBlock(const uint256 &hashBlockIn) 
{
    hashBlock = hashBlockIn;
}

bool CCoinsByScriptView::Flush() 
{
    bool fOk = base->BatchWrite(this, hashBlock);
    return fOk;
}

/*
coinsbyscriptmap_t::iterator CCoinsByScriptView::FetchCoinsByScript(const CScript &script, bool fRequireExisting)
{
const scripthash_t key = GetScriptHash(script);
coinsbyscriptmap_t::iterator it = cacheCoinsByScript.find(key);
if (it != cacheCoinsByScript.end())
{
return it;
}

unspentcoins_t tmp;
if (!base->GetCoinsByScriptHash(key, tmp))
{
if (fRequireExisting)
return cacheCoinsByScript.end();
}

return cacheCoinsByScript.emplace_hint(it, key, tmp);
}*/



bool CCoinsByScriptViewDBCursor::GetKey(scripthash_t &keyOut) const
{
	// Return cached key
	if (keyTmp.first == DB_COINS_BYSCRIPT)
	{
		keyOut = keyTmp.second;
		return true;
	}
	return false;
}

bool CCoinsByScriptViewDBCursor::GetValue(unspentcoins_t &coinsOut) const
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

bool CCoinsByScriptViewDB::GetCoinsByScriptHash(const scripthash_t &scriptHash, unspentcoins_t &coins) const
{
    return db.Read(std::make_pair(DB_COINS_BYSCRIPT, scriptHash), coins);
}

bool CCoinsByScriptViewDB::BatchWrite(CCoinsByScriptView* pcoinsViewByScriptIn, const uint256 &hashBlock) 
{
    CDBBatch batch(db);
    size_t count = 0;
    //for (coinsbyscriptmap_t::iterator it = pcoinsViewByScriptIn->cacheCoinsByScript.begin(); it != pcoinsViewByScriptIn->cacheCoinsByScript.end();) 
	for(const auto& it : pcoinsViewByScriptIn->cacheCoinsByScript)
	{
        if (it.second.empty())
            batch.Erase(std::make_pair(DB_COINS_BYSCRIPT, it.first));
        else
            batch.Write(std::make_pair(DB_COINS_BYSCRIPT, it.first), it.second);
        /*coinsbyscriptmap_t::iterator itOld = it++;
        pcoinsViewByScriptIn->cacheCoinsByScript.erase(itOld);*/
        count++;
    }
    pcoinsViewByScriptIn->cacheCoinsByScript.clear();

	if (!hashBlock.IsNull())
	{
		batch.Write(DB_BEST_BLOCK, hashBlock);
	}

    LogPrintf("Committing %u coin address indexes to coin database...\n", (unsigned int)count);
    return db.WriteBatch(batch);
}

bool CCoinsByScriptViewDB::WriteFlag(const std::string &name, bool fValue) 
{
    return db.Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CCoinsByScriptViewDB::ReadFlag(const std::string &name, bool &fValue)
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

CCoinsByScriptViewDBCursor *CCoinsByScriptViewDB::Cursor() const
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
                CDBBatch batch(db);
               // for (coinsbyscriptmap_t::iterator it = mapCoinsByScript.begin(); it != mapCoinsByScript.end();) {
				for(const auto& it : mapCoinsByScript) {
                    if (it.second.empty())
                        batch.Erase(make_pair(DB_COINS_BYSCRIPT, it.first));
                    else
                        batch.Write(make_pair(DB_COINS_BYSCRIPT, it.first), it.second);
            /*      coinsbyscriptmap_t::iterator itOld = it++;
                    mapCoinsByScript.erase(itOld);*/
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
		   /*      coinsbyscriptmap_t::iterator itOld = it++;
		   mapCoinsByScript.erase(itOld);*/
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

bool GetUTXOByScript_OnTheFly(CCoinsViewDB* coinsIn, const scripthash_t& pubScriptHash, CAmount& balanceOut)
{
	LogPrintf("Calculating unspent outputs on the fly(no index)\n");
	int64_t nTxCount = coinsIn->CountCoins();

	std::unique_ptr<CCoinsViewCursor> pcursor(coinsIn->Cursor());

	balanceOut = 0;

	int64_t txCount = 0;
	int64_t progress = 0;
	while (pcursor->Valid())
	{
		boost::this_thread::interruption_point();
		try
		{
			uint256 txhash;
			CCoins coins;
			if (!pcursor->GetKey(txhash) || !pcursor->GetValue(coins))
			{
				break;
			}

			for (unsigned int j = 0; j < coins.vout.size(); j++)
			{
				if (coins.vout[j].IsNull() || coins.vout[j].scriptPubKey.IsUnspendable())
					continue;

				const scripthash_t txoScriptHash = GetScriptHash(coins.vout[j].scriptPubKey);
				if(pubScriptHash == txoScriptHash)
				{
					balanceOut += coins.vout[j].nValue;
				}
				txCount++;
			}
			pcursor->Next();
		}
		catch (std::exception &e)
		{
			return error("%s : Deserialize or I/O error - %s", __func__, e.what());
		}
	}
	LogPrintf("Successfully calculated unspent outputs on the fly(no index) for %d transactions.\n", txCount);
	return true;
}


void CoinsByScriptIndex_UpdateTx(const CTxOut& txout, const COutPoint& outpoint, bool fInsert)
{
	//return;
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
	//return;
	if (!fUTXOIndex)
		return;

	assert(block.vtx.size() > 0);

	if (block.vtx.size() < 1)
	{
		throw std::runtime_error(std::string(__func__) + "CoinsByScriptIndex_UpdateBlock failed - block.vtx.size() < 1");
	}

	if (fBlockConnected)
	{
		for (unsigned int i = 0; i < block.vtx.size(); i++)
		{
			const CTransaction &tx = block.vtx[i];
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
		for (int i = block.vtx.size() - 1; i >= 0; i--)
		{
			if (i > 0)
			{
				const CTransaction &tx = block.vtx[i];
				for (unsigned int j = 0; j < tx.vin.size(); j++)
				{
					assert(blockundo.vtxundo[i - 1].vprevout.size() >= tx.vin.size());
					const CTxOut& txout = blockundo.vtxundo[i - 1].vprevout[j].txout;
					CoinsByScriptIndex_UpdateTx(txout, tx.vin[j].prevout, false);
				}
			}
		}
	}

/*	unsigned int i = 0;
	if (!fBlockConnected)
	{
		i = block.vtx.size() - 1; // iterate backwards
	}

	while (true)
	{
		const CTransaction &tx = block.vtx[i];

		

		

		if (fBlockConnected)
		{
			for (unsigned int j = 0; j < tx.vout.size(); j++)
			{
				CTxOut& txout = const_cast<CTxOut&>(tx.vout[j]);
				const COutPoint outpoint(tx.GetHash(), ((uint32_t)j));
				CoinsByScriptIndex_UpdateTx(txout, outpoint, true);
			}
			if (i == block.vtx.size() - 1)
				break;
			i++;
		}
		else
		{
			if (i > 0)
			{
				for (unsigned int j = 0; j < tx.vin.size(); j++)
				{
					assert(blockundo.vtxundo[i - 1].vprevout.size() >= tx.vin.size());
					const CTxOut& txout = blockundo.vtxundo[i - 1].vprevout[j].txout;
					CoinsByScriptIndex_UpdateTx(txout, tx.vin[j].prevout, false);
				}
			}

			if (i == 0)
				break;
			i--;
		}
	}
	*/
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