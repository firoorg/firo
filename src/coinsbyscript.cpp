// Copyright (c) 2014-2016 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coinsbyscript.h"
#include "txdb.h"
#include "hash.h"
#include "ui_interface.h"

#include <assert.h>

#include <boost/thread.hpp>


using namespace std;

static const char DB_COINS_BYSCRIPT = 'd';
static const char DB_FLAG = 'F';
static const char DB_BEST_BLOCK = 'B';


bool fTxOutIndex = false;
CCoinsViewByScriptDB *pCoinsViewByScriptDB = NULL;
CCoinsViewByScript *pCoinsViewByScript = NULL;



CCoinsViewByScript::CCoinsViewByScript(CCoinsViewByScriptDB* viewIn) 
	: base(viewIn) 
{ 
}

bool CCoinsViewByScript::GetCoinsByScript(const CScript &script, CCoinsByScript &coins) 
{

    const CScriptID key = CScriptID(script);
    if (cacheCoinsByScript.count(key)) 
	{
        coins = cacheCoinsByScript[key];
        return true;
    }
    if (base->GetCoinsByScriptID(key, coins)) 
	{
        cacheCoinsByScript[key] = coins;
        return true;
    }
    return false;
}

CCoinsMapByScript::iterator CCoinsViewByScript::FetchCoinsByScript(const CScript &script, bool fRequireExisting) 
{
    const CScriptID key = CScriptID(script);
    CCoinsMapByScript::iterator it = cacheCoinsByScript.find(key);
	if (it != cacheCoinsByScript.end())
	{
		return it;
	}

    CCoinsByScript tmp;
    if (!base->GetCoinsByScriptID(key, tmp))
    {
        if (fRequireExisting)
            return cacheCoinsByScript.end();
    }

    return cacheCoinsByScript.emplace_hint(it, key, tmp);
}

CCoinsByScript &CCoinsViewByScript::GetCoinsByScript(const CScript &script, bool fRequireExisting) 
{
    CCoinsMapByScript::iterator it = FetchCoinsByScript(script, fRequireExisting);
    assert(it != cacheCoinsByScript.end());
    return it->second;
}

uint256 CCoinsViewByScript::GetBestBlock() const 
{
    return hashBlock;
}

void CCoinsViewByScript::SetBestBlock(const uint256 &hashBlockIn) 
{
    hashBlock = hashBlockIn;
}

bool CCoinsViewByScript::Flush() 
{
    bool fOk = base->BatchWrite(this, hashBlock);
    return fOk;
}

CCoinsViewByScriptDB::CCoinsViewByScriptDB(size_t nCacheSize, bool fMemory, bool fWipe) 
	: db(GetDataDir() / "coinsbyscript", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewByScriptDB::GetCoinsByScriptID(const CScriptID &scriptID, CCoinsByScript &coins) const 
{
    return db.Read(make_pair(DB_COINS_BYSCRIPT, scriptID), coins);
}

bool CCoinsViewByScriptDB::BatchWrite(CCoinsViewByScript* pcoinsViewByScriptIn, const uint256 &hashBlock) 
{
    CDBBatch batch(db);
    size_t count = 0;
    for (CCoinsMapByScript::iterator it = pcoinsViewByScriptIn->cacheCoinsByScript.begin(); it != pcoinsViewByScriptIn->cacheCoinsByScript.end();) 
	{
        if (it->second.IsEmpty())
            batch.Erase(make_pair(DB_COINS_BYSCRIPT, it->first));
        else
            batch.Write(make_pair(DB_COINS_BYSCRIPT, it->first), it->second);
        CCoinsMapByScript::iterator itOld = it++;
        pcoinsViewByScriptIn->cacheCoinsByScript.erase(itOld);
        count++;
    }
    pcoinsViewByScriptIn->cacheCoinsByScript.clear();

	if (!hashBlock.IsNull())
	{
		batch.Write(DB_BEST_BLOCK, hashBlock);
	}

    LogPrintf("utxoindex", "Committing %u coin address indexes to coin database...\n", (unsigned int)count);
    return db.WriteBatch(batch);
}

bool CCoinsViewByScriptDB::WriteFlag(const std::string &name, bool fValue) 
{
    return db.Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CCoinsViewByScriptDB::ReadFlag(const std::string &name, bool &fValue) 
{
    char ch;
	if (!db.Read(std::make_pair(DB_FLAG, name), ch))
	{
		return false;
	}
    fValue = ch == '1';
    return true;
}

CCoinsViewByScriptDBCursor *CCoinsViewByScriptDB::Cursor() const
{
    CCoinsViewByScriptDBCursor *i = new CCoinsViewByScriptDBCursor(const_cast<CDBWrapper*>(&db)->NewIterator());
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

bool CCoinsViewByScriptDBCursor::GetKey(CScriptID &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COINS_BYSCRIPT) 
	{
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewByScriptDBCursor::GetValue(CCoinsByScript &coins) const
{
    return pcursor->GetValue(coins);
}

unsigned int CCoinsViewByScriptDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewByScriptDBCursor::Valid() const
{
    return keyTmp.first == DB_COINS_BYSCRIPT;
}

void CCoinsViewByScriptDBCursor::Next()
{
    pcursor->Next();
	if (!pcursor->Valid() || !pcursor->GetKey(keyTmp))
	{
		keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
	}
}

bool CCoinsViewByScriptDB::DeleteAllCoinsByScript()
{
    std::unique_ptr<CCoinsViewByScriptDBCursor> pcursor(Cursor());

    std::vector<CScriptID> v;
    int64_t i = 0;
    while (pcursor->Valid()) 
	{
        boost::this_thread::interruption_point();
        try 
		{
            CScriptID hash;
            if (!pcursor->GetKey(hash))
                break;
            v.push_back(hash);
            if (v.size() >= 10000)
            {
                i += v.size();
                CDBBatch batch(db);
                for(auto& av: v)
                {
                    const CScriptID& _hash = av;
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
            const CScriptID& hash = av;
            batch.Erase(make_pair(DB_COINS_BYSCRIPT, hash)); // delete
        }
        db.WriteBatch(batch);
    }
    if (i > 0)
        LogPrintf("Address index with %d addresses successfully deleted.\n", i);

    return true;
}

bool CCoinsViewByScriptDB::GenerateAllCoinsByScript(CCoinsViewDB* coinsIn)
{
    LogPrintf("Building address index for -txoutindex. Be patient...\n");
    int64_t nTxCount = coinsIn->CountCoins();

    std::unique_ptr<CCoinsViewCursor> pcursor(coinsIn->Cursor());

    CCoinsMapByScript mapCoinsByScript;
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

            for (unsigned int j = 0; j < coins.vout.size(); j++)
            {
                if (coins.vout[j].IsNull() || coins.vout[j].scriptPubKey.IsUnspendable())
                    continue;

                const CScriptID key = CScriptID(coins.vout[j].scriptPubKey);
                if (!mapCoinsByScript.count(key))
                {
                    CCoinsByScript coinsByScript;
                    GetCoinsByScriptID(key, coinsByScript);
                    mapCoinsByScript.insert(make_pair(key, coinsByScript));
                }
                mapCoinsByScript[key].setCoins.insert(COutPoint(txhash, (uint32_t)j));
                i++;
            }

            if (mapCoinsByScript.size() >= 10000)
            {
                CDBBatch batch(db);
                for (CCoinsMapByScript::iterator it = mapCoinsByScript.begin(); it != mapCoinsByScript.end();) {
                    if (it->second.IsEmpty())
                        batch.Erase(make_pair(DB_COINS_BYSCRIPT, it->first));
                    else
                        batch.Write(make_pair(DB_COINS_BYSCRIPT, it->first), it->second);
                    CCoinsMapByScript::iterator itOld = it++;
                    mapCoinsByScript.erase(itOld);
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
       for (CCoinsMapByScript::iterator it = mapCoinsByScript.begin(); it != mapCoinsByScript.end();) 
	   {
           if (it->second.IsEmpty())
               batch.Erase(make_pair(DB_COINS_BYSCRIPT, it->first));
           else
               batch.Write(make_pair(DB_COINS_BYSCRIPT, it->first), it->second);
           CCoinsMapByScript::iterator itOld = it++;
           mapCoinsByScript.erase(itOld);
       }
       db.WriteBatch(batch);
    }
    LogPrintf("Address index with %d outputs successfully built.\n", i);
    return true;
}

bool GetUTXOByScript_OnTheFly(CCoinsViewDB* coinsIn, const uint160& pubScriptHash, CAmount& balanceOut)
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

				const uint160 txoScriptHash = uint160(Hash160(coins.vout[j].scriptPubKey.begin(), coins.vout[j].scriptPubKey.end()));
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
		CCoinsByScript &coinsByScript = pCoinsViewByScript->GetCoinsByScript(txout.scriptPubKey, !fInsert);
		if (fInsert)
			coinsByScript.setCoins.insert(outpoint);
		else
			coinsByScript.setCoins.erase(outpoint);
	}
}

void CoinsByScriptIndex_UpdateBlock(const CBlock& block, CBlockUndo& blockundo, bool fBlockConnected)
{
	//return;
	if (!fTxOutIndex)
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
	pCoinsViewByScript->SetBestBlock(block.GetHash());
}