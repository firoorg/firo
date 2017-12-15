// Copyright (c) 2014-2016 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSBYSCRIPT_H
#define BITCOIN_COINSBYSCRIPT_H

#include "coins.h"
#include "dbwrapper.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "script/standard.h"
#include "undo.h"

class CCoinsViewDB;
class CCoinsByScriptViewDB;
class CScript;

class CCoinsByScript
{
public:
    // unspent transaction outputs
    std::set<COutPoint> setCoins;

    // empty constructor
    CCoinsByScript() { }

    bool IsEmpty() const {
        return (setCoins.empty());
    }

    void swap(CCoinsByScript &to) {
        to.setCoins.swap(setCoins);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(setCoins);
    }
};

typedef std::map<CScriptID, CCoinsByScript> CCoinsMapByScript;

/** Adds a memory cache for coins by address */
class CCoinsByScriptView
{
private:
    CCoinsByScriptViewDB *base;

    mutable uint256 hashBlock;

public:
    CCoinsMapByScript cacheCoinsByScript; // accessed also from CCoinsViewByScriptDB
    CCoinsByScriptView(CCoinsByScriptViewDB* baseIn);

    bool GetCoinsByScript(const CScript &script, CCoinsByScript &coins);

    // Return a modifiable reference to a CCoinsByScript.
    CCoinsByScript &GetCoinsByScript(const CScript &script, bool fRequireExisting = true);

    void SetBestBlock(const uint256 &hashBlock);
    uint256 GetBestBlock() const;

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

private:
    CCoinsMapByScript::iterator FetchCoinsByScript(const CScript &script, bool fRequireExisting);
};

/** Cursor for iterating over a CCoinsViewByScriptDB */
class CCoinsByScriptViewDBCursor 
{
public:
    ~CCoinsByScriptViewDBCursor() {}

    bool GetKey(CScriptID &key) const;
    bool GetValue(CCoinsByScript &coins) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();

private:
    CCoinsByScriptViewDBCursor(CDBIterator* pcursorIn):
        pcursor(pcursorIn) {}
    uint256 hashBlock;
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, CScriptID> keyTmp;

    friend class CCoinsByScriptViewDB;
};

/** coinsbyscript database (coinsbyscript/) */
class CCoinsByScriptViewDB 
{
protected:
    CDBWrapper db;
public:
    CCoinsByScriptViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoinsByScriptID(const CScriptID &scriptID, CCoinsByScript &coins) const;
    bool BatchWrite(CCoinsByScriptView* pcoinsViewByScriptIn, const uint256 &hashBlock);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
	bool ReadBestBlock(uint256& bestBlock);
    bool DeleteAllCoinsByScript();   // removes utxoindex
    bool GenerateAllCoinsByScript(CCoinsViewDB* coinsIn); // creates utxoindex


    CCoinsByScriptViewDBCursor *Cursor() const;
};

bool GetUTXOByScript_OnTheFly(CCoinsViewDB* coinsIn, const uint160& pubScriptHash, CAmount& balanceOut);

struct CUnspentTxBalance
{
	CAmount total = 0;
	CAmount sumSent = 0;
	CAmount sumReceived = 0;
};


extern bool fUTXOIndex;
extern CCoinsByScriptViewDB *pCoinsByScriptViewDB;
extern CCoinsByScriptView *pCoinsByScriptView;

void CoinsByScriptIndex_UpdateTx(const CTxOut& txout, const COutPoint& outpoint, bool fInsert);
void CoinsByScriptIndex_UpdateBlock(const CBlock& block, CBlockUndo& blockundo, bool fBlockConnected);

bool CoinsByScriptIndex_Rebuild(std::string& error);
bool CoinsByScriptIndex_Delete(std::string& error);

#endif // BITCOIN_COINSBYSCRIPT_H
