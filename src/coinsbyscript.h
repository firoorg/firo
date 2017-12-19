// Copyright (c) 2014-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_COINSBYSCRIPT_H
#define ZCOIN_COINSBYSCRIPT_H

#include "coins.h"
#include "dbwrapper.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "script/standard.h"
#include "undo.h"
#include <univalue.h>
#include <limits.h>

class CCoinsViewDB;
class CCoinsByScriptViewDB;
class CScript;

// unspent transaction outputs
typedef std::set<COutPoint> unspentcoins_t;

typedef uint160 scripthash_t;

typedef std::map<scripthash_t, unspentcoins_t> coinsbyscriptmap_t;


/** A memory cache backed by database */
class CCoinsByScriptView
{
private:
    CCoinsByScriptViewDB *base;

    //best block
    uint256 hashBlock;

public:
    coinsbyscriptmap_t cacheCoinsByScript;
    CCoinsByScriptView(CCoinsByScriptViewDB* baseIn);

    bool GetCoinsByScript(const CScript& scriptIn, unspentcoins_t& coinsOut);

    // Return a modifiable reference to a unspentcoins_t. Searches for 'script' in both cache and db
    unspentcoins_t &GetCoinsByScript(const CScript& script, bool fRequireExisting = true);

    void SetBestBlock(const uint256& hashBlock);
    uint256 GetBestBlock() const;

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();
};

/** Cursor for iterating over a CCoinsViewByScriptDB */
class CCoinsByScriptViewDBCursor 
{
public:
    ~CCoinsByScriptViewDBCursor() {}

    bool GetKey(scripthash_t &keyOut) const;
    bool GetValue(unspentcoins_t &coinsOut) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();

private:
    CCoinsByScriptViewDBCursor(CDBIterator* pcursorIn):
        pcursor(pcursorIn) {}
    std::unique_ptr<CDBIterator> pcursor;

    std::pair<char, scripthash_t> keyTmp;

    friend class CCoinsByScriptViewDB;
};

/** coinsbyscript database (coinsbyscript/) */
class CCoinsByScriptViewDB 
{
protected:
    CDBWrapper db;
public:
    CCoinsByScriptViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoinsByScriptHash(const scripthash_t& scriptHash, unspentcoins_t& coins) const;
    bool BatchWrite(CCoinsByScriptView* pcoinsViewByScriptIn, const uint256& hashBlock);
    bool WriteFlag(const std::string& name, bool fValue);
    bool ReadFlag(const std::string& name, bool &fValue);
    bool ReadBestBlock(uint256& bestBlock);

    CCoinsByScriptViewDBCursor* Cursor() const;

    bool DeleteAllCoinsByScript();   // removes utxoindex
    bool GenerateAllCoinsByScript(CCoinsViewDB* coinsIn); // creates utxoindex
};

/* Helper function for converting a script to a key hash */
scripthash_t GetScriptHash(const CScript& in);

UniValue ValueFromUnspentCoins(const unspentcoins_t& unspentCoins, const int64_t nMaxOutputs = std::numeric_limits<int64_t>::max());

extern bool fUTXOIndex;
extern CCoinsByScriptViewDB *pCoinsByScriptViewDB;
extern CCoinsByScriptView *pCoinsByScriptView;

/* A function to update the index on blockchain change (eg. on block connection/disconnection) */
void CoinsByScriptIndex_UpdateBlock(const CBlock& block, CBlockUndo& blockundo, bool fBlockConnected);

bool CoinsByScriptIndex_Rebuild(std::string& error);
bool CoinsByScriptIndex_Delete(std::string& error);

#endif // ZCOIN_COINSBYSCRIPT_H
