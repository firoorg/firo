// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mintpool.h"
#include "util.h"

using namespace std;

CMintPool::CMintPool()
{
    this->nCountLastGenerated = 0;
    this->nCountLastRemoved = 0;
}

CMintPool::CMintPool(uint32_t nCount)
{
    this->nCountLastRemoved = nCount;
    this->nCountLastGenerated = nCount;
}

void CMintPool::Add(const CBigNum& bnValue, const uint32_t& nCount)
{
    uint256 hash = GetPubCoinHash(bnValue);
    Add(make_pair(hash, nCount));
    LogPrintf("%s : add %s to mint pool, nCountLastGenerated=%d\n", __func__, bnValue.GetHex().substr(0, 6), nCountLastGenerated);
}

void CMintPool::Add(const pair<uint256, uint32_t>& pMint, bool fVerbose)
{
    insert(pMint);
    if (pMint.second > nCountLastGenerated)
        nCountLastGenerated = pMint.second;

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), pMint.second);
}

bool CMintPool::Has(const CBigNum& bnValue)
{
    return static_cast<bool>(count(GetPubCoinHash(bnValue)));
}

std::pair<uint256, uint32_t> CMintPool::Get(const CBigNum& bnValue)
{
    auto it = find(GetPubCoinHash(bnValue));
    return *it;
}

bool SortSmallest(const pair<uint256, uint32_t>& a, const pair<uint256, uint32_t>& b)
{
    return a.second < b.second;
}

std::list<pair<uint256, uint32_t> > CMintPool::List()
{
    list<pair<uint256, uint32_t> > listMints;
    for (auto pMint : *(this)) {
        listMints.emplace_back(pMint);
    }

    listMints.sort(SortSmallest);

    return listMints;
}

void CMintPool::Reset()
{
    clear();
    nCountLastGenerated = 0;
    nCountLastRemoved = 0;
}

bool CMintPool::Front(std::pair<uint256, uint32_t>& pMint)
{
    if (empty())
        return false;
    pMint = *begin();
    return true;
}

bool CMintPool::Next(pair<uint256, uint32_t>& pMint)
{
    auto it = find(pMint.first);
    if (it == end() || ++it == end())
        return false;

    pMint = *it;
    return true;
}

void CMintPool::Remove(const CBigNum& bnValue)
{
    Remove(GetPubCoinHash(bnValue));
    LogPrintf("%s : remove %s from mint pool\n", __func__, bnValue.GetHex().substr(0, 6));
}

void CMintPool::Remove(const uint256& hashPubcoin)
{
    auto it = find(hashPubcoin);
    if (it == end())
        return;

    nCountLastRemoved = it->second;
    erase(it);
}


