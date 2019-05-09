// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/mintpool.h"
#include "zerocoin_v3.h"

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

void CMintPool::Add(const CKeyID& seedId, const uint32_t& nCount)
{
    Add(make_pair(seedId, nCount));
    LogPrintf("%s : add %s to mint pool, nCountLastGenerated=%d\n", __func__, seedId.GetHex(), nCountLastGenerated);
}

void CMintPool::Add(const pair<CKeyID, uint32_t>& pMint, bool fVerbose)
{
    insert(pMint);
    if (pMint.second > nCountLastGenerated)
        nCountLastGenerated = pMint.second;

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), pMint.second);
}

bool CMintPool::Has(const CKeyID& seedId)
{
    return static_cast<bool>(count(seedId));
}

bool CMintPool::Get(const CKeyID& seedId, std::pair<CKeyID, uint32_t> result)
{
    for(std::list<pair<CKeyID, uint32_t>>::iterator it = List().begin(); it != List().end(); ++it){
        if(it->first==seedId){
            result = *it;
            return true;
        }
    }
    return false;
}

bool CMintPool::Get(const uint32_t& nCount, std::pair<CKeyID, uint32_t> result)
{
    for(std::list<pair<CKeyID, uint32_t>>::iterator it = List().begin(); it != List().end(); ++it){
        if(it->second==nCount){
            result = *it;
            return true;
        }
    }
    return false;
}

bool SortSmallest(const pair<CKeyID, uint32_t>& a, const pair<CKeyID, uint32_t>& b)
{
    return a.second < b.second;
}

std::list<pair<CKeyID, uint32_t> > CMintPool::List()
{
    list<pair<CKeyID, uint32_t> > listMints;
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

bool CMintPool::Front(std::pair<CKeyID, uint32_t>& pMint)
{
    if (empty())
        return false;
    pMint = *begin();
    return true;
}

bool CMintPool::Next(pair<CKeyID, uint32_t>& pMint)
{
    auto it = find(pMint.first);
    if (it == end() || ++it == end())
        return false;

    pMint = *it;
    return true;
}

void CMintPool::Remove(const CKeyID& seedId)
{
    auto it = find(seedId);
    if (it == end())
        return;

    nCountLastRemoved = it->second;
    erase(it);
}


