// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/mintpool.h"
#include "zerocoin_v3.h"

using namespace std;

CMintPool::CMintPool(){}

void CMintPool::Add(pair<uint256, MintPoolEntry> pMint, bool fVerbose)
{
    insert(pMint);

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), get<2>(pMint.second));
}

bool SortSmallest(const pair<uint256, MintPoolEntry> a, const pair<uint256, MintPoolEntry> b)
{
    return a.second < b.second;
}

void CMintPool::List(list<pair<uint256, MintPoolEntry>>& listMints)
{
    for (auto pMint : *(this)) {
        listMints.emplace_back(pMint);
    }

    listMints.sort(SortSmallest);
}

void CMintPool::Reset()
{
    clear();
}

bool CMintPool::Get(int32_t nCount, uint160 hashSeedMaster, pair<uint256, MintPoolEntry>& result){
    for (auto pMint : *(this)) {
        if(get<0>(pMint.second)==hashSeedMaster && get<2>(pMint.second)==nCount){
           result = pMint;
           return true;
        }
    }

    return false;

}
bool CMintPool::Front(pair<uint256, MintPoolEntry> pMint)
{
    if (empty())
        return false;
    pMint = *begin();
    return true;
}

bool CMintPool::Next(pair<uint256, MintPoolEntry> pMint)
{
    auto it = find(pMint.first);
    if (it == end() || ++it == end())
        return false;

    pMint = *it;
    return true;
}


