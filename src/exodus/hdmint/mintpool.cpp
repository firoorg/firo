// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mintpool.h"

#include "../sigma.h"

using namespace std;

CExodusMintPool::CExodusMintPool(){}

void CExodusMintPool::Add(pair<uint256, MintPoolEntry> pMint, bool fVerbose)
{
    insert(pMint);

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), get<2>(pMint.second));
}

bool SortSmallest(const pair<uint256, MintPoolEntry>& a, const pair<uint256, MintPoolEntry>& b)
{
    return get<2>(a.second) < get<2>(b.second);
}

void CExodusMintPool::List(list<pair<uint256, MintPoolEntry>>& listMints)
{
    for (auto pMint : *(this)) {
        listMints.emplace_back(pMint);
    }

    listMints.sort(SortSmallest);
}

void CExodusMintPool::Reset()
{
    clear();
}

bool CExodusMintPool::Get(int32_t nCount, uint160 hashSeedMaster, pair<uint256, MintPoolEntry>& result){
    for (auto pMint : *(this)) {
        if(get<0>(pMint.second)==hashSeedMaster && get<2>(pMint.second)==nCount){
           result = pMint;
           return true;
        }
    }

    return false;

}


