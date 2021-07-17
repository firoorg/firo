// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/mintpool.h"
#include "sigma.h"

CMintPool::CMintPool(){}

/**
 * Add a mintpool entry
 *
 * @return void
 */
void CMintPool::Add(std::pair<uint256, MintPoolEntry> pMint, bool fVerbose)
{
    insert(pMint);

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), std::get<2>(pMint.second));
}

/**
 * Sort mintpool entries in terms of the mint count.
 *
 * @return success
 */
bool SortSmallest(const std::pair<uint256, MintPoolEntry>& a, const std::pair<uint256, MintPoolEntry>& b)
{
    return std::get<2>(a.second) < std::get<2>(b.second);
}

/**
 * place the mintpool in listMints.
 *
 * @param listMints
 * @return void
 */
void CMintPool::List(std::list<std::pair<uint256, MintPoolEntry>>& listMints)
{
    for (auto pMint : *(this)) {
        listMints.emplace_back(pMint);
    }

    listMints.sort(SortSmallest);
}

/**
 * clear the current mintpool
 *
 * @return void
 */
void CMintPool::Reset()
{
    clear();
}

bool CMintPool::Get(int32_t nCount, uint160 hashSeedMaster, std::pair<uint256, MintPoolEntry>& result){
    for (auto pMint : *(this)) {
        if(std::get<0>(pMint.second)==hashSeedMaster && std::get<2>(pMint.second)==nCount){
           result = pMint;
           return true;
        }
    }

    return false;

}


