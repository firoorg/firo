#ifndef EXODUS_WALLETCACHE_H
#define EXODUS_WALLETCACHE_H

class uint256;

#include <vector>

namespace exodus
{
//! Global vector of Exodus transactions in the wallet
extern std::vector<uint256> walletTXIDCache;

/** Adds a txid to the wallet txid cache, performing duplicate detection */
void WalletTXIDCacheAdd(const uint256& hash);

/** Performs initial population of the wallet txid cache */
void WalletTXIDCacheInit();

/** Updates the cache and returns whether any wallet addresses were changed */
int WalletCacheUpdate();
}

#endif // EXODUS_WALLETCACHE_H
