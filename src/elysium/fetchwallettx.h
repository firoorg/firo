#ifndef ELYSIUM_FETCHWALLETTX_H
#define ELYSIUM_FETCHWALLETTX_H

class uint256;

#include <map>
#include <string>

namespace elysium
{
/** Gets the byte offset of a transaction from the transaction index. */
unsigned int GetTransactionByteOffset(const uint256& txid);

/** Returns an ordered list of Elysium transactions that are relevant to the wallet. */
std::map<std::string, uint256> FetchWalletElysiumTransactions(unsigned int count, int startBlock = 0, int endBlock = 999999);
}

#endif // ELYSIUM_FETCHWALLETTX_H
