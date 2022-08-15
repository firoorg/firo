#ifndef CLIENTAPI_MISC_H
#define CLIENTAPI_MISC_H

#include <sync.h>

// defined in misc.cpp
extern CCriticalSection cs_clientApiLogMessages;
extern std::vector<std::string> clientApiLogMessages;
extern std::atomic<int> currentBlockHeight;
extern std::atomic<int64_t> currentBlockTimestamp;
extern std::atomic<int> currentConnectionCount;
extern std::atomic<bool> isBlockchainSynced;
extern std::atomic<bool> isLelantusDisabled;

#endif //CLIENTAPI_MISC_H
