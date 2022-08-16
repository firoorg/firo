#ifndef CLIENTAPI_EXTERNS_H
#define CLIENTAPI_EXTERNS_H

#include <sync.h>

extern CCriticalSection cs_clientApiLogMessages;
extern std::vector<std::string> clientApiLogMessages;
extern std::atomic<int> currentBlockHeight;
extern std::atomic<int64_t> currentBlockTimestamp;
extern std::atomic<int> currentConnectionCount;
extern std::atomic<bool> isBlockchainSynced;
extern std::atomic<bool> isLelantusDisabled;

#endif // CLIENTAPI_EXTERNS_H