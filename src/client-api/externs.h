#ifndef CLIENTAPI_EXTERNS_H
#define CLIENTAPI_EXTERNS_H

#include <sync.h>
#include <boost/lockfree/queue.hpp>

extern boost::lockfree::queue<std::string*> clientApiLogMessages;
extern std::atomic<int> currentBlockHeight;
extern std::atomic<int> bestHeaderHeight;
extern std::atomic<int64_t> currentBlockTimestamp;
extern std::atomic<int> currentConnectionCount;
extern std::atomic<bool> isLelantusDisabled;

#endif // CLIENTAPI_EXTERNS_H