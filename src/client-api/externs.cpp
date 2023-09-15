#include "client-api/externs.h"
#include <boost/lockfree/queue.hpp>
boost::lockfree::queue<std::string*> clientApiLogMessages{16384};
std::atomic<int> currentBlockHeight{0};
std::atomic<int> bestHeaderHeight{0};
std::atomic <int64_t> currentBlockTimestamp{0};
std::atomic<int> currentConnectionCount{0};
std::atomic<bool> isLelantusDisabled{false};
