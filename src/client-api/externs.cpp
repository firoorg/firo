#include "client-api/externs.h"

CCriticalSection cs_clientApiLogMessages;
std::vector <std::string> clientApiLogMessages;
std::atomic<int> currentBlockHeight{0};
std::atomic<int> bestHeaderHeight{0};
std::atomic <int64_t> currentBlockTimestamp{0};
std::atomic<int> currentConnectionCount{0};
std::atomic<bool> isLelantusDisabled{false};
