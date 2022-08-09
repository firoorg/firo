#ifndef CLIENTAPI_MISC_H
#define CLIENTAPI_MISC_H

#include <sync.h>

// defined in misc.cpp
extern CCriticalSection cs_clientApiLogMessages;
extern std::vector<std::string> clientApiLogMessages;

#endif //CLIENTAPI_MISC_H
