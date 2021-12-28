#ifndef CLIENTAPI_ELYSIUM_H
#define CLIENTAPI_ELYSIUM_H

#include "univalue.h"

UniValue getPropertyData(uint32_t propertyId);
UniValue getPropertyData(uint256 propertyCreationTxid);

#endif