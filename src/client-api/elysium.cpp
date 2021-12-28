#include "client-api/server.h"
#include "client-api/wallet.h"
#include "univalue.h"
#include "chain.h"
#include "validation.h"
#include "protocol.h"
#include "../elysium/wallettxs.h"
#include "../elysium/tx.h"

UniValue getPropertyData(uint32_t propertyId) {
    CMPSPInfo::Entry info;

    if (elysium::_my_sps->getSP(propertyId, info)) {
        UniValue propertyData = UniValue::VOBJ;
        propertyData.pushKV("id", (int64_t)propertyId);
        propertyData.pushKV("issuer", info.issuer);
        propertyData.pushKV("creationTx", info.txid.GetHex());
        propertyData.pushKV("isDivisible", info.isDivisible());
        propertyData.pushKV("ecosystem", propertyId >= TEST_ECO_PROPERTY_1 ? "test" : "main");
        propertyData.pushKV("isFixed", info.fixed);
        propertyData.pushKV("isManaged", info.manual);
        propertyData.pushKV("lelantusStatus", std::to_string(info.lelantusStatus));
        propertyData.pushKV("name", info.name);
        propertyData.pushKV("category", info.category);
        propertyData.pushKV("subcategory", info.subcategory);
        propertyData.pushKV("data", info.data);
        propertyData.pushKV("url", info.url);

        return propertyData;
    }

    throw JSONAPIError(API_INTERNAL_ERROR, "tried to get information about an Elysium property that does not exist");
}

UniValue getPropertyData(uint256 propertyCreationTxid) {
    uint32_t propertyId = elysium::_my_sps->findSPByTX(propertyCreationTxid);
    if (propertyId <= 0) throw JSONAPIError(API_INTERNAL_ERROR, "tried to get information about an Elysium property that does not exist");

    return getPropertyData(propertyId);
}

UniValue getElysiumPropertyInfo(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    LOCK(cs_main);

    if (data.exists("propertyId")) {
        return getPropertyData(data["propertyId"].get_int64());
    }

    if (data.exists("propertyCreationTxid")) {
        uint256 txid;
        txid.SetHex(data["propertyCreationTxid"].get_str());
        return getPropertyData(txid);
    }

    throw JSONAPIError(API_INVALID_PARAMS, "propertyId or propertyCreationTxid must be specified");
}

static const CAPICommand commands[] =
        { //  category collection actor authPort authPassphrase  warmupOk
          //  -------- ---------- ----- -------- --------------  --------
          { "elysium", "getElysiumPropertyInfo", &getElysiumPropertyInfo, true, false, false  },
        };

void RegisterElysiumAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
