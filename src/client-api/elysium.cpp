#include "client-api/server.h"
#include "client-api/wallet.h"
#include "univalue.h"
#include "chain.h"
#include "validation.h"
#include "protocol.h"
#include "../elysium/wallettxs.h"
#include "../elysium/tx.h"
#include "../elysium/createpayload.h"
#include "../elysium/rules.h"
#include "../elysium/errors.h"
#include "../elysium/wallet.h"
#include "../elysium/pending.h"

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

UniValue createElysiumProperty(Type type, const UniValue &data, const UniValue &auth, bool fHelp) {
    LOCK(cs_main);

    std::string fromAddress;
    CAmount minAmount = elysium::ConsensusParams().REFERENCE_AMOUNT * 2;
    std::map<CTxDestination, CAmount> balances = pwalletMain->GetAddressBalances();
    for (auto& balance : balances) {
        if (balance.second >= minAmount) {
            fromAddress = CBitcoinAddress(balance.first).ToString();
            break;
        }
    }
    if (fromAddress.empty()) {
        throw JSONAPIError(API_INVALID_PARAMS, "no addresses with public balance >= 0.002 FIRO");
    }

    bool isFixed = data["isFixed"].get_bool();
    bool isMainEcosystem = true;
    bool isDivisible = data["isDivisible"].get_bool();
    int previousId = 0;
    std::string category = data["category"].get_str();
    if (category.length() > 255) throw JSONAPIError(API_INVALID_PARAMS, "category must be <256 chars");
    std::string subcategory = data["subcategory"].get_str();
    if (subcategory.length() > 255) throw JSONAPIError(API_INVALID_PARAMS, "subcategory must be <256 chars");
    std::string name = data["name"].get_str();
    if (name.empty() || name.length() > 255) throw JSONAPIError(API_INVALID_PARAMS, "name must be between 1 and 255 chars");
    std::string url = data["url"].get_str();
    if (url.length() > 255) throw JSONAPIError(API_INVALID_PARAMS, "url must be <256 chars");
    std::string propertyData = data["data"].get_str();
    if (propertyData.length() > 255) throw JSONAPIError(API_INVALID_PARAMS, "data must be <256 chars");
    int64_t amount = 0;
    if (isFixed) {
        amount = boost::lexical_cast<int64_t>(data["amount"].get_str());
        if (amount <= 0) throw JSONAPIError(API_INVALID_PARAMS, "amount must be between 0 and 2^63-1");
    }
    elysium::LelantusStatus lelantusStatus = elysium::LelantusStatus::HardEnabled;

    // create a payload for the transaction
    std::vector<unsigned char> payload;
    if (isFixed) {
        payload = CreatePayload_IssuanceFixed(
                isMainEcosystem ? 1 : 2,
                isDivisible ? 2 : 1,
                previousId,
                category,
                subcategory,
                name,
                url,
                propertyData,
                amount,
                lelantusStatus
        );
    } else {
        payload = CreatePayload_IssuanceManaged(
                isMainEcosystem ? 1 : 2,
                isDivisible ? 2 : 1,
                previousId,
                category,
                subcategory,
                name,
                url,
                propertyData,
                lelantusStatus
        );
    }

    uint256 txid;
    std::string rawHex;
    std::string receiver;
    int result = elysium::WalletTxBuilder(fromAddress, receiver, "", payload, txid, rawHex, autoCommit);
    if (result != 0) throw JSONAPIError(API_INTERNAL_ERROR, error_str(result));
    else return txid.GetHex();
}

UniValue mintElysium(Type type, const UniValue &data, const UniValue &auth, bool fHelp) {
    LOCK(cs_main);

    std::string address = data["address"].get_str();
    uint32_t propertyId = data["propertyId"].get_int64();

    CMPSPInfo::Entry info;
    if (!elysium::_my_sps->getSP(propertyId, info))
        throw JSONAPIError(API_INVALID_PARAMS, "invalid propertyId");
    if (info.lelantusStatus == elysium::LelantusStatus::SoftDisabled || info.lelantusStatus == elysium::LelantusStatus::HardDisabled)
        throw JSONAPIError(API_INVALID_PARAMS, "lelantus not enabled for this property");

    int64_t balance = std::min(getMPbalance(address, propertyId, BALANCE), getUserAvailableMPbalance(address, propertyId));
    if (!balance) return UniValue::VNULL;

    elysium::LelantusWallet::MintReservation mint = elysium::wallet->CreateLelantusMint(propertyId, balance);
    lelantus::PrivateCoin coin = mint.coin;

    CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    uint256 txid;
    std::string rawHex;
    std::vector<unsigned char> payload = CreatePayload_CreateLelantusMint(propertyId, coin.getPublicCoin(), mint.id, balance, {serializedSchnorrProof.begin(), serializedSchnorrProof.end()});
    auto result = elysium::WalletTxBuilder(address, "", "", payload, txid, rawHex, true);
    if (result != 0) throw JSONAPIError(API_INTERNAL_ERROR, error_str(result));

    mint.Commit();
    elysium::PendingAdd(txid, address, ELYSIUM_TYPE_LELANTUS_MINT, propertyId, balance);

    return txid.GetHex();
}

static const CAPICommand commands[] =
        { //  category collection actor authPort authPassphrase  warmupOk
          //  -------- ---------- ----- -------- --------------  --------
          { "elysium", "getElysiumPropertyInfo", &getElysiumPropertyInfo, true, false, false  },
          { "elysium", "createElysiumProperty", &createElysiumProperty, true, true, false  },
          { "elysium", "mintElysium", &mintElysium, true, true, false  },
        };

void RegisterElysiumAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
