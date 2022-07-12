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
#include "../elysium/lelantusdb.h"
#include "../elysium/lelantusutils.h"

UniValue getPropertyData(uint32_t propertyId) {
    AssertLockHeld(cs_main);

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
    AssertLockHeld(cs_main);

    uint32_t propertyId = elysium::_my_sps->findSPByTX(propertyCreationTxid);
    if (propertyId > 0) {
        return getPropertyData(propertyId);
    } else {
        auto wtxIt = pwalletMain->mapWallet.find(propertyCreationTxid);
        if (wtxIt == pwalletMain->mapWallet.end())
            throw JSONAPIError(API_INTERNAL_ERROR, "tried to get information about an Elysium property that does not exist");
        CWalletTx *wtx = &wtxIt->second;

        CMPTransaction mp_obj;
        if (ParseTransaction(*wtx->tx, 0, 0, mp_obj, wtx->GetTxTime()) < 0 || !mp_obj.interpret_Transaction()) {
            throw JSONAPIError(API_INTERNAL_ERROR, "tried to get information about an Elysium property that does not exist");
        }

        UniValue propertyData = UniValue::VOBJ;
        propertyData.pushKV("id", UniValue::VNULL);
        propertyData.pushKV("lelantusStatus", std::to_string(mp_obj.getLelantusStatus()));
        propertyData.pushKV("issuer", mp_obj.getSender());
        propertyData.pushKV("creationTx", wtx->tx->GetHash().GetHex());
        propertyData.pushKV("isDivisible", mp_obj.getPropertyType() == ELYSIUM_PROPERTY_TYPE_DIVISIBLE);
        propertyData.pushKV("ecosystem", elysium::strEcosystem(mp_obj.getEcosystem()));
        propertyData.pushKV("isFixed", mp_obj.getType() == ELYSIUM_TYPE_CREATE_PROPERTY_FIXED);
        propertyData.pushKV("isManaged", mp_obj.getType() == ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL);
        propertyData.pushKV("name", mp_obj.getSPName());
        propertyData.pushKV("category", mp_obj.getSPCategory());
        propertyData.pushKV("subcategory", mp_obj.getSPSubCategory());
        propertyData.pushKV("data", mp_obj.getSPData());
        propertyData.pushKV("url", mp_obj.getSPUrl());
        return propertyData;
    }

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

    std::string fromAddress = data["fromAddress"].get_str();
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
    UniValue inputs = UniValue::VARR;
    int result = elysium::WalletTxBuilder(fromAddress, receiver, "", payload, txid, rawHex, autoCommit, elysium::InputMode::CREATE_PROPERTY, &inputs);
    if (result != 0) throw JSONAPIError(API_INTERNAL_ERROR, error_str(result));

    UniValue ret = UniValue::VOBJ;
    ret.pushKV("txid", txid.GetHex());
    ret.pushKV("inputs", inputs);
    return ret;
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

    UniValue txids = UniValue::VARR;
    UniValue inputs = UniValue::VARR;

    int b = INT_MAX;
    if (elysium::lelantusDb->GetAnonymityGroup(propertyId, 0, 1, b).empty()) {
        if (balance == 1) throw JSONAPIError(API_INTERNAL_ERROR, "minting logic requires two initial mints; this condition cannot be fulfilled");

        int64_t premintAmount = balance / 2;
        balance = balance - premintAmount;

        elysium::LelantusWallet::MintReservation mint = elysium::wallet->CreateLelantusMint(propertyId, premintAmount);
        lelantus::PrivateCoin coin = mint.coin;

        CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
        lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);

        uint256 txid;
        std::string rawHex;
        std::vector<unsigned char> payload = CreatePayload_CreateLelantusMint(propertyId, coin.getPublicCoin(), mint.id, premintAmount, {serializedSchnorrProof.begin(), serializedSchnorrProof.end()});
        auto result = elysium::WalletTxBuilder(address, "", "", payload, txid, rawHex, true, elysium::InputMode::MINT, &inputs);
        if (result != 0) throw JSONAPIError(API_INTERNAL_ERROR, error_str(result));

        mint.Commit();
        elysium::PendingAdd(txid, address, ELYSIUM_TYPE_LELANTUS_MINT, propertyId, premintAmount);
        txids.push_back(txid.GetHex());

        GetMainSignals().WalletTransaction(pwalletMain->mapWallet.at(txid));
    }

    elysium::LelantusWallet::MintReservation mint = elysium::wallet->CreateLelantusMint(propertyId, balance);
    lelantus::PrivateCoin coin = mint.coin;

    CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    uint256 txid;
    std::string rawHex;
    std::vector<unsigned char> payload = CreatePayload_CreateLelantusMint(propertyId, coin.getPublicCoin(), mint.id, balance, {serializedSchnorrProof.begin(), serializedSchnorrProof.end()});
    auto result = elysium::WalletTxBuilder(address, "", "", payload, txid, rawHex, true, elysium::InputMode::MINT, &inputs);
    if (result != 0) throw JSONAPIError(API_INTERNAL_ERROR, error_str(result));

    mint.Commit();
    elysium::PendingAdd(txid, address, ELYSIUM_TYPE_LELANTUS_MINT, propertyId, balance);
    txids.push_back(txid.GetHex());

    GetMainSignals().WalletTransaction(pwalletMain->mapWallet.at(txid));

    UniValue ret = UniValue::VOBJ;
    ret.pushKV("txids", txids);
    ret.pushKV("inputs", inputs);
    return ret;
}

UniValue sendElysium(Type type, const UniValue &data, const UniValue &auth, bool fHelp) {
    LOCK(cs_main);

    // obtain parameters & info
    std::string sAddress = data["address"].get_str();
    CBitcoinAddress address(sAddress);
    int64_t propertyId = data["propertyId"].get_int64();
    int64_t amount = data["amount"].get_int64();
    int64_t referenceAmount = elysium::ConsensusParams().REFERENCE_AMOUNT;

    CMPSPInfo::Entry info;
    if (!elysium::_my_sps->getSP(propertyId, info))
        throw JSONAPIError(API_INVALID_PARAMS, "invalid propertyId");
    if (info.lelantusStatus == elysium::LelantusStatus::SoftDisabled || info.lelantusStatus == elysium::LelantusStatus::HardDisabled)
        throw JSONAPIError(API_INVALID_PARAMS, "lelantus not enabled for this property");

    std::vector<unsigned char> payload;

    uint256 metaData = elysium::PrepareSpendMetadata(address, referenceAmount);

    std::vector<elysium::SpendableCoin> spendables;
    boost::optional<elysium::LelantusWallet::MintReservation> reservation;
    elysium::LelantusAmount changeValue = 0;

    try {
        auto joinSplit = elysium::wallet->CreateLelantusJoinSplit(propertyId, amount, metaData, spendables, reservation, changeValue);

        boost::optional<elysium::JoinSplitMint> joinSplitMint;
        if (reservation.get_ptr() != nullptr) {
            auto pub = reservation->coin.getPublicCoin();
            elysium::EncryptedValue enc;
            elysium::EncryptMintAmount(changeValue, pub.getValue(), enc);

            joinSplitMint = elysium::JoinSplitMint(
                    reservation->id,
                    pub,
                    enc
            );
        }

        payload = CreatePayload_CreateLelantusJoinSplit(
                propertyId, amount, joinSplit, joinSplitMint);
    } catch (InsufficientFunds& e) {
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, e.what());
    } catch (WalletError &e) {
        throw JSONAPIError(API_INTERNAL_ERROR, e.what());
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    UniValue baseLayerInputs = UniValue::VARR;
    int result = WalletTxBuilder(
            "",
            sAddress,
            "",
            payload,
            txid,
            rawHex,
            autoCommit,
            elysium::InputMode::LELANTUS,
            &baseLayerInputs
    );

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONAPIError(result, error_str(result));
    } else {
        // mark the coin as used
        for (auto const &s : spendables) {
            elysium::wallet->SetLelantusMintUsedTransaction(s.id, txid);
        }

        if (reservation.get_ptr() != nullptr) {
            reservation->Commit();
        }

        elysium::PendingAdd(
                txid,
                "Lelantus Joinsplit",
                ELYSIUM_TYPE_LELANTUS_JOINSPLIT,
                propertyId,
                amount,
                false,
                sAddress);

        GetMainSignals().WalletTransaction(pwalletMain->mapWallet.at(txid));

        UniValue ret = UniValue::VOBJ;
        ret.pushKV("txid", txid.GetHex());
        ret.pushKV("inputs", baseLayerInputs);
        return ret;
    }
}

UniValue recoverElysium(Type type, const UniValue &data, const UniValue &auth, bool fHelp) {
    LOCK2(cs_main, pwalletMain->cs_wallet);
    elysium::wallet->SyncWithChain();
    return UniValue::VNULL;
}

static const CAPICommand commands[] =
    { //  category collection actor authPort authPassphrase  warmupOk
      //  -------- ---------- ----- -------- --------------  --------
      { "elysium", "getElysiumPropertyInfo", &getElysiumPropertyInfo, true, false, false  },
      { "elysium", "createElysiumProperty", &createElysiumProperty, true, true, false  },
      { "elysium", "mintElysium", &mintElysium, true, true, false  },
      { "elysium", "sendElysium", &sendElysium, true, true, false  },
      { "elysium", "recoverElysium", &recoverElysium, true, true, false  },
    };

void RegisterElysiumAPICommands(CAPITable &tableAPI)
{
    if (!isElysiumEnabled()) return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
