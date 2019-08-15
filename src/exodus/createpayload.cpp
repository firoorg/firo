#include "createpayload.h"

#include "convert.h"
#include "exodus.h"
#include "sigma.h"
#include "utils.h"

#include "../clientversion.h"
#include "../tinyformat.h"
#include "../streams.h"

#include <string>
#include <vector>

#include <inttypes.h>

/**
 * Pushes bytes to the end of a vector.
 */
#define PUSH_BACK_BYTES(vector, value)\
    vector.insert(vector.end(), reinterpret_cast<unsigned char *>(&(value)),\
    reinterpret_cast<unsigned char *>(&(value)) + sizeof((value)));

/**
 * Pushes bytes to the end of a vector based on a pointer.
 */
#define PUSH_BACK_BYTES_PTR(vector, ptr, size)\
    vector.insert(vector.end(), reinterpret_cast<unsigned char *>((ptr)),\
    reinterpret_cast<unsigned char *>((ptr)) + (size));


std::vector<unsigned char> CreatePayload_SimpleSend(uint32_t propertyId, uint64_t amount)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_SIMPLE_SEND;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);

    return payload;
}

std::vector<unsigned char> CreatePayload_SendAll(uint8_t ecosystem)
{
    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = EXODUS_TYPE_SEND_ALL;
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);

    return payload;
}

std::vector<unsigned char> CreatePayload_DExSell(uint32_t propertyId, uint64_t amountForSale, uint64_t amountDesired, uint8_t timeLimit, uint64_t minFee, uint8_t subAction)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_TRADE_OFFER;
    uint16_t messageVer = 1;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amountForSale);
    exodus::swapByteOrder64(amountDesired);
    exodus::swapByteOrder64(minFee);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amountForSale);
    PUSH_BACK_BYTES(payload, amountDesired);
    PUSH_BACK_BYTES(payload, timeLimit);
    PUSH_BACK_BYTES(payload, minFee);
    PUSH_BACK_BYTES(payload, subAction);

    return payload;
}

std::vector<unsigned char> CreatePayload_DExAccept(uint32_t propertyId, uint64_t amount)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_ACCEPT_OFFER_BTC;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);

    return payload;
}

std::vector<unsigned char> CreatePayload_SendToOwners(uint32_t propertyId, uint64_t amount, uint32_t distributionProperty)
{
    bool v0 = (propertyId == distributionProperty) ? true : false;

    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_SEND_TO_OWNERS;
    uint16_t messageVer = (v0) ? 0 : 1;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    if (!v0) {
        exodus::swapByteOrder32(distributionProperty);
        PUSH_BACK_BYTES(payload, distributionProperty);
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_IssuanceFixed(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data, uint64_t amount,
                                                       boost::optional<SigmaStatus> sigmaStatus)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_CREATE_PROPERTY_FIXED;
    uint16_t messageVer = sigmaStatus ? 1 : 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(propertyType);
    exodus::swapByteOrder32(previousPropertyId);
    exodus::swapByteOrder64(amount);

    if (category.size() > 255) category = category.substr(0,255);
    if (subcategory.size() > 255) subcategory = subcategory.substr(0,255);
    if (name.size() > 255) name = name.substr(0,255);
    if (url.size() > 255) url = url.substr(0,255);
    if (data.size() > 255) data = data.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);
    PUSH_BACK_BYTES(payload, propertyType);
    PUSH_BACK_BYTES(payload, previousPropertyId);
    payload.insert(payload.end(), category.begin(), category.end());
    payload.push_back('\0');
    payload.insert(payload.end(), subcategory.begin(), subcategory.end());
    payload.push_back('\0');
    payload.insert(payload.end(), name.begin(), name.end());
    payload.push_back('\0');
    payload.insert(payload.end(), url.begin(), url.end());
    payload.push_back('\0');
    payload.insert(payload.end(), data.begin(), data.end());
    payload.push_back('\0');
    PUSH_BACK_BYTES(payload, amount);

    if (sigmaStatus) {
        PUSH_BACK_BYTES(payload, sigmaStatus.get());
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_IssuanceVariable(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                          std::string subcategory, std::string name, std::string url, std::string data, uint32_t propertyIdDesired,
                                                          uint64_t amountPerUnit, uint64_t deadline, uint8_t earlyBonus, uint8_t issuerPercentage)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_CREATE_PROPERTY_VARIABLE;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(propertyType);
    exodus::swapByteOrder32(previousPropertyId);
    exodus::swapByteOrder32(propertyIdDesired);
    exodus::swapByteOrder64(amountPerUnit);
    exodus::swapByteOrder64(deadline);
    if (category.size() > 255) category = category.substr(0,255);
    if (subcategory.size() > 255) subcategory = subcategory.substr(0,255);
    if (name.size() > 255) name = name.substr(0,255);
    if (url.size() > 255) url = url.substr(0,255);
    if (data.size() > 255) data = data.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);
    PUSH_BACK_BYTES(payload, propertyType);
    PUSH_BACK_BYTES(payload, previousPropertyId);
    payload.insert(payload.end(), category.begin(), category.end());
    payload.push_back('\0');
    payload.insert(payload.end(), subcategory.begin(), subcategory.end());
    payload.push_back('\0');
    payload.insert(payload.end(), name.begin(), name.end());
    payload.push_back('\0');
    payload.insert(payload.end(), url.begin(), url.end());
    payload.push_back('\0');
    payload.insert(payload.end(), data.begin(), data.end());
    payload.push_back('\0');
    PUSH_BACK_BYTES(payload, propertyIdDesired);
    PUSH_BACK_BYTES(payload, amountPerUnit);
    PUSH_BACK_BYTES(payload, deadline);
    PUSH_BACK_BYTES(payload, earlyBonus);
    PUSH_BACK_BYTES(payload, issuerPercentage);

    return payload;
}

std::vector<unsigned char> CreatePayload_IssuanceManaged(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data,
                                                       boost::optional<SigmaStatus> sigmaStatus)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_CREATE_PROPERTY_MANUAL;
    uint16_t messageVer = sigmaStatus ? 1 : 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(propertyType);
    exodus::swapByteOrder32(previousPropertyId);

    if (category.size() > 255) category = category.substr(0,255);
    if (subcategory.size() > 255) subcategory = subcategory.substr(0,255);
    if (name.size() > 255) name = name.substr(0,255);
    if (url.size() > 255) url = url.substr(0,255);
    if (data.size() > 255) data = data.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);
    PUSH_BACK_BYTES(payload, propertyType);
    PUSH_BACK_BYTES(payload, previousPropertyId);
    payload.insert(payload.end(), category.begin(), category.end());
    payload.push_back('\0');
    payload.insert(payload.end(), subcategory.begin(), subcategory.end());
    payload.push_back('\0');
    payload.insert(payload.end(), name.begin(), name.end());
    payload.push_back('\0');
    payload.insert(payload.end(), url.begin(), url.end());
    payload.push_back('\0');
    payload.insert(payload.end(), data.begin(), data.end());
    payload.push_back('\0');

    if (sigmaStatus) {
        PUSH_BACK_BYTES(payload, sigmaStatus.get());
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_CloseCrowdsale(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_CLOSE_CROWDSALE;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_Grant(uint32_t propertyId, uint64_t amount, std::string memo)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_GRANT_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);
    if (memo.size() > 255) memo = memo.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), memo.begin(), memo.end());
    payload.push_back('\0');

    return payload;
}


std::vector<unsigned char> CreatePayload_Revoke(uint32_t propertyId, uint64_t amount, std::string memo)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_REVOKE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);
    if (memo.size() > 255) memo = memo.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), memo.begin(), memo.end());
    payload.push_back('\0');

    return payload;
}

std::vector<unsigned char> CreatePayload_ChangeIssuer(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_CHANGE_ISSUER_ADDRESS;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_EnableFreezing(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_ENABLE_FREEZING;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_DisableFreezing(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_DISABLE_FREEZING;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_FreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_FREEZE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);
    std::vector<unsigned char> addressBytes = AddressToBytes(address);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), addressBytes.begin(), addressBytes.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_UnfreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_TYPE_UNFREEZE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(amount);
    std::vector<unsigned char> addressBytes = AddressToBytes(address);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), addressBytes.begin(), addressBytes.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_MetaDExTrade(uint32_t propertyIdForSale, uint64_t amountForSale, uint32_t propertyIdDesired, uint64_t amountDesired)
{
    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_METADEX_TRADE;
    uint16_t messageVer = 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder32(propertyIdForSale);
    exodus::swapByteOrder64(amountForSale);
    exodus::swapByteOrder32(propertyIdDesired);
    exodus::swapByteOrder64(amountDesired);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyIdForSale);
    PUSH_BACK_BYTES(payload, amountForSale);
    PUSH_BACK_BYTES(payload, propertyIdDesired);
    PUSH_BACK_BYTES(payload, amountDesired);

    return payload;
}

std::vector<unsigned char> CreatePayload_MetaDExCancelPrice(uint32_t propertyIdForSale, uint64_t amountForSale, uint32_t propertyIdDesired, uint64_t amountDesired)
{
    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_METADEX_CANCEL_PRICE;
    uint16_t messageVer = 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder32(propertyIdForSale);
    exodus::swapByteOrder64(amountForSale);
    exodus::swapByteOrder32(propertyIdDesired);
    exodus::swapByteOrder64(amountDesired);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyIdForSale);
    PUSH_BACK_BYTES(payload, amountForSale);
    PUSH_BACK_BYTES(payload, propertyIdDesired);
    PUSH_BACK_BYTES(payload, amountDesired);

    return payload;
}

std::vector<unsigned char> CreatePayload_MetaDExCancelPair(uint32_t propertyIdForSale, uint32_t propertyIdDesired)
{
    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_METADEX_CANCEL_PAIR;
    uint16_t messageVer = 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder32(propertyIdForSale);
    exodus::swapByteOrder32(propertyIdDesired);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyIdForSale);
    PUSH_BACK_BYTES(payload, propertyIdDesired);

    return payload;
}

std::vector<unsigned char> CreatePayload_MetaDExCancelEcosystem(uint8_t ecosystem)
{
    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_METADEX_CANCEL_ECOSYSTEM;
    uint16_t messageVer = 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);

    return payload;
}

std::vector<unsigned char> CreatePayload_DeactivateFeature(uint16_t featureId)
{
    std::vector<unsigned char> payload;

    uint16_t messageVer = 65535;
    uint16_t messageType = EXODUS_MESSAGE_TYPE_DEACTIVATION;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(featureId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, featureId);

    return payload;
}

std::vector<unsigned char> CreatePayload_ActivateFeature(uint16_t featureId, uint32_t activationBlock, uint32_t minClientVersion)
{
    std::vector<unsigned char> payload;

    uint16_t messageVer = 65535;
    uint16_t messageType = EXODUS_MESSAGE_TYPE_ACTIVATION;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(featureId);
    exodus::swapByteOrder32(activationBlock);
    exodus::swapByteOrder32(minClientVersion);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, featureId);
    PUSH_BACK_BYTES(payload, activationBlock);
    PUSH_BACK_BYTES(payload, minClientVersion);

    return payload;
}

std::vector<unsigned char> CreatePayload_ExodusAlert(uint16_t alertType, uint32_t expiryValue, const std::string& alertMessage)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = EXODUS_MESSAGE_TYPE_ALERT;
    uint16_t messageVer = 65535;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder16(alertType);
    exodus::swapByteOrder32(expiryValue);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, alertType);
    PUSH_BACK_BYTES(payload, expiryValue);
    payload.insert(payload.end(), alertMessage.begin(), alertMessage.end());
    payload.push_back('\0');

    return payload;
}

std::vector<unsigned char> CreatePayload_CreateDenomination(uint32_t propertyId, uint64_t value)
{
    std::vector<unsigned char> payload;

    uint16_t messageType = EXODUS_TYPE_CREATE_DENOMINATION;
    uint16_t messageVer = 0;

    exodus::swapByteOrder16(messageVer);
    exodus::swapByteOrder16(messageType);
    exodus::swapByteOrder32(propertyId);
    exodus::swapByteOrder64(value);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, value);

    return payload;
}

std::vector<unsigned char> CreatePayload_SimpleMint(
    uint32_t propertyId, const std::vector<std::pair<uint8_t, exodus::SigmaPublicKey>>& mints)
{
    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = EXODUS_TYPE_SIGMA_SIMPLE_MINT;
    exodus::swapByteOrder(messageVer);
    exodus::swapByteOrder(messageType);
    exodus::swapByteOrder(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    if (mints.size() > EXODUS_MAX_SIMPLE_MINTS) {
        throw std::invalid_argument("amount of mints exceeded limit");
    }

    if (mints.size() == 0) {
        throw std::invalid_argument("no mints provided");
    }

    auto mintAmount = static_cast<uint8_t>(mints.size());
    PUSH_BACK_BYTES(payload, mintAmount);

    CDataStream serialized(SER_NETWORK, CLIENT_VERSION);
    for (auto const &mint : mints) {
        serialized << mint;
    }
    payload.insert(payload.end(), serialized.begin(), serialized.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_SimpleSpend(
    uint32_t propertyId, std::vector<exodus::SigmaSpend> const &spends)
{
    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = EXODUS_TYPE_SIGMA_SIMPLE_SPEND;
    exodus::swapByteOrder(messageVer);
    exodus::swapByteOrder(messageType);
    exodus::swapByteOrder(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    if (spends.size() > EXODUS_MAX_SIMPLE_SPENDS) {
        throw std::invalid_argument("amount of spends exceeded limit");
    }

    auto spendAmount = static_cast<uint8_t>(spends.size());
    PUSH_BACK_BYTES(payload, spendAmount);

    CDataStream serialized(SER_NETWORK, CLIENT_VERSION);

    for (auto const &spend : spends) {
        serialized << spend;
    }
    payload.insert(payload.end(), serialized.begin(), serialized.end());

    return payload;
}

#undef PUSH_BACK_BYTES
#undef PUSH_BACK_BYTES_PTR
