#include "rpcrequirements.h"

#include "dex.h"
#include "exodus.h"
#include "rules.h"
#include "sp.h"
#include "utilsbitcoin.h"

#include "../amount.h"
#include "../main.h"
#include "../rpc/protocol.h"
#include "../sync.h"
#include "../tinyformat.h"

#include <string>

#include <stdint.h>

void RequireBalance(const std::string& address, uint32_t propertyId, int64_t amount)
{
    int64_t balance = getMPbalance(address, propertyId, BALANCE);
    if (balance < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender has insufficient balance");
    }
    int64_t balanceUnconfirmed = getUserAvailableMPbalance(address, propertyId);
    if (balanceUnconfirmed < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender has insufficient balance (due to pending transactions)");
    }
}

void RequirePrimaryToken(uint32_t propertyId)
{
    if (propertyId < 1 || 2 < propertyId) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier must be 1 (EXODUS) or 2 (TEXODUS)");
    }
}

void RequirePropertyName(const std::string& name)
{
    if (name.empty()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Property name must not be empty");
    }
}

void RequireExistingProperty(uint32_t propertyId)
{
    LOCK(cs_main);
    if (!exodus::IsPropertyIdValid(propertyId)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not exist");
    }
}

void RequireSameEcosystem(uint32_t propertyId, uint32_t otherId)
{
    if (exodus::isTestEcosystemProperty(propertyId) != exodus::isTestEcosystemProperty(otherId)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Properties must be in the same ecosystem");
    }
}

void RequireDifferentIds(uint32_t propertyId, uint32_t otherId)
{
    if (propertyId == otherId) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifiers must not be the same");
    }
}

void RequireCrowdsale(uint32_t propertyId)
{
    LOCK(cs_main);
    CMPSPInfo::Entry sp;
    if (!exodus::_my_sps->getSP(propertyId, sp)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to retrieve property");
    }
    if (sp.fixed || sp.manual) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not refer to a crowdsale");
    }
}

void RequireActiveCrowdsale(uint32_t propertyId)
{
    LOCK(cs_main);
    if (!exodus::isCrowdsaleActive(propertyId)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Property identifier does not refer to an active crowdsale");
    }
}

void RequireManagedProperty(uint32_t propertyId)
{
    LOCK(cs_main);
    CMPSPInfo::Entry sp;
    if (!exodus::_my_sps->getSP(propertyId, sp)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to retrieve property");
    }
    if (sp.fixed || !sp.manual) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not refer to a managed property");
    }
}

void RequireTokenIssuer(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    CMPSPInfo::Entry sp;
    if (!exodus::_my_sps->getSP(propertyId, sp)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to retrieve property");
    }
    if (address != sp.issuer) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender is not authorized to manage the property");
    }
}

void RequireMatchingDExOffer(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    if (!exodus::DEx_offerExists(address, propertyId)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "No matching sell offer on the distributed exchange");
    }
}

void RequireNoOtherDExOffer(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    if (exodus::DEx_offerExists(address, propertyId)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Another active sell offer from the given address already exists on the distributed exchange");
    }
}

void RequireSaneReferenceAmount(int64_t amount)
{
    if ((0.01 * COIN) < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Reference amount higher is than 0.01 XZC");
    }
}

void RequireSaneDExPaymentWindow(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    const CMPOffer* poffer = exodus::DEx_getOffer(address, propertyId);
    if (poffer == NULL) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to load sell offer from the distributed exchange");
    }
    if (poffer->getBlockTimeLimit() < 10) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Payment window is less than 10 blocks (use override = true to continue)");
    }
}

void RequireSaneDExFee(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    const CMPOffer* poffer = exodus::DEx_getOffer(address, propertyId);
    if (poffer == NULL) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to load sell offer from the distributed exchange");
    }
    if (poffer->getMinFee() > 1000000) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Minimum accept fee is higher than 0.01 XZC (use override = true to continue)");
    }
}

void RequireHeightInChain(int blockHeight)
{
    if (blockHeight < 0 || exodus::GetHeight() < blockHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height is out of range");
    }
}

void RequireSigmaStatus(SigmaStatus status)
{
    if (!exodus::IsSigmaStatusValid(status)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Sigma status is not valid");
    }

    if (!exodus::IsFeatureActivated(exodus::FEATURE_SIGMA, exodus::GetHeight())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Sigma feature is not activated yet");
    }
}

namespace exodus {

void RequireSigma(PropertyId property)
{
    if (!IsFeatureActivated(FEATURE_SIGMA, GetHeight())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Sigma feature is not activated yet");
    }

    if (!IsSigmaEnabled(property)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property has not enabled Sigma");
    }
}

void RequireExistingDenomination(PropertyId property, SigmaDenomination denomination)
{
    if (!IsDenominationValid(property, denomination)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Denomination is not valid");
    }
}

}
