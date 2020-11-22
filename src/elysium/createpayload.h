#ifndef ZCOIN_ELYSIUM_CREATEPAYLOAD_H
#define ZCOIN_ELYSIUM_CREATEPAYLOAD_H

#include "../lelantus.h"

#include "ecdsa_signature.h"
#include "lelantusprimitives.h"
#include "sp.h"
#include "sigma.h"

#include <boost/optional.hpp>

#include <string>
#include <vector>

#include <stdint.h>

std::vector<unsigned char> CreatePayload_SimpleSend(uint32_t propertyId, uint64_t amount);
std::vector<unsigned char> CreatePayload_SimpleMint(uint32_t propertyId, const std::vector<std::pair<uint8_t, elysium::SigmaPublicKey>>& mints);
std::vector<unsigned char> CreatePayload_SimpleSpend(uint32_t propertyId, uint8_t denomination, uint32_t group,
                                                    uint16_t groupSize, elysium::SigmaProof const &proof, secp_primitives::Scalar const &serial);
std::vector<unsigned char> CreatePayload_SimpleSpend(uint32_t propertyId, uint8_t denomination, uint32_t group,
                                                    uint16_t groupSize, elysium::SigmaProof const &proof,
                                                    ECDSASignature const &signature, CPubKey const &pubkey);
std::vector<unsigned char> CreatePayload_SendAll(uint8_t ecosystem);
std::vector<unsigned char> CreatePayload_DExSell(uint32_t propertyId, uint64_t amountForSale, uint64_t amountDesired, uint8_t timeLimit, uint64_t minFee, uint8_t subAction);
std::vector<unsigned char> CreatePayload_DExAccept(uint32_t propertyId, uint64_t amount);
std::vector<unsigned char> CreatePayload_SendToOwners(uint32_t propertyId, uint64_t amount, uint32_t distributionProperty);
std::vector<unsigned char> CreatePayload_IssuanceFixed(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data, uint64_t amount,
                                                       boost::optional<SigmaStatus> sigmaStatus = boost::none, boost::optional<LelantusStatus> lelantusStatus = boost::none);
std::vector<unsigned char> CreatePayload_IssuanceVariable(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                          std::string subcategory, std::string name, std::string url, std::string data, uint32_t propertyIdDesired,
                                                          uint64_t amountPerUnit, uint64_t deadline, uint8_t earlyBonus, uint8_t issuerPercentage);
std::vector<unsigned char> CreatePayload_IssuanceManaged(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data,
                                                       boost::optional<SigmaStatus> sigmaStatus = boost::none, boost::optional<LelantusStatus> lelantusStatus = boost::none);
std::vector<unsigned char> CreatePayload_CloseCrowdsale(uint32_t propertyId);
std::vector<unsigned char> CreatePayload_Grant(uint32_t propertyId, uint64_t amount, std::string memo);
std::vector<unsigned char> CreatePayload_Revoke(uint32_t propertyId, uint64_t amount, std::string memo);
std::vector<unsigned char> CreatePayload_ChangeIssuer(uint32_t propertyId);
std::vector<unsigned char> CreatePayload_EnableFreezing(uint32_t propertyId);
std::vector<unsigned char> CreatePayload_DisableFreezing(uint32_t propertyId);
std::vector<unsigned char> CreatePayload_FreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address);
std::vector<unsigned char> CreatePayload_UnfreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address);
std::vector<unsigned char> CreatePayload_MetaDExTrade(uint32_t propertyIdForSale, uint64_t amountForSale, uint32_t propertyIdDesired, uint64_t amountDesired);
std::vector<unsigned char> CreatePayload_MetaDExCancelPrice(uint32_t propertyIdForSale, uint64_t amountForSale, uint32_t propertyIdDesired, uint64_t amountDesired);
std::vector<unsigned char> CreatePayload_MetaDExCancelPair(uint32_t propertyIdForSale, uint32_t propertyIdDesired);
std::vector<unsigned char> CreatePayload_MetaDExCancelEcosystem(uint8_t ecosystem);
std::vector<unsigned char> CreatePayload_ElysiumAlert(uint16_t alertType, uint32_t expiryValue, const std::string& alertMessage);
std::vector<unsigned char> CreatePayload_DeactivateFeature(uint16_t featureId);
std::vector<unsigned char> CreatePayload_ActivateFeature(uint16_t featureId, uint32_t activationBlock, uint32_t minClientVersion);
std::vector<unsigned char> CreatePayload_CreateDenomination(uint32_t propertyId, uint64_t value);
std::vector<unsigned char> CreatePayload_CreateLelantusMint(uint32_t propertyId, lelantus::PublicCoin const &pubcoin, MintEntryId const &id,
                                                            uint64_t value, std::vector<unsigned char> const &schnorrProof);
std::vector<unsigned char> CreatePayload_CreateLelantusJoinSplit(uint32_t propertyId, uint64_t amount,
                                                                 lelantus::JoinSplit const &joinSplit,
                                                                 boost::optional<JoinSplitMint> const &mint);
std::vector<unsigned char> CreatePayload_ChangeLelantusStatus(uint32_t propertyId, LelantusStatus status);

#endif // ZCOIN_ELYSIUM_CREATEPAYLOAD_H
