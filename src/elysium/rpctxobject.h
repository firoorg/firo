#ifndef ELYSIUM_RPCTXOBJECT_H
#define ELYSIUM_RPCTXOBJECT_H

#include <univalue.h>

#include <string>

class uint256;
class CMPTransaction;
class CTransaction;

int populateRPCTransactionObject(const uint256& txid, UniValue& txobj, std::string filterAddress = "", bool extendedDetails = false, std::string extendedDetailsFilter = "");
int populateRPCTransactionObject(const CTransaction& tx, const uint256& blockHash, UniValue& txobj, std::string filterAddress = "", bool extendedDetails = false, std::string extendedDetailsFilter = "", int blockHeight = 0);

void populateRPCTypeInfo(CMPTransaction& mp_obj, UniValue& txobj, uint32_t txType, bool extendedDetails, std::string extendedDetailsFilter, int confirmations);

void populateRPCTypeSimpleSend(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeSendToOwners(CMPTransaction& exodusObj, UniValue& txobj, bool extendedDetails, std::string extendedDetailsFilter);
void populateRPCTypeSendAll(CMPTransaction& exodusObj, UniValue& txobj, int confirmations);
void populateRPCTypeTradeOffer(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeMetaDExTrade(CMPTransaction& exodusObj, UniValue& txobj, bool extendedDetails);
void populateRPCTypeMetaDExCancelPrice(CMPTransaction& exodusObj, UniValue& txobj, bool extendedDetails);
void populateRPCTypeMetaDExCancelPair(CMPTransaction& exodusObj, UniValue& txobj, bool extendedDetails);
void populateRPCTypeMetaDExCancelEcosystem(CMPTransaction& exodusObj, UniValue& txobj, bool extendedDetails);
void populateRPCTypeAcceptOffer(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeCreatePropertyFixed(CMPTransaction& exodusObj, UniValue& txobj, int confirmations);
void populateRPCTypeCreatePropertyVariable(CMPTransaction& exodusObj, UniValue& txobj, int confirmations);
void populateRPCTypeCreatePropertyManual(CMPTransaction& exodusObj, UniValue& txobj, int confirmations);
void populateRPCTypeCloseCrowdsale(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeGrant(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeRevoke(CMPTransaction& exodusOobj, UniValue& txobj);
void populateRPCTypeChangeIssuer(CMPTransaction& exodusObj, UniValue& txobj);
void populateRPCTypeActivation(CMPTransaction& exodusObj, UniValue& txobj);

void populateRPCExtendedTypeSendToOwners(const uint256 txid, std::string extendedDetailsFilter, UniValue& txobj, uint16_t version);
void populateRPCExtendedTypeMetaDExTrade(const uint256& txid, uint32_t propertyIdForSale, int64_t amountForSale, UniValue& txobj);
void populateRPCExtendedTypeMetaDExCancel(const uint256& txid, UniValue& txobj);

int populateRPCDExPurchases(const CTransaction& wtx, UniValue& purchases, std::string filterAddress);
int populateRPCSendAllSubSends(const uint256& txid, UniValue& subSends);

bool showRefForTx(uint32_t txType);

#endif // ELYSIUM_RPCTXOBJECT_H
