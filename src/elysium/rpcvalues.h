#ifndef FIRO_ELYSIUM_RPCVALUES_H
#define FIRO_ELYSIUM_RPCVALUES_H

class CPubKey;
class CTransaction;
struct CMutableTransaction;
struct PrevTxsEntry;

#include "sigmaprimitives.h"

#include <univalue.h>

#include <string>
#include <vector>

#include <inttypes.h>

std::string ParseAddress(const UniValue& value);
std::string ParseAddressOrEmpty(const UniValue& value);
std::string ParseAddressOrWildcard(const UniValue& value);
uint32_t ParsePropertyId(const UniValue& value);
int64_t ParseAmount(const UniValue& value, bool isDivisible);
int64_t ParseAmount(const UniValue& value, int propertyType);
uint8_t ParseDExPaymentWindow(const UniValue& value);
int64_t ParseDExFee(const UniValue& value);
uint8_t ParseDExAction(const UniValue& value);
uint8_t ParseEcosystem(const UniValue& value);
uint16_t ParsePropertyType(const UniValue& value);
uint32_t ParsePreviousPropertyId(const UniValue& value);
std::string ParseText(const UniValue& value);
int64_t ParseDeadline(const UniValue& value);
uint8_t ParseEarlyBirdBonus(const UniValue& value);
uint8_t ParseIssuerBonus(const UniValue& value);
uint8_t ParseMetaDExAction(const UniValue& value);
CTransaction ParseTransaction(const UniValue& value);
CMutableTransaction ParseMutableTransaction(const UniValue& value);
CPubKey ParsePubKeyOrAddress(const UniValue& value);
uint32_t ParseOutputIndex(const UniValue& value);
/** Parses previous transaction outputs. */
std::vector<PrevTxsEntry> ParsePrevTxs(const UniValue& value);

namespace elysium {

SigmaDenomination ParseSigmaDenomination(const UniValue& value);

}

#endif // FIRO_ELYSIUM_RPCVALUES_H
