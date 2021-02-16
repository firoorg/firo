#ifndef ZCOIN_BIP47UTIL_H
#define ZCOIN_BIP47UTIL_H
#include "key.h"
#include <string.h>
#include <vector>
#include <openssl/sha.h>
#include "GroupElement.h"
#include "defs.h"

#define HARDENED_BIT 0x80000000

class COutPoint;
class CTransaction;
typedef class std::shared_ptr<const CTransaction> CTransactionRef;

namespace bip47 {

class CPaymentCode;
class CAccount;

namespace utils {

/******************************************************************************/
std::unique_ptr<CPaymentCode> PcodeFromMaskedPayload(Bytes payload, COutPoint const & outpoint, CKey const & myPrivkey, CPubKey const & outPubkey);
std::unique_ptr<CPaymentCode> PcodeFromMaskedPayload(Bytes payload, unsigned char const * data, size_t dataSize, CKey const & myPrivkey, CPubKey const & outPubkey);
Bytes GetMaskedPcode(CTransactionRef const & tx);
bool GetScriptSigPubkey(CTxIn const & txin, CPubKey& pubkey);
bool GetJsplitPubkey(CTxIn const & jsplitIn, CPubKey& pubkey);

/******************************************************************************/
CExtKey Derive(CExtKey const & source, std::vector<uint32_t> const & path);

/******************************************************************************/
GroupElement GeFromPubkey(CPubKey const & pubKey);
CPubKey PubkeyFromGe(GroupElement const & ge);

} }

#endif // ZCOIN_BIP47UTIL_H
