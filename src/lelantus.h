#ifndef _MAIN_LELANTUS_H__
#define _MAIN_LELANTUS_H__

#include "amount.h"
#include "chain.h"
#include "liblelantus/coin.h"
#include "consensus/validation.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "liblelantus/params.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>

namespace lelantus {

bool IsLelantusAllowed();
bool IsLelantusAllowed(int height);

bool IsAvailableToMint(const CAmount& amount);

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, std::vector<unsigned char>&  serializedSchnorrProof);

} // end of namespace lelantus

#endif // _MAIN_LELANTUS_H__
