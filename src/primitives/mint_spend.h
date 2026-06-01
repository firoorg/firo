// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRIMITIVES_MINT_SPEND_H
#define PRIMITIVES_MINT_SPEND_H

#include <amount.h>
#include <streams.h>
#include <boost/optional.hpp>
#include <limits.h>
#include "key.h"
#include "serialize.h"
#include "firo_params.h"
#include "../secp256k1/include/GroupElement.h"

namespace primitives {
uint256 GetSerialHash(const secp_primitives::Scalar& bnSerial);
uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue);
}

#endif //PRIMITIVES_MINT_SPEND_H
