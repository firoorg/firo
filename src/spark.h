// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _MAIN_SPARK_H__
#define _MAIN_SPARK_H__

#include "libspark/coin.h"
#include "chain.h"

namespace spark {

bool GetOutPoint(COutPoint& outPoint, const spark::Coin coin);

} // namespace spark

#endif //_MAIN_SPARK_H__
