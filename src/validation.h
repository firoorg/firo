// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "protocol.h" // For CMessageHeader::MessageStartChars
#include "script/script_error.h"
#include "sync.h"
#include "versionbits.h"

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <atomic>

#include <boost/unordered_map.hpp>
#include <boost/filesystem/path.hpp>

