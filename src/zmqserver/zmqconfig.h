// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQCONFIG_H
#define BITCOIN_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <stdarg.h>
#include <string>
#define ZMQ_STATIC
#include <zmq.h>

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "znode.h"

void zmqError(const char *str);

#endif // BITCOIN_ZMQ_ZMQCONFIG_H
