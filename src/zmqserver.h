// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <map>
#include "client-api/zmqconfig.h"
#include <univalue.h>
#include <client-api/json.hpp>

/** Start REQ/REP ZMQ subsystem.
 * Precondition; REQ/REP ZMQ has been started.
 */
bool InitZMQServer();
/** Interrupt REQ/REP ZMQ subsystem.
 */
void InterruptZMQServer();
/** Stop HTTP RPC subsystem.
 * Precondition; REQ/REP ZMQ has been stopped.
 */
void StopZMQServer();

//static const bool DEV_AUTH = false; in zmq.h

//TODO ifndef defines