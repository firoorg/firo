// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <map>
#include "client-api/zmqconfig.h"

#ifndef BITCOIN_ZMQAPI_ZMQ_H
#define BITCOIN_ZMQAPI_ZMQ_H

/** Start REQ/REP ZMQ subsystem.
 * Precondition; REQ/REP ZMQ has been started.
 */
bool StartREQREPZMQ();
/** Interrupt REQ/REP ZMQ subsystem.
 */
void InterruptREQREPZMQ();
/** Stop HTTP RPC subsystem.
 * Precondition; REQ/REP ZMQ has been stopped.
 */
void StopREQREPZMQ();

/* TODO new function layout */

#endif // BITCOIN_ZMQAPI_ZMQ_H
