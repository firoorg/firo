// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <map>
#include "client-api/zmqconfig.h"
#include <univalue.h>
#include <client-api/json.hpp>

using json = nlohmann::json;

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

static const bool DEV_AUTH = false;

//UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams);

UniValue SetupRPC(std::vector<std::string> args);

json response_to_json(UniValue reply);
json finalize_json(json request, bool errored);

/* Get all transactions related to the wallet from block "block". */
json WalletDataSinceBlock(string block);

/* Setup a port for an auth/noauth port */
bool SetupType(int type);

/* read certificate from datadir certificate folder. */
vector<string> read_cert(string type);

/* write certificate to datadir certificate folder. */
void write_cert(string public_key, string private_key, string type);

//UniValue CallRPC(const string& strMethod, const UniValue& params);

//static void http_request_done(struct evhttp_request *req, void *ctx);

/* TODO new function layout */

#endif // BITCOIN_ZMQAPI_ZMQ_H
