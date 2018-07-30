// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "chain.h"
#include "zmqreplier.h"
#include "zmqabstract.h"
#include "main.h"
#include "util.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "base58.h"
#include "client-api/json.hpp"
#include "client-api/zmq.h"
#include "zmqserver.h"
#include "znode-sync.h"
#include "net.h"
#include "script/ismine.h"
#include "wallet/wallet.h"
#include "wallet/wallet.cpp"
#include "wallet/rpcwallet.cpp"

using path = boost::filesystem::path;
using json = nlohmann::json;
extern CWallet* pwalletMain;

bool CZMQAbstractReplier::Socket(){
    LogPrintf("ZMQ: setting up type in Socket.\n");
    pcontext = zmq_ctx_new();

    LogPrintf("ZMQ: created pcontext\n");

    psocket = zmq_socket(pcontext,ZMQ_REP);
    if(!psocket){
        //TODO fail
        LogPrintf("ZMQ: Failed to create psocket\n");
        return false;
    }
    return true;
}

bool CZMQAuthReplier::Auth(){
    // set up auth
    vector<string> keys = readCert(CZMQAbstract::Server);

    string server_secret_key = keys.at(1);

    LogPrintf("ZMQ: secret_server_key: %s\n", server_secret_key);

    const int curve_server_enable = 1;
    zmq_setsockopt(psocket, ZMQ_CURVE_SERVER, &curve_server_enable, sizeof(curve_server_enable));
    zmq_setsockopt(psocket, ZMQ_CURVE_SECRETKEY, server_secret_key.c_str(), 40);

    return true;
}

bool CZMQAbstractReplier::Bind(){
    string tcp = "tcp://*:";

    LogPrintf("Port in bind: %s\n", port);

    int rc = zmq_bind(psocket, tcp.append(port).c_str());
    if (rc == -1)
    {
        LogPrintf("ZMQ: Unable to send ZMQ msg\n");
        return false;
    }
    LogPrintf("ZMQ: Bound socket\n");
    return true;
}

bool CZMQAbstractReplier::Initialize()
{
    assert(!psocket);
    //TODO error handling
    Socket();
    Auth();
    Bind();

    return true;
}

void CZMQAbstractReplier::Shutdown()
{
    assert(psocket);

    LogPrint(NULL, "Close socket at address %s\n", address);

    int linger = 0;
    zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(psocket);
    psocket = 0;

    if (pcontext)
    {
        zmq_ctx_destroy(pcontext);
        pcontext = 0;
    }
}