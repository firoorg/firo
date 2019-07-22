// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqabstract.h"
#include <fstream>
#include "util.h"
#include <boost/filesystem/operations.hpp>
#include "zmqconfig.h"
#include "univalue.h"

using namespace std;


CZMQAbstract::~CZMQAbstract()
{
    assert(!psocket);
}

bool CZMQAbstract::NotifyBlock(const CBlockIndex * /*CBlockIndex*/)
{
    return true;
}

bool CZMQAbstract::NotifyTransaction(const CTransaction &/*transaction*/)
{
    return true;
}

bool CZMQAbstract::NotifyConnections()
{
    return true;
}

bool CZMQAbstract::NotifyStatus()
{
    return true;
}

bool CZMQAbstract::NotifyAPIStatus()
{
    return true;
}

bool CZMQAbstract::NotifyZnodeUpdate(CZnode &znode)
{
    return true;
}

bool CZMQAbstract::NotifyMintStatusUpdate(std::string update)
{
    return true;
}

bool CZMQAbstract::NotifySettingsUpdate(std::string update)
{
    return true;
}

bool CZMQAbstract::SendMultipart(const void* data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void*);

        rc = zmq_msg_send(&msg, psocket, data ? ZMQ_SNDMORE : 0);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    return 0;
}

bool CZMQAbstract::SendMessage()
{
    assert(psocket);

    /* send three parts, command & data & a LE 4byte sequence number */
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(&msgseq[0], nSequence);
    int rc;
    if(!(topic.empty())){
        rc = SendMultipart(topic.c_str(), topic.length(), message.c_str(), message.length(), msgseq, (size_t)sizeof(uint32_t), (void*)0);
    }else{
        rc = SendMultipart(message.c_str(), message.length(), msgseq, (size_t)sizeof(uint32_t), (void*)0);
    }

    if (rc == -1)
        return false;

    /* increment memory only sequence number after sending */
    nSequence++;

    return true;
}

string CZMQAbstract::GetAuthType(KeyType type){
    return (type == Server) ? "server" : "client";
}

bool CZMQAbstract::WriteCert(string publicKey, string privateKey, KeyType type, bool reset){

    boost::filesystem::path cert = GetDataDir(true) / "certificates" / GetAuthType(type);

    LogPrintf("ZMQ: path @ write: %s\n", cert.string());

    LogPrintf("reset: %s\n", reset);
    if (!boost::filesystem::exists(cert) || reset) {
        boost::filesystem::create_directories(cert);
    
        cert /= "keys.json";

        UniValue certUni(UniValue::VOBJ);
        UniValue data(UniValue::VOBJ);

        data.push_back(Pair("public",publicKey));
        data.push_back(Pair("private",privateKey));

        LogPrintf("data write: %s\n", data.write());

        certUni.push_back(Pair("type","keys"));
        certUni.push_back(Pair("data", data));

        LogPrintf("ZMQ: cert json: %s\n", certUni.write());

        // write keys to fs
        std::ofstream certOut(cert.string());
        certOut << certUni.write(4,0) << std::endl;
    }

    return true;
}

vector<string> CZMQAbstract::ReadCert(KeyType type){
    boost::filesystem::path cert = GetDataDir(true) / "certificates" / GetAuthType(type) / "keys.json"; 

    LogPrintf("ZMQ: path @ read: %s\n", cert.string());

    std::ifstream certIn(cert.string());

    // parse as std::string
    std::string certStr((std::istreambuf_iterator<char>(certIn)), std::istreambuf_iterator<char>());

    UniValue certUni(UniValue::VOBJ);
    certUni.read(certStr);

    UniValue certUniData(UniValue::VOBJ);
    certUniData = certUni["data"];

    vector<string> result;

    result.push_back(find_value(certUniData,"public").get_str());
    result.push_back(find_value(certUniData,"private").get_str());

    return result;
}

bool CZMQAbstract::CreateCerts(bool reset){
    // Generate client/server keys for auth over zmq.
    char serverPublicKey[41], serverSecretKey[41];
    char clientPublicKey[41], clientSecretKey[41];
    zmq_curve_keypair(serverPublicKey, serverSecretKey);
    zmq_curve_keypair(clientPublicKey, clientSecretKey);

    WriteCert(serverPublicKey, serverSecretKey, Server, reset);
    WriteCert(clientPublicKey, clientSecretKey, Client, reset);

    return true;
}