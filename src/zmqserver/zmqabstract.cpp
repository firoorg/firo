// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqabstract.h"
#include <fstream>
#include "util.h"
#include <boost/filesystem/operations.hpp>
#include <univalue.h>

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

string CZMQAbstract::GetAuthType(KeyType type){
    return (type == Server) ? "server" : "client";
}

bool CZMQAbstract::writeCert(string publicKey, string privateKey, KeyType type){

    boost::filesystem::path cert = GetDataDir(true) / "certificates" / GetAuthType(type);

    LogPrintf("ZMQ: path @ write: %s\n", cert.string());

    if (!boost::filesystem::exists(cert)) {
        boost::filesystem::create_directories(cert);
    }

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

    return true;
}

vector<string> CZMQAbstract::readCert(KeyType type){
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

bool CZMQAbstract::createCerts(){
    // Generate client/server keys for auth over zmq.
    char serverPublicKey[41], serverSecretKey[41];
    char clientPublicKey[41], clientSecretKey[41];
    zmq_curve_keypair(serverPublicKey, serverSecretKey);
    zmq_curve_keypair(clientPublicKey, clientSecretKey);

    writeCert(serverPublicKey, serverSecretKey, Server);
    writeCert(clientPublicKey, clientSecretKey, Client);

    return true;
}