// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "client-api/protocol.h"
#include "univalue.h"
#include <string>

using namespace std;

UniValue JSONAPIReplyObj(const UniValue& result, const UniValue& error)
{
    UniValue reply(UniValue::VOBJ);
    UniValue status(UniValue::VOBJ);
    if (!error.isNull()){
        reply.push_back(Pair("data", NullUniValue));
        status.push_back(Pair("status", 400));
    }
    else {
        reply.push_back(Pair("data", result));
        status.push_back(Pair("status", 200));
    }
    reply.push_back(Pair("meta", status));
    reply.push_back(Pair("error", error));
    return reply;
}

std::string JSONAPIReply(const UniValue& result, const UniValue& error)
{
    UniValue reply = JSONAPIReplyObj(result, error);
    return reply.write() + "\n";
}

UniValue JSONAPIError(int code, const std::string& message)
{
    UniValue error(UniValue::VOBJ);
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}