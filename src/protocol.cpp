// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "util.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

namespace NetMsgType {
    const char *VERSION="version";
    const char *VERACK="verack";
    const char *ADDR="addr";
    const char *INV="inv";
    const char *GETDATA="getdata";
    const char *MERKLEBLOCK="merkleblock";
    const char *GETBLOCKS="getblocks";
    const char *GETHEADERS="getheaders";
    const char *TX="tx";
    const char *HEADERS="headers";
    const char *BLOCK="block";
    const char *GETADDR="getaddr";
    const char *MEMPOOL="mempool";
    const char *PING="ping";
    const char *PONG="pong";
    const char *NOTFOUND="notfound";
    const char *FILTERLOAD="filterload";
    const char *FILTERADD="filteradd";
    const char *FILTERCLEAR="filterclear";
    const char *REJECT="reject";
    const char *SENDHEADERS="sendheaders";
    const char *FEEFILTER="feefilter";
    const char *SENDCMPCT="sendcmpct";
    const char *CMPCTBLOCK="cmpctblock";
    const char *GETBLOCKTXN="getblocktxn";
    const char *BLOCKTXN="blocktxn";
    const char *DANDELIONTX="dandeliontx";
    const char *SYNCSTATUSCOUNT="ssc";
    const char *GETMNLISTDIFF="getmnlistd";
    const char *MNLISTDIFF="mnlistdiff";
    const char *QSENDRECSIGS="qsendrecsigs";
    const char *QFCOMMITMENT="qfcommit";
    const char *QCONTRIB="qcontrib";
    const char *QCOMPLAINT="qcomplaint";
    const char *QJUSTIFICATION="qjustify";
    const char *QPCOMMITMENT="qpcommit";
    const char *QWATCH="qwatch";
    const char *QSIGSESANN="qsigsesann";
    const char *QSIGSHARESINV="qsigsinv";
    const char *QGETSIGSHARES="qgetsigs";
    const char *QBSIGSHARES="qbsigs";
    const char *QSIGREC="qsigrec";
    const char *CLSIG="clsig";
    const char *ISLOCK="islock";
    const char *MNAUTH="mnauth";
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION,
    NetMsgType::VERACK,
    NetMsgType::ADDR,
    NetMsgType::INV,
    NetMsgType::GETDATA,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETHEADERS,
    NetMsgType::TX,
    NetMsgType::HEADERS,
    NetMsgType::BLOCK,
    NetMsgType::GETADDR,
    NetMsgType::MEMPOOL,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::NOTFOUND,
    NetMsgType::FILTERLOAD,
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::REJECT,
    NetMsgType::SENDHEADERS,
    NetMsgType::FEEFILTER,
    NetMsgType::SENDCMPCT,
    NetMsgType::CMPCTBLOCK,
    NetMsgType::GETBLOCKTXN,
    NetMsgType::BLOCKTXN,
    NetMsgType::DANDELIONTX,
    //znode
    NetMsgType::GETMNLISTDIFF,
    NetMsgType::MNLISTDIFF,
    NetMsgType::SYNCSTATUSCOUNT,
    NetMsgType::QSENDRECSIGS,
    NetMsgType::QFCOMMITMENT,
    NetMsgType::QCONTRIB,
    NetMsgType::QCOMPLAINT,
    NetMsgType::QJUSTIFICATION,
    NetMsgType::QPCOMMITMENT,
    NetMsgType::QWATCH,
    NetMsgType::QSIGSESANN,
    NetMsgType::QSIGSHARESINV,
    NetMsgType::QGETSIGSHARES,
    NetMsgType::QBSIGSHARES,
    NetMsgType::QSIGREC,
    NetMsgType::CLSIG,
    NetMsgType::ISLOCK,
    NetMsgType::MNAUTH,
};
const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes+ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageStartChars& pchMessageStartIn) const
{
    // Check start string
    if (memcmp(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}



CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NONE;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

std::string CInv::GetCommand() const
{
    std::string cmd;
    if (type & MSG_WITNESS_FLAG)
        cmd.append("witness-");
    FIRO_UNUSED int masked = type & MSG_TYPE_MASK;
    // TODO: switch(masked)
    switch (type)
    {
    case MSG_TX:             return cmd.append(NetMsgType::TX);
    case MSG_BLOCK:          return cmd.append(NetMsgType::BLOCK);
    case MSG_FILTERED_BLOCK: return cmd.append(NetMsgType::MERKLEBLOCK);
    case MSG_CMPCT_BLOCK:    return cmd.append(NetMsgType::CMPCTBLOCK);
    case MSG_DANDELION_TX:   return cmd.append(NetMsgType::DANDELIONTX);

    case MSG_QUORUM_FINAL_COMMITMENT:       return cmd.append(NetMsgType::QFCOMMITMENT);
    case MSG_QUORUM_CONTRIB:                return cmd.append(NetMsgType::QCONTRIB);
    case MSG_QUORUM_COMPLAINT:              return cmd.append(NetMsgType::QCOMPLAINT);
    case MSG_QUORUM_JUSTIFICATION:          return cmd.append(NetMsgType::QJUSTIFICATION);
    case MSG_QUORUM_PREMATURE_COMMITMENT:   return cmd.append(NetMsgType::QPCOMMITMENT);
    case MSG_QUORUM_RECOVERED_SIG:          return cmd.append(NetMsgType::QSIGREC);
    case MSG_CLSIG:                         return cmd.append(NetMsgType::CLSIG);
    case MSG_ISLOCK:                        return cmd.append(NetMsgType::ISLOCK);
    default:
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch(const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string> &getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}
