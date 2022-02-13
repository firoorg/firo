// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::DEVNET = "dev";
const std::string CBaseChainParams::REGTEST = "regtest";
const std::string CBaseChainParams::REGTEST_QL = "regtest-ql";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    strUsage += HelpMessageOpt("-devnet", _("Use the dev chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
        strUsage += HelpMessageOpt("-regtest-ql", "Like -regtest but with Lelantus transactions starting at block 1");
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nAPIAddr = "tcp://127.0.0.1:";
        nAPIAuthREPPort = 15557;
        nAPIOpenREPPort = 25558;
        nAPIAuthPUBPort = 18332;
        nAPIOpenPUBPort = 28333;
        nRPCPort = 8888;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nAPIAddr = "tcp://127.0.0.1:";
        nAPIAuthREPPort = 25557;
        nAPIOpenREPPort = 25558;
        nAPIAuthPUBPort = 28332;
        nAPIOpenPUBPort = 28333;
        nRPCPort = 18888;
        strDataDir = "testnet3";
    }
};
static CBaseTestNetParams testNetParams;

/**
 * Devnet
 */
class CBaseDevNetParams : public CBaseChainParams
{
public:
    CBaseDevNetParams()
    {
        nRPCPort = 38888;
        strDataDir = "devnet";
    }
};
static CBaseDevNetParams devNetParams;

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nAPIAddr = "tcp://127.0.0.1:";
        nAPIAuthREPPort = 35557;
        nAPIOpenREPPort = 25558;
        nAPIAuthPUBPort = 38332;
        nAPIOpenPUBPort = 28333;
        nRPCPort = 28888;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

class CBaseRegTestQlParams : public CBaseRegTestParams
{
public:
    CBaseRegTestQlParams()
    {
        strDataDir = "regtest-ql";
    }
};
static CBaseRegTestQlParams regTestQlParams;

static CBaseChainParams* pCurrentBaseParams = 0;

const CBaseChainParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CBaseChainParams& BaseParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::DEVNET)
        return devNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else if (chain == CBaseChainParams::REGTEST_QL)
        return regTestQlParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    pCurrentBaseParams = &BaseParams(chain);
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fRegTestQl = GetBoolArg("-regtest-ql", false);
    bool fDevNet = GetBoolArg("-devnet", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if ((int)fTestNet + (int)fDevNet + (int)fRegTest > 1)
        throw std::runtime_error("Invalid combination of -regtest, -devnet and -testnet.");
    if (fRegTestQl)
        return CBaseChainParams::REGTEST_QL;
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fDevNet)
        return CBaseChainParams::DEVNET;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}

std::string ChainNameFromCommandLineAPI()
{
    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
        , regTestQl = GetOptBoolArg("-regtest-ql")
        , testNet = GetOptBoolArg("-testnet")
        , mainNet = GetOptBoolArg("-mainnet");

    if ((int)!!(regTest && *regTest) + (int)!!(regTestQl && *regTestQl) + (int)!!(testNet && *testNet) + (int)!!(mainNet && *mainNet) > 1)
        throw std::runtime_error("Invalid combination of network flags (-mainnet, -testnet, -regtest-ql, and -regtest)");
    if (regTestQl && *regTestQl)
        return CBaseChainParams::REGTEST_QL;
    if (regTest && *regTest)
        return CBaseChainParams::REGTEST;
    if (testNet && *testNet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}

#ifdef ENABLE_CLIENTAPI
bool IsZMQPort(int64_t port){
    return (port == pCurrentBaseParams->APIAuthREPPort() ||
            port == pCurrentBaseParams->APIOpenREPPort() ||
            port == pCurrentBaseParams->APIAuthPUBPort() ||
            port == pCurrentBaseParams->APIOpenPUBPort());
}
#endif

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
