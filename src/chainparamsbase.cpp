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
const std::string CBaseChainParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
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
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    pCurrentBaseParams = &BaseParams(chain);
}

std::string ChainNameFromCommandLine()
{
    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
        , testNet = GetOptBoolArg("-testnet");

    if (testNet && regTest && *testNet && *regTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (regTest && *regTest)
        return CBaseChainParams::REGTEST;
    if (testNet && *testNet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
