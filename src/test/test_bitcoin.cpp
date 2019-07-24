// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#if defined(HAVE_CONFIG_H)
#include "../config/bitcoin-config.h"
#endif

#include "test_bitcoin.h"

#include "util.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"

#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#ifdef ENABLE_EXODUS
#include "../exodus/exodus.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>
#include "zerocoin.h"
#include "zerocoin_v3.h"

extern bool fPrintToConsole;
extern void noui_connect();

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
{
    SoftSetBoolArg("-dandelion", false);
    ECC_Start();
    SetupEnvironment();
    SoftSetBoolArg("-dandelion", false);
    SetupNetworking();
    SoftSetBoolArg("-dandelion", false);
    fPrintToDebugLog = false; // don't want to write to debug.log file
    fCheckBlockIndex = true;
    SoftSetBoolArg("-dandelion", false);
    SelectParams(chainName);
    SoftSetBoolArg("-dandelion", false);
    noui_connect();
}

BasicTestingSetup::~BasicTestingSetup()
{
        ECC_Stop();
}

TestingSetup::TestingSetup(const std::string& chainName, std::string suf) : BasicTestingSetup(chainName)
{
    const CChainParams& chainparams = Params();
        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.
        CZerocoinState::GetZerocoinState()->Reset();
        CZerocoinState::GetZerocoinState()->Reset();
        RegisterAllCoreRPCCommands(tableRPC);
        ClearDatadirCache();
        pathTemp = GetTempPath() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        mempool.setSanityCheck(1.0);
        pblocktree = new CBlockTreeDB(1 << 20, true);
        pcoinsdbview = new CCoinsViewDB(1 << 23, true);
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        pwalletMain = new CWallet(string("wallet_test.dat"));
        static bool fFirstRun = true;
        pwalletMain->LoadWallet(fFirstRun);
        InitBlockIndex(chainparams);
        {
            CValidationState state;
            bool ok = ActivateBestChain(state, chainparams);
            BOOST_CHECK(ok);
        }
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        RegisterNodeSignals(GetNodeSignals());

        // Init HD mint

        // Create new keyUser and set as default key
        // generate a new master key
        CPubKey masterPubKey = pwalletMain->GenerateNewHDMasterKey();
        pwalletMain->SetHDMasterKey(masterPubKey);
        CPubKey newDefaultKey;
        if (pwalletMain->GetKeyFromPool(newDefaultKey)) {
            pwalletMain->SetDefaultKey(newDefaultKey);
            pwalletMain->SetAddressBook(pwalletMain->vchDefaultKey.GetID(), "", "receive");
        }

        pwalletMain->SetBestChain(chainActive.GetLocator());

        zwalletMain = new CHDMintWallet(pwalletMain->strWalletFile);
        zwalletMain->GetTracker().Init();
        zwalletMain->LoadMintPoolFromDB();
        zwalletMain->SyncWithChain();
}

TestingSetup::~TestingSetup()
{
    UnregisterNodeSignals(GetNodeSignals());
#ifdef ENABLE_EXODUS
    exodus_shutdown();
#endif
    threadGroup.interrupt_all();
    threadGroup.join_all();
    UnloadBlockIndex();
    delete pwalletMain;
    pwalletMain = NULL;
    delete pcoinsTip;
    delete pcoinsdbview;
    delete pblocktree;
	try {
		boost::filesystem::remove_all(pathTemp);
	}
	catch(...) {
		try {
			MilliSleep(100);
			boost::filesystem::remove_all(std::wstring(L"\\\\?\\") + pathTemp.wstring());
		}
		catch(...) {

		}
	}
    bitdb.RemoveDb("wallet_test.dat");
    bitdb.Reset();
}

TestChain100Setup::TestChain100Setup() : TestingSetup(CBaseChainParams::REGTEST)
{
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(b.vtx[0]);
    }
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock
TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey, {});
    CBlock& block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    BOOST_FOREACH(const CMutableTransaction& tx, txns)
        block.vtx.push_back(tx);
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){

        ++block.nNonce;


}
    CValidationState state;
    ProcessNewBlock(state, chainparams, NULL, &block, true, NULL, false);

    CBlock result = block;
    delete pblocktemplate;
    return result;
}

TestChain100Setup::~TestChain100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(CMutableTransaction &tx, CTxMemPool *pool) {
    CTransaction txn(tx);
    return FromTx(txn, pool);
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(CTransaction &txn, CTxMemPool *pool) {
    bool hasNoDependencies = pool ? pool->HasNoInputsOf(txn) : hadNoDependencies;
    // Hack to assume either its completely dependent on other mempool txs or not at all
    CAmount inChainValue = hasNoDependencies ? txn.GetValueOut() : 0;

    return CTxMemPoolEntry(txn, nFee, nTime, dPriority, nHeight,
                           hasNoDependencies, inChainValue, spendsCoinbase, sigOpCost, lp);
}
/*
void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

bool ShutdownRequested()
{
  return false;
}*/
