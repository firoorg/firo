// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Zcoin Test Suite

#if defined(HAVE_CONFIG_H)
#include "../config/bitcoin-config.h"
#endif

#include "test_bitcoin.h"

#include "util.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "net_processing.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/sigcache.h"

#include "test/testutil.h"

#include "wallet/db.h"
#include "wallet/wallet.h"
#include <memory>

#ifdef ENABLE_EXODUS
#include "../exodus/exodus.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>
#include "zerocoin.h"
#include "sigma.h"
#include "evo/evodb.h"
#include "evo/cbtx.h"
#include "evo/specialtx.h"
#include "llmq/quorums_init.h"

extern std::unique_ptr<CConnman> g_connman;
uint256 insecure_rand_seed = GetRandHash();
FastRandomContext insecure_rand_ctx(insecure_rand_seed);

extern bool fPrintToConsole;
extern void noui_connect();
extern CEvoDB* evoDb;

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
{
    ECC_Start();
    SetupEnvironment();
    SetupNetworking();
    InitSignatureCache();
    fPrintToDebugLog = false; // don't want to write to debug.log file
    fCheckBlockIndex = true;
    SelectParams(chainName);
    SoftSetBoolArg("-dandelion", false);
    evoDb = new CEvoDB(1 << 20, true, true);
    deterministicMNManager = new CDeterministicMNManager(*evoDb);
    noui_connect();
}

BasicTestingSetup::~BasicTestingSetup()
{
        delete deterministicMNManager;
        delete evoDb;

        ECC_Stop();
        g_connman.reset();
}

TestingSetup::TestingSetup(const std::string& chainName, std::string suf) : BasicTestingSetup(chainName)
{
    const CChainParams& chainparams = Params();
        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.
        CZerocoinState::GetZerocoinState()->Reset();
        RegisterAllCoreRPCCommands(tableRPC);
        ClearDatadirCache();
        pathTemp = GetTempPath() / strprintf("test_zcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        ForceSetArg("-datadir", pathTemp.string());
        mempool.setSanityCheck(1.0);
        pblocktree = new CBlockTreeDB(1 << 20, true);
        pcoinsdbview = new CCoinsViewDB(1 << 23, true);
        llmq::InitLLMQSystem(*evoDb, nullptr, true);
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
        g_connman = std::unique_ptr<CConnman>(new CConnman(0x1337, 0x1337)); // Deterministic randomness for tests.
        connman = g_connman.get();
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
    llmq::InterruptLLMQSystem();
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

TestChain100Setup::TestChain100Setup(int nBlocks) : TestingSetup(CBaseChainParams::REGTEST)
{
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < nBlocks; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(*b.vtx[0]);
    }
}

CBlock TestChain100Setup::CreateBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;

    std::vector<CTransactionRef> llmqCommitments;
    for (const auto& tx : block.vtx) {
        if (tx->nVersion == 3 && tx->nType == TRANSACTION_QUORUM_COMMITMENT) {
            llmqCommitments.emplace_back(tx);
        }
    }

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    // Re-add quorum commitments
    block.vtx.insert(block.vtx.end(), llmqCommitments.begin(), llmqCommitments.end());
    BOOST_FOREACH(const CMutableTransaction& tx, txns)
        block.vtx.push_back(MakeTransactionRef(tx));

    // Manually update CbTx as we modified the block here
    if (block.vtx[0]->nType == TRANSACTION_COINBASE) {
        LOCK(cs_main);
        CCbTx cbTx;
        if (!GetTxPayload(*block.vtx[0], cbTx)) {
            BOOST_ASSERT(false);
        }
        CValidationState state;
        if (!CalcCbTxMerkleRootMNList(block, chainActive.Tip(), cbTx.merkleRootMNList, state)) {
            BOOST_ASSERT(false);
        }
        if (!CalcCbTxMerkleRootQuorums(block, chainActive.Tip(), cbTx.merkleRootQuorums, state)) {
            BOOST_ASSERT(false);
        }
        CMutableTransaction tmpTx = *block.vtx[0];
        SetTxPayload(tmpTx, cbTx);
        block.vtx[0] = MakeTransactionRef(tmpTx);
    }

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) ++block.nNonce;

    CBlock result = block;
    return result;
}

CBlock TestChain100Setup::CreateBlock(const std::vector<CMutableTransaction>& txns, const CKey& scriptKey)
{
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    return CreateBlock(txns, scriptPubKey);
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock
TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    auto block = CreateBlock(txns, scriptPubKey);

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    ProcessNewBlock(chainparams, shared_pblock, true, NULL);

    CBlock result = block;
    return result;
}

CBlock TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CKey& scriptKey)
{
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    return CreateAndProcessBlock(txns, scriptPubKey);
}

TestChain100Setup::~TestChain100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CMutableTransaction &tx, CTxMemPool *pool) {
    CTransaction txn(tx);
    return FromTx(txn, pool);
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransaction &txn, CTxMemPool *pool) {
    // Hack to assume either it's completely dependent on other mempool txs or not at all
    CAmount inChainValue = pool && pool->HasNoInputsOf(txn) ? txn.GetValueOut() : 0;

    return CTxMemPoolEntry(MakeTransactionRef(txn), nFee, nTime, nHeight,
                           inChainValue, spendsCoinbase, sigOpCost, lp);
}

size_t FindZnodeOutput(CTransaction const & tx) {
    static std::vector<CScript> const founders {
        GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get()),
        GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get()),
        GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get()),
        GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get()),
        GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get()),
    };

    BOOST_CHECK(tx.IsCoinBase());
    for(size_t i = 0; i < tx.vout.size(); ++i) {
        CTxOut const & out = tx.vout[i];
         if(std::find(founders.begin(), founders.end(), out.scriptPubKey) == founders.end()) {
            if(out.nValue == GetZnodePayment(Params().GetConsensus(), false))
                return i;
        }
    }
    throw std::runtime_error("Cannot find the Znode output");
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
