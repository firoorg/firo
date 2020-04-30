#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <vector>
#include <iostream>

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "zerocoin.h"

#include "test/testutil.h"
#include "test/fixtures.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include "zerocoin.h"
#include "sigma.h"


ZerocoinTestingSetupBase::ZerocoinTestingSetupBase():
    TestingSetup(CBaseChainParams::REGTEST, "1") {
    // Crean sigma state, just in case someone forgot to do so.
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    sigmaState->Reset();

    // Also clean up old zerocoin state.
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    zerocoinState->Reset();
};

ZerocoinTestingSetupBase::~ZerocoinTestingSetupBase() {
    // Clean sigma state after us.
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    sigmaState->Reset();

    // Also clean up old zerocoin state.
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    zerocoinState->Reset();

}

CBlock ZerocoinTestingSetupBase::CreateBlock(const CScript& scriptPubKey) {
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock block = pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
        ++block.nNonce;
    }

    return block;
}

bool ZerocoinTestingSetupBase::ProcessBlock(const CBlock &block) {
    const CChainParams& chainparams = Params();
    return ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block), true, NULL);
}

// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
CBlock ZerocoinTestingSetupBase::CreateAndProcessBlock(const CScript& scriptPubKey) {
    CBlock block = CreateBlock(scriptPubKey);
    BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
    return block;
}

void ZerocoinTestingSetupBase::CreateAndProcessEmptyBlocks(size_t block_numbers, const CScript& script) {
    while (block_numbers--) {
        CreateAndProcessBlock(script);
    }
}

 ZerocoinTestingSetup200::ZerocoinTestingSetup200()
    {
        BOOST_CHECK(pwalletMain->GetKeyFromPool(pubkey));

        string strAddress = CBitcoinAddress(pubkey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        //Mine 200 blocks so that we have funds for creating mints and we are over these limits:
        //mBlockHeightConstants["ZC_V1_5_STARTING_BLOCK"] = 150;
        //mBlockHeightConstants["ZC_CHECK_BUG_FIXED_AT_BLOCK"] = 140;
        // Since sigma V3 implementation also over consensus.nMintV3SigmaStartBlock = 180;

        scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
        for (int i = 0; i < 200; i++)
        {
            CBlock b = CreateAndProcessBlock(scriptPubKey);
            coinbaseTxns.push_back(*b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(*b.vtx[0], chainActive.Tip(), 0, true);
            }
        }

    }


 ZerocoinTestingSetup109::ZerocoinTestingSetup109()
    {
        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        scriptPubKey = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        for (int i = 0; i < 109; i++)
        {
            CBlock b = CreateAndProcessBlock(scriptPubKey);
            coinbaseTxns.push_back(*b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(*b.vtx[0], chainActive.Tip(), 0, true);
            }
        }

    }

MtpMalformedTestingSetup::MtpMalformedTestingSetup()
{
    CPubKey newKey;
    BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

    string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
    pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                            ( "receive"));

    scriptPubKey = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
    bool mtp = false;
    CBlock b;
    for (int i = 0; i < 150; i++)
    {
        b = CreateAndProcessBlock(scriptPubKey, mtp);
        coinbaseTxns.push_back(*b.vtx[0]);
        LOCK(cs_main);
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->AddToWalletIfInvolvingMe(*b.vtx[0], chainActive.Tip(), 0, true);
        }
    }
}

CBlock MtpMalformedTestingSetup::CreateBlock(
    const CScript& scriptPubKeyMtpMalformed, bool mtp = false) {
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKeyMtpMalformed);
    CBlock block = pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
        ++block.nNonce;
    }
    if(mtp) {
        while (!CheckMerkleTreeProof(block, chainparams.GetConsensus())){
            block.mtpHashValue = mtp::hash(block, Params().GetConsensus().powLimit);
        }
    }
    else {
        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
            ++block.nNonce;
        }
    }

    //delete pblocktemplate;
    return block;
}

// Create a new block with just given transactions, coinbase paying to
// scriptPubKeyMtpMalformed, and try to add it to the current chain.
CBlock MtpMalformedTestingSetup::CreateAndProcessBlock(
        const CScript& scriptPubKeyMtpMalformed,
        bool mtp = false) {

    CBlock block = CreateBlock(scriptPubKeyMtpMalformed, mtp);
    BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
    return block;
}

LelantusTestingSetup::LelantusTestingSetup() :
    params(lelantus::Params::get_default()) {
    CPubKey key;
    {
        LOCK(pwalletMain->cs_wallet);
        key = pwalletMain->GenerateNewKey();
    }

    script = GetScriptForDestination(key.GetID());
}

CBlockIndex* LelantusTestingSetup::GenerateBlock(std::vector<CMutableTransaction> const &txns) {
    auto last = chainActive.Tip();

    CreateAndProcessBlock(txns, script);
    auto block = chainActive.Tip();

    if (block != last) {
        pwalletMain->ScanForWalletTransactions(block, true);
    }

    return block != last ? block : nullptr;
}

void LelantusTestingSetup::GenerateBlocks(size_t blocks) {
    while (--blocks) {
        GenerateBlock();
    }
}

std::vector<CHDMint> LelantusTestingSetup::GenerateMints(
    std::vector<CAmount> const &amounts,
    std::vector<CMutableTransaction> &txs,
    bool useHdMints) {

    std::vector<CHDMint> mints;

    for (auto a : amounts) {
        lelantus::PrivateCoin coin(params, a);

        if (useHdMints) {
            CHDMint hdmint;
            zwalletMain->GenerateLelantusMint(coin, hdmint);
        }

        mints.emplace_back();
        auto &mint = mints.back();

        auto rec = CWallet::CreateLelantusMintRecipient(coin, mint);

        CWalletTx wtx;
        auto result = pwalletMain->MintAndStoreLelantus(rec, coin, mint, wtx);
        txs.emplace_back(wtx);

        if (useHdMints) {
            zwalletMain->GetTracker().AddLelantus(mint, true);
        }

        if (result != "") {
            throw std::runtime_error("Fail to generate mints " + result);
        }
    }

    return mints;
}

CPubKey LelantusTestingSetup::GenerateAddress() {
    LOCK(pwalletMain->cs_wallet);
    return pwalletMain->GenerateNewKey();
}