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
#include "sigma/openssl_context.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"

#include "test/testutil.h"
#include "test/fixtures.h"

#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include "sigma.h"
#include "lelantus.h"
#include "../libspark/coin.h"


ZerocoinTestingSetupBase::ZerocoinTestingSetupBase():
    TestingSetup(CBaseChainParams::REGTEST, "1") {
    // Crean sigma state, just in case someone forgot to do so.
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    sigmaState->Reset();
};

ZerocoinTestingSetupBase::~ZerocoinTestingSetupBase() {
    // Clean sigma state after us.
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    sigmaState->Reset();


}

CBlock ZerocoinTestingSetupBase::CreateBlock(const CScript& scriptPubKey) {
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock block = pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
    
    uint256 mix_hash;
    while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, chainparams.GetConsensus())) {
        ++block.nNonce64;
        ++block.nNonce;
        if(!(block.nNonce64 % 5000)) {
            BOOST_TEST_MESSAGE(std::to_string(block.nNonce64));
        }
    }
    block.mix_hash = mix_hash;
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

        std::string strAddress = CBitcoinAddress(pubkey.GetID()).ToString();
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

        std::string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
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

    std::string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
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

CBlockIndex* LelantusTestingSetup::GenerateBlock(std::vector<CMutableTransaction> const &txns, CScript *script) {
    auto last = chainActive.Tip();

    CreateAndProcessBlock(txns, script ? *script : this->script);
    auto block = chainActive.Tip();

    if (block != last) {
        pwalletMain->ScanForWalletTransactions(block, true);
    }

    return block != last ? block : nullptr;
}

void LelantusTestingSetup::GenerateBlocks(size_t blocks, CScript *script) {
    while (blocks--) {
        GenerateBlock({}, script);
    }
}

std::vector<lelantus::PrivateCoin> LelantusTestingSetup::GenerateMints(
    std::vector<CAmount> const &amounts) {

    auto const &p = lelantus::Params::get_default();

    std::vector<lelantus::PrivateCoin> coins;
    for (auto a : amounts) {
        std::vector<unsigned char> k(32);
        GetRandBytes(k.data(), k.size());

        secp256k1_pubkey pubkey;

        if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, k.data())) {
            throw std::runtime_error("Fail to create public key");
        }

        auto serial = lelantus::PrivateCoin::serialNumberFromSerializedPublicKey(
            OpenSSLContext::get_context(), &pubkey);

        Scalar randomness;
        randomness.randomize();

        coins.emplace_back(p, serial, a, randomness, k, 0);
    }

    return coins;
}

std::vector<CHDMint> LelantusTestingSetup::GenerateMints(
    std::vector<CAmount> const &amounts,
    std::vector<CMutableTransaction> &txs) {

    std::vector<lelantus::PrivateCoin> coins;
    return GenerateMints(amounts, txs, coins);
}

std::vector<CHDMint> LelantusTestingSetup::GenerateMints(
    std::vector<CAmount> const &amounts,
    std::vector<CMutableTransaction> &txs,
    std::vector<lelantus::PrivateCoin> &coins) {

    std::vector<CHDMint> hdMints;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    for (auto a : amounts) {
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        std::vector<CHDMint> mints;
        auto result = pwalletMain->MintAndStoreLelantus(a, wtxAndFee, mints);

        if (result != "") {
            throw std::runtime_error(_("Fail to generate mints, ") + result);
        }

        for(auto itr : wtxAndFee)
            txs.emplace_back(itr.first);

        hdMints.insert(hdMints.end(), mints.begin(), mints.end());
    }

    return hdMints;
}

CPubKey LelantusTestingSetup::GenerateAddress() {
    LOCK(pwalletMain->cs_wallet);
    return pwalletMain->GenerateNewKey();
}

LelantusTestingSetup::~LelantusTestingSetup() {
    lelantus::CLelantusState::GetState()->Reset();
}

// SparkTestingSetup
SparkTestingSetup::SparkTestingSetup() : params(spark::Params::get_default()) {
    CPubKey key;
    {
        LOCK(pwalletMain->cs_wallet);
        key = pwalletMain->GenerateNewKey();
    }
    script = GetScriptForDestination(key.GetID());
}

CBlockIndex* SparkTestingSetup::GenerateBlock(std::vector<CMutableTransaction> const &txns, CScript *script) {
    auto last = chainActive.Tip();

    CreateAndProcessBlock(txns, script ? *script : this->script);
    auto block = chainActive.Tip();

    if (block != last) {
        pwalletMain->ScanForWalletTransactions(block, true);
    }

    return block != last ? block : nullptr;
}

void SparkTestingSetup::GenerateBlocks(size_t blocks, CScript *script) {
    while (blocks--) {
        GenerateBlock({}, script);
    }
}

CPubKey SparkTestingSetup::GenerateAddress() {
    LOCK(pwalletMain->cs_wallet);
    return pwalletMain->GenerateNewKey();
}

std::vector<CSparkMintMeta> SparkTestingSetup::GenerateMints(
    std::vector<CAmount> const &amounts,
    std::vector<CMutableTransaction> &txs) {

    CWalletDB walletdb(pwalletMain->strWalletFile);
    std::vector<CSparkMintMeta> mints;
    // Parameters
    const spark::Params* params;
    params = spark::Params::get_default();

    // Generate address
    spark::Address address = pwalletMain->sparkWallet->getDefaultAddress();

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFeeAll;

    for (auto& a : amounts) {
        std::vector<spark::MintedCoinData> outputs;
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        spark::MintedCoinData data;
        data.v = a;
        data.memo = "memo";
        data.address = address;
        outputs.push_back(data);

        auto result = pwalletMain->MintAndStoreSpark(outputs, wtxAndFee, false);

        if (result != "") {
            throw std::runtime_error(_("Fail to generate mints, ") + result);
        }

        for (auto itr: wtxAndFee) {
            wtxAndFeeAll.push_back(itr);
            txs.emplace_back(itr.first);
        }

    }
    std::vector<CSparkMintMeta> walletMints = pwalletMain->sparkWallet->ListSparkMints();

    for (int i = 0; i < walletMints.size(); ++i) {
        for (int j = 0; j < wtxAndFeeAll.size(); ++j) {
            if (walletMints[i].txid == wtxAndFeeAll[j].first.GetHash()) {
                mints.push_back(walletMints[i]);
            }
        }
    }
    reverse(mints.begin(), mints.end());

    return mints;
}

CTransaction SparkTestingSetup::GenerateSparkSpend(
        std::vector<CAmount> const &outs,
        std::vector<CAmount> const &mints,
        CCoinControl const *coinControl = nullptr) {

    std::vector<CRecipient> vecs;
    for (auto const &out : outs) {
        LOCK(pwalletMain->cs_wallet);
        auto pub = pwalletMain->GenerateNewKey();

        vecs.push_back(
                {
                        GetScriptForDestination(pub.GetID()),
                        out,
                        false
                });
    }

    CAmount fee;
    auto wtx = pwalletMain->SpendAndStoreSpark(
            vecs, {}, fee, coinControl);

    return *wtx.tx;
}


SparkTestingSetup::~SparkTestingSetup()
{
}