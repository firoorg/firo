    // Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "client-api/wallet.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "client-api/register.h"

#include "wallet/rpcwallet.h"

#include "base58.h"
#include "netbase.h"

#include "test/test_bitcoin.h"

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include "miner.h"
#include "main.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "znode-sync.h"
#include "znodeconfig.h"

using namespace std;
CScript script;
extern CCriticalSection cs_main;

static const std::string passphrase = "12345";

struct ClientApiTestingSetup : public TestingSetup {
    ClientApiTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
        //turn warmup status off
        SetAPIWarmupFinished();

        CPubKey newKey;
        BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));

        string strAddress = CBitcoinAddress(newKey.GetID()).ToString();
        pwalletMain->SetAddressBook(CBitcoinAddress(strAddress).Get(), "",
                               ( "receive"));

        //Mine 200 blocks so that we have funds for creating mints and we are over these limits:
        //mBlockHeightConstants["ZC_V1_5_STARTING_BLOCK"] = 150;
        //mBlockHeightConstants["ZC_CHECK_BUG_FIXED_AT_BLOCK"] = 140;

        printf("Balance before %ld\n", pwalletMain->GetBalance());
        script = CScript() <<  ToByteVector(newKey/*coinbaseKey.GetPubKey()*/) << OP_CHECKSIG;
        for (int i = 0; i < 200; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, script);
            coinbaseTxns.push_back(b.vtx[0]);
            LOCK(cs_main);
            {
                LOCK(pwalletMain->cs_wallet);
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[0], &b, true);
            }
        }
        sendZcoin();
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, script);
        LOCK(cs_main);
        {
            LOCK(pwalletMain->cs_wallet);
            for(int i=0;i<b.vtx.size();i++)
                pwalletMain->AddToWalletIfInvolvingMe(b.vtx[i], &b, true);
        }

        printf("Balance after 200 blocks: %ld\n", pwalletMain->GetBalance());
    }

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns,
                       const CScript& script) {
        const CChainParams& chainparams = Params();
        CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(script);
        CBlock& block = pblocktemplate->block;

        // Replace mempool-selected txns with just coinbase plus passed-in txns:
        if(txns.size() > 0) {
            block.vtx.resize(1);
            BOOST_FOREACH(const CMutableTransaction& tx, txns)
                block.vtx.push_back(tx);
        }
        // IncrementExtraNonce creates a valid coinbase and merkleRoot
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
            ++block.nNonce;
        }

        //delete pblocktemplate;
        return block;
    }

    UniValue CallAPI(UniValue valRequest, bool isAuth)
    {
        try {
            APIJSONRequest jreq;
            UniValue auth(UniValue::VOBJ);
            //auth.push_back(Pair("passphrase", passphrase));
            //valRequest.push_back(Pair("auth",auth));
            jreq.parse(valRequest);
            UniValue result = tableAPI.execute(jreq, isAuth);
            return result;
        }
        catch (const UniValue& objError) {
            throw runtime_error(find_value(objError, "message").get_str());
        }
    }

    bool sendZcoin(){
        UniValue valRequest(UniValue::VOBJ);
        UniValue data(UniValue::VOBJ);
        UniValue addresses(UniValue::VOBJ);
        UniValue address(UniValue::VOBJ);
        UniValue result(UniValue::VOBJ);

        address.push_back(Pair("amount",100000000));
        address.push_back(Pair("label","label"));
        addresses.push_back(Pair(GetAccountAddress("*").ToString(), address));
        data.push_back(Pair("addresses",addresses));
        data.push_back(Pair("feePerKb", 100000));

        valRequest.push_back(Pair("type", "create"));
        valRequest.push_back(Pair("collection", "sendZcoin"));
        valRequest.push_back(Pair("data", data));

        result = CallAPI(valRequest, true);
    }

    bool ProcessBlock(CBlock &block) {
        const CChainParams& chainparams = Params();
        CValidationState state;
        return ProcessNewBlock(state, chainparams, NULL, &block, true, NULL, false);
    }

    // Create a new block with just given transactions, coinbase paying to
    // script, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& script){

        CBlock block = CreateBlock(txns, script);
        BOOST_CHECK_MESSAGE(ProcessBlock(block), "Processing block failed");
        return block;
    }

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

BOOST_FIXTURE_TEST_SUITE(client_api_tests, ClientApiTestingSetup)

BOOST_AUTO_TEST_CASE(api_status_test)
{
    UniValue valRequest(UniValue::VOBJ);
    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","apiStatus"));
    
    UniValue result = CallAPI(valRequest, false);

    cout << "result:" << result.write(4,0) << endl;

    BOOST_CHECK(!result.isNull());
    }

BOOST_AUTO_TEST_CASE(blockchain_test)
{
    UniValue valRequest(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","blockchain"));

    
    result = CallAPI(valRequest, true);

    BOOST_CHECK(!result.isNull());

    // set height and time, verify result is returned
    data.push_back(Pair("nHeight", chainActive.Tip()->nHeight));
    data.push_back(Pair("nTime", to_string(chainActive.Tip()->nTime)));
    valRequest.push_back(Pair("data",data));

    result = CallAPI(valRequest, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(block_test)
{
    UniValue valRequest(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);;

    UniValue data(UniValue::VOBJ);
    string hashLatestBlock = chainActive.Tip()->phashBlock->ToString();
    data.push_back(Pair("hashBlock", hashLatestBlock));

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","block"));
    valRequest.push_back(Pair("data", data));
    
    result = CallAPI(valRequest, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(transaction_test)
{
    UniValue valRequest(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);;
    UniValue data(UniValue::VOBJ);

    CBlock block;
    ReadBlockFromDisk(block, chainActive.Tip(), Params().GetConsensus());
    const CWalletTx *coinbaseTx = pwalletMain->GetWalletTx(block.vtx[0].GetHash());
    data.push_back(Pair("txRaw",EncodeHexTx(*coinbaseTx)));

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","transaction"));
    valRequest.push_back(Pair("data", data));
    
    result = CallAPI(valRequest, true);

    //send invalid transaction encoding, verify failure.
    data.replace("txRaw", "000000000000");
    valRequest.replace("data", data);

    BOOST_CHECK_THROW(CallAPI(valRequest, true), runtime_error);
}

BOOST_AUTO_TEST_CASE(sendzcoin_test)
{
    // verify txid field is filled in result.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue addresses(UniValue::VOBJ);
    UniValue address(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    address.push_back(Pair("amount",100000000));
    address.push_back(Pair("label","label"));
    addresses.push_back(Pair(GetAccountAddress("*").ToString(), address));
    data.push_back(Pair("addresses",addresses));
    data.push_back(Pair("feePerKb", 100000));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "sendZcoin"));
    valRequest.push_back(Pair("data", data));

    result = CallAPI(valRequest, true);
    BOOST_CHECK(!result["txid"].isNull());

}

BOOST_AUTO_TEST_CASE(txfee_test)
{
    // verify txid field is filled in result.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue addresses(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    addresses.push_back(Pair(GetAccountAddress("*").ToString(), 1000000));
    data.push_back(Pair("feePerKb", 200000));
    data.push_back(Pair("addresses",addresses));
    

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "txFee"));
    valRequest.push_back(Pair("data", data));

    result = CallAPI(valRequest, true);
    BOOST_CHECK(!result["fee"].isNull());
}

BOOST_AUTO_TEST_CASE(paymentrequest_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);
    UniValue nextResult(UniValue::VOBJ);

    data.push_back(Pair("amount", 40000000));
    data.push_back(Pair("label", "label"));
    data.push_back(Pair("message", "message"));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "paymentRequest"));
    valRequest.push_back(Pair("data", data));

    result = CallAPI(valRequest, true);

    BOOST_CHECK(!result["address"].isNull());
    BOOST_CHECK(!result["createdAt"].isNull());
    BOOST_CHECK(!result["amount"].isNull());
    BOOST_CHECK(!result["message"].isNull());
    BOOST_CHECK(!result["label"].isNull());

    // Now test "initial". values should be the same as what's currently in "result".
    valRequest.replace("type", "initial");
    nextResult = CallAPI(valRequest, true);

    string address = result["address"].get_str();

    BOOST_CHECK(!nextResult[address].isNull());

    // test "Update".
    valRequest.replace("type", "update");
    data.setObject();
    data.push_back(Pair("id",address));
    data.push_back(Pair("amount", 400000000));
    valRequest.replace("data",data);
    nextResult = CallAPI(valRequest, true);

    BOOST_CHECK(result["amount"].get_int64()!=nextResult["amount"].get_int64());

    // test "Delete".
    valRequest.replace("type", "delete");
    data.setObject();
    data.push_back(Pair("id",address));
    valRequest.replace("data",data);
    nextResult = CallAPI(valRequest, true);

    BOOST_CHECK(nextResult.get_bool());
}

BOOST_AUTO_TEST_CASE(mint_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue denominations(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    denominations.push_back(Pair("1", 1));
    data.push_back(Pair("denominations", denominations));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "mint"));
    valRequest.push_back(Pair("data", data));

    result = CallAPI(valRequest, true);

    BOOST_CHECK(result.isStr());
}

BOOST_AUTO_TEST_CASE(sendprivate_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue denominationArr(UniValue::VARR);
    UniValue denominationObj(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    CPubKey newKey;
    BOOST_CHECK(pwalletMain->GetKeyFromPool(newKey));
    string address = CBitcoinAddress(newKey.GetID()).ToString();


    denominationObj.push_back(Pair("value", 1));
    denominationObj.push_back(Pair("amount", 1));
    denominationArr.push_back(denominationObj);
    data.push_back(Pair("denomination", denominationArr));
    data.push_back(Pair("address", address));
    data.push_back(Pair("label", "label"));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "sendPrivate"));
    valRequest.push_back(Pair("data", data));

    // try to send now, verify failure.
    BOOST_CHECK_THROW(CallAPI(valRequest, true), runtime_error);

    // mint two of denomination 1 and mine 6 blocks.
    vector<pair<int,int>> denominationPairs;
    std::vector<CMutableTransaction> MinTxns;
    CWalletTx wtx;

    pwalletMain->SetBroadcastTransactions(true);

    string stringError;

    std::pair<int,int> denominationPair(1, 2);
    denominationPairs.push_back(denominationPair);

    BOOST_CHECK_MESSAGE(pwalletMain->CreateZerocoinMintModel(stringError, denominationPairs), stringError + " - Create Mint failed");

    BOOST_CHECK_MESSAGE(mempool.size() == 1, "Mint not added to mempool");

    // add block
    int previousHeight = chainActive.Height();
    CBlock b = CreateAndProcessBlock(MinTxns, script);
    wtx.Init(NULL);
    //Add 5 more blocks
    for (int i = 0; i < 5; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        b = CreateAndProcessBlock(noTxns, script);
        wtx.Init(NULL);
    }
    BOOST_CHECK_MESSAGE(previousHeight + 6 == chainActive.Height(), "Block not added to chain");
    previousHeight = chainActive.Height();

    // recall now that conditions are met.
    result = CallAPI(valRequest, true);
    BOOST_CHECK(!result["txids"].isNull());
}

BOOST_AUTO_TEST_CASE(statewallet_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue auth(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    valRequest.push_back(Pair("type", "initial"));
    valRequest.push_back(Pair("collection", "stateWallet"));
    //valRequest.push_back(Pair("auth", auth));

    result = CallAPI(valRequest, true);
    BOOST_CHECK(!result.isNull());

}

BOOST_AUTO_TEST_CASE(znodelist_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue auth(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    valRequest.push_back(Pair("type", "initial"));
    valRequest.push_back(Pair("collection", "znodeList"));
    //valRequest.push_back(Pair("auth", auth));

    BOOST_CHECK_THROW(CallAPI(valRequest, true), runtime_error);

    // artificially finish znode sync to test list call
    while(!znodeSync.IsSynced()){
        znodeSync.SwitchToNextAsset();
    }

    result = CallAPI(valRequest, true);
    BOOST_CHECK(!result.isNull()); // empty znode list
}

BOOST_AUTO_TEST_CASE(balance_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    valRequest.push_back(Pair("type", "initial"));
    valRequest.push_back(Pair("collection", "balance"));

    result = CallAPI(valRequest, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(setpassphrase_test)
{
    // Verify "Create" initially.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue auth(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);

    auth.push_back(Pair("passphrase", "123456"));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "setPassphrase"));
    valRequest.push_back(Pair("auth", auth));

    result = CallAPI(valRequest, true);
    BOOST_CHECK(result.get_str()=="wallet encrypted; zcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.");

    auth.push_back(Pair("newPassphrase", passphrase));

    valRequest.replace("type", "update");
    valRequest.replace("auth", auth);

    result = CallAPI(valRequest, true);
    BOOST_CHECK(result.get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
