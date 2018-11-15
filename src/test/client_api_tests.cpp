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

using namespace std;
CScript script;
extern CCriticalSection cs_main;

struct ClientApiTestingSetup : public TestingSetup {
    ClientApiTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
        // First register all commands to tableAPI + turn warmup status off
        RegisterAllCoreAPICommands(tableAPI);
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

// UniValue createArgs(int nRequired, const char* address1=NULL, const char* address2=NULL)
// {
//     UniValue result(UniValue::VARR);
//     result.push_back(nRequired);
//     UniValue addresses(UniValue::VARR);
//     if (address1) addresses.push_back(address1);
//     if (address2) addresses.push_back(address2);
//     result.push_back(addresses);
//     return result;
// }

// UniValue CallAPI(string args)
// {
//     vector<string> vArgs;
//     boost::split(vArgs, args, boost::is_any_of(" \t"));
//     string strMethod = vArgs[0];
//     vArgs.erase(vArgs.begin());
//     UniValue params = RPCConvertValues(strMethod, vArgs);
//     BOOST_CHECK(tableRPC[strMethod]);
//     rpcfn_type method = tableRPC[strMethod]->actor;
//     try {
//         UniValue result = (*method)(params, false);
//         return result;
//     }
//     catch (const UniValue& objError) {
//         throw runtime_error(find_value(objError, "message").get_str());
//     }
// }


BOOST_FIXTURE_TEST_SUITE(client_api_tests, ClientApiTestingSetup)

BOOST_AUTO_TEST_CASE(api_status_test)
{
    UniValue valRequest(UniValue::VOBJ);
    APIJSONRequest jreq;
    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","apiStatus"));

    jreq.parse(valRequest);
    
    UniValue result = tableAPI.execute(jreq, false);

    cout << "result:" << result.write(4,0) << endl;

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(blockchain_test)
{
    UniValue valRequest(UniValue::VOBJ);
    APIJSONRequest jreq;
    UniValue result(UniValue::VOBJ);;

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","blockchain"));

    jreq.parse(valRequest);
    
    result = tableAPI.execute(jreq, true);

    BOOST_CHECK(!result.isNull());

    // set height and time, verify result is returned
    valRequest.push_back(Pair("nHeight", stoi(to_string(chainActive.Tip()->nHeight))));
    valRequest.push_back(Pair("nTime", stoi(to_string(chainActive.Tip()->nHeight))));

    jreq.parse(valRequest);

    result = tableAPI.execute(jreq, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(block_test)
{
    UniValue valRequest(UniValue::VOBJ);
    APIJSONRequest jreq;
    UniValue result(UniValue::VOBJ);;

    UniValue data(UniValue::VOBJ);
    string hashLatestBlock = chainActive.Tip()->phashBlock->ToString();
    data.push_back(Pair("hashBlock", hashLatestBlock));

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","block"));
    valRequest.push_back(Pair("data", data));
    jreq.parse(valRequest);
    
    result = tableAPI.execute(jreq, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(transaction_test)
{
    UniValue valRequest(UniValue::VOBJ);
    APIJSONRequest jreq;
    UniValue result(UniValue::VOBJ);;
    UniValue data(UniValue::VOBJ);

    CBlock block;
    ReadBlockFromDisk(block, chainActive.Tip(), Params().GetConsensus());
    const CWalletTx *coinbaseTx = pwalletMain->GetWalletTx(block.vtx[0].GetHash());
    data.push_back(Pair("txRaw",EncodeHexTx(*coinbaseTx)));

    valRequest.push_back(Pair("type","initial"));
    valRequest.push_back(Pair("collection","transaction"));
    valRequest.push_back(Pair("data", data));
    jreq.parse(valRequest);
    
    result = tableAPI.execute(jreq, true);

    BOOST_CHECK(!result.isNull());
}

BOOST_AUTO_TEST_CASE(sendzcoin_test)
{
    // verify txid field is filled in result.
    UniValue valRequest(UniValue::VOBJ);
    UniValue data(UniValue::VOBJ);
    UniValue addresses(UniValue::VOBJ);
    UniValue address(UniValue::VOBJ);
    UniValue result(UniValue::VOBJ);
    APIJSONRequest jreq;

    address.push_back(Pair("amount",100000000));
    address.push_back(Pair("label","label"));
    addresses.push_back(Pair(GetAccountAddress("*").ToString(), address));
    data.push_back(Pair("addresses",addresses));
    data.push_back(Pair("feePerKb", 100000));

    valRequest.push_back(Pair("type", "create"));
    valRequest.push_back(Pair("collection", "sendZcoin"));
    valRequest.push_back(Pair("data", data));

    jreq.parse(valRequest); 
    result = tableAPI.execute(jreq, true);
    BOOST_CHECK(!result["txid"].isNull());
}

BOOST_AUTO_TEST_SUITE_END()
