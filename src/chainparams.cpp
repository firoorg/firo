// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"
#include "zerocoin_params.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "libzerocoin/bitcoin_bignum/bignum.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"


static CBlock CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
                   uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
//    CScriptNum csn = CScriptNum(4);
//    std::cout << "CScriptNum(4):" << csn.GetHex();
//    CBigNum cbn = CBigNum(4);
//    std::cout << "CBigNum(4):" << cbn.GetHex();
    txNew.vin[0].scriptSig = CScript() << 504365040 << CBigNum(4).getvch() << std::vector < unsigned char >
    ((const unsigned char *) pszTimestamp, (const unsigned char *) pszTimestamp + strlen(pszTimestamp)) << extraNonce;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
//    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    //btzc: zcoin timestamp
    const char *pszTimestamp = "Times 2014/10/31 Maine Judge Says Nurse Must Follow Ebola Quarantine for Now";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,
                              extraNonce);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.chainType = Consensus::chainMain;        
        consensus.nSubsidyHalvingInterval = 305000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;
        //nVertcoinStartTime
        consensus.nChainStartTime = 1389306217;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        //static const int64 nInterval = nTargetTimespan / nTargetSpacing;
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 10 * 60; // 10 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1475020800; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // Deployment of MTP
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = SWITCH_TO_MTP_BLOCK_HEADER - 2*60; // 2 hours leeway
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = SWITCH_TO_MTP_BLOCK_HEADER + consensus.nMinerConfirmationWindow*2 * 5*60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        consensus.nCheckBugFixedAtBlock = ZC_CHECK_BUG_FIXED_AT_BLOCK;
        consensus.nZnodePaymentsBugFixedAtBlock = ZC_ZNODE_PAYMENT_BUG_FIXED_AT_BLOCK;
	    consensus.nSpendV15StartBlock = ZC_V1_5_STARTING_BLOCK;
	    consensus.nSpendV2ID_1 = ZC_V2_SWITCH_ID_1;
	    consensus.nSpendV2ID_10 = ZC_V2_SWITCH_ID_10;
	    consensus.nSpendV2ID_25 = ZC_V2_SWITCH_ID_25;
	    consensus.nSpendV2ID_50 = ZC_V2_SWITCH_ID_50;
	    consensus.nSpendV2ID_100 = ZC_V2_SWITCH_ID_100;
	    consensus.nModulusV2StartBlock = ZC_MODULUS_V2_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK;
	    consensus.nModulusV1StopBlock = ZC_MODULUS_V1_STOP_BLOCK;
        consensus.nMultipleSpendInputsInOneTxStartBlock = ZC_MULTIPLE_SPEND_INPUT_STARTING_BLOCK;
        consensus.nDontAllowDupTxsStartBlock = 119700;

        // znode params
        consensus.nZnodePaymentsStartBlock = HF_ZNODE_PAYMENT_START; // not true, but it's ok as long as it's less then nZnodePaymentsIncreaseBlock
        // consensus.nZnodePaymentsIncreaseBlock = 680000; // actual historical value // not used for now, probably later
        // consensus.nZnodePaymentsIncreasePeriod = 576*30; // 17280 - actual historical value // not used for now, probably later
        // consensus.nSuperblockStartBlock = 614820;
        // consensus.nBudgetPaymentsStartBlock = 328008; // actual historical value
        // consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        // consensus.nBudgetPaymentsWindowBlocks = 100;

        consensus.nMTPSwitchTime = SWITCH_TO_MTP_BLOCK_HEADER;
        consensus.nMTPFiveMinutesStartBlock = SWITCH_TO_MTP_5MIN_BLOCK;
        consensus.nDifficultyAdjustStartBlock = 0;
        consensus.nFixedDifficulty = 0x2000ffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x1c021e57;
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = 157000;

        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        strZnodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
       `  * a large 32-bit integer with any alignment.
         */
        //btzc: update zcoin pchMessage
        pchMessageStart[0] = 0xe3;
        pchMessageStart[1] = 0xd9;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 8168;
        nPruneAfterHeight = 100000;
        /**
         * btzc: zcoin init genesis block
         * nBits = 0x1e0ffff0
         * nTime = 1414776286
         * nNonce = 142392
         * genesisReward = 0 * COIN
         * nVersion = 2
         * extraNonce
         */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x82;
        extraNonce[1] = 0x3f;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 142392, 0x1e0ffff0, 2, 0 * COIN, extraNonce);
        const std::string s = genesis.GetHash().ToString();
        // std::cout << "zcoin new hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4381deb85b1b2c9843c222944b616d997516dcbd6a964e1eaf0def0830695233"));
        assert(genesis.hashMerkleRoot == uint256S("0x365d2aa75d061370c9aefdabac3985716b1e3b4bb7c4af4ed54f25e5aaa42783"));
        vSeeds.push_back(CDNSSeedData("amsterdam.zcoin.io", "amsterdam.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("australia.zcoin.io", "australia.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("chicago.zcoin.io", "chicago.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("london.zcoin.io", "london.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("frankfurt.zcoin.io", "frankfurt.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("newjersey.zcoin.io", "newjersey.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("sanfrancisco.zcoin.io", "sanfrancisco.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("tokyo.zcoin.io", "tokyo.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("singapore.zcoin.io", "singapore.zcoin.io", false));
        // Note that of those with the service bits flag, most only support a subset of possible options
        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 82);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 7);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 210);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container < std::vector < unsigned char > > ();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (0, uint256S("0xf11046292ff76af48b66de6f1a210c09825d2ab4f56975ec507766ebf9c9f443"))
                        (14000, uint256S("0xeab9b7e451284cb75ada7609e0220bee2b4f289fed9d9cf2a9e3aa548b2d38eb"))
                        (14001, uint256S("0x98641539b9b8ff4e6a8053ec904a14a99f95cf7655c71625104419b22016c9a0"))
                        (14002, uint256S("0x8c8c67106b0b612b08edd13e846c97c24ad0b59066efdb3ad6666e20f90d4bfa"))
                        (14003, uint256S("0xaccfa7c7bb153135def08bb54dadb1835744d9521afb36661a91aa2f70df9abd"))
                        (14271, uint256S("0xf15088099a30f98e85a09789880f74cadca42f725c0cc1666484865539d2f335"))
                        (20580, uint256S("0x591b00ac1ba7d30b9f440efc467072400805a900e92f04f272e6f70cb55ab026"))
			(121378, uint256S("0xa7d9a56dd2986442b5c10ad036eb4e6555eaa8d9f6645c7b9620597792a153ac")),
                1545712287, // * UNIX timestamp of last checkpoint block
                933513,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
                1200.0     // * estimated number of transactions per day after checkpoint
        };
    }
};

static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.chainType = Consensus::chainTestnet;
        consensus.nSubsidyHalvingInterval = 305000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;
        consensus.nChainStartTime = 1389306217;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 5 * 60; // 5 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // Deployment of MTP
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = 1539172800 - 2*60;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = 1539172800 + consensus.nMinerConfirmationWindow*2 * 5*60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

	    consensus.nSpendV15StartBlock = 5000;
        consensus.nCheckBugFixedAtBlock = 1;
        consensus.nZnodePaymentsBugFixedAtBlock = 1;

	    consensus.nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
	    consensus.nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
	    consensus.nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
	    consensus.nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
	    consensus.nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
	    consensus.nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
	    consensus.nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;
        consensus.nMultipleSpendInputsInOneTxStartBlock = 1;
        consensus.nDontAllowDupTxsStartBlock = 18825;

        // Znode params testnet
        consensus.nZnodePaymentsStartBlock = 2200;
        //consensus.nZnodePaymentsIncreaseBlock = 360; // not used for now, probably later
        //consensus.nZnodePaymentsIncreasePeriod = 650; // not used for now, probably later
        //consensus.nSuperblockStartBlock = 61000;
        //consensus.nBudgetPaymentsStartBlock = 60000;
        //consensus.nBudgetPaymentsCycleBlocks = 50;
        //consensus.nBudgetPaymentsWindowBlocks = 10;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet

        consensus.nMTPSwitchTime = 1539172800;
        consensus.nMTPFiveMinutesStartBlock = 0;
        consensus.nDifficultyAdjustStartBlock = 100;
        consensus.nFixedDifficulty = 0x2000ffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x2000ffff;  // !!!! change it to the real value
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = 50500;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        strZnodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";

        pchMessageStart[0] = 0xcf;
        pchMessageStart[1] = 0xfc;
        pchMessageStart[2] = 0xbe;
        pchMessageStart[3] = 0xea;
        nDefaultPort = 18168;
        nPruneAfterHeight = 1000;
        /**
          * btzc: testnet params
          * nTime: 1414776313
          * nNonce: 1620571
          */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x08;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 3564781, 0x1e0ffff0, 2, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << "zcoin testnet genesisBlock hash: " << consensus.hashGenesisBlock.ToString() << std::endl;
        //std::cout << "zcoin testnet hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;
        //btzc: update testnet zcoin hashGenesisBlock and hashMerkleRoot
        assert(consensus.hashGenesisBlock ==
               uint256S("0x1e3487fdb1a7d46dac3e8f3e58339c6eff54abf6aef353485f3ed64250a35e89"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x25b361d60bc7a66b311e72389bf5d9add911c735102bcb6425f63aceeff5b7b8"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // zcoin test seeds
        // vSeeds.push_back(CDNSSeedData("beta1.zcoin.io", "beta1.zcoin.io", false));
        // vSeeds.push_back(CDNSSeedData("beta2.zcoin.io", "beta2.zcoin.io", false));
        // vSeeds.push_back(CDNSSeedData("45.76.182.254", "45.76.182.254", false));
        vSeeds.push_back(CDNSSeedData("MTP1", "mtp1.zcoin.io", false));
        vSeeds.push_back(CDNSSeedData("MTP2", "mtp2.zcoin.io", false));

//        vSeeds.push_back(CDNSSeedData("testnetbitcoin.jonasschnelli.ch", "testnet-seed.bitcoin.jonasschnelli.ch", true));
//        vSeeds.push_back(CDNSSeedData("petertodd.org", "seed.tbtc.petertodd.org", true));
//        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));
//        vSeeds.push_back(CDNSSeedData("bitcoin.schildbach.de", "testnet-seed.bitcoin.schildbach.de"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 178);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 185);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (0, uint256S("0x")),
                        1414776313,
                        0,
                        100.0
        };
    }
};

static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.chainType = Consensus::chainRegtest;
        consensus.nSubsidyHalvingInterval = 305000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60 * 1000; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 1; // 10 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nZnodePaymentsStartBlock = 120;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = INT_MAX;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");
        // Znode code
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        consensus.nCheckBugFixedAtBlock = 120;
        consensus.nZnodePaymentsBugFixedAtBlock = 1;
        consensus.nSpendV15StartBlock = 1;
        consensus.nSpendV2ID_1 = 2;
        consensus.nSpendV2ID_10 = 3;
        consensus.nSpendV2ID_25 = 3;
        consensus.nSpendV2ID_50 = 3;
        consensus.nSpendV2ID_100 = 3;
        consensus.nModulusV2StartBlock = 130;
        consensus.nModulusV1MempoolStopBlock = 135;
        consensus.nModulusV1StopBlock = 140;
        consensus.nMultipleSpendInputsInOneTxStartBlock = 1;
        consensus.nDontAllowDupTxsStartBlock = 1;

        consensus.nMTPSwitchTime = INT_MAX;
        consensus.nMTPFiveMinutesStartBlock = 0;
        consensus.nDifficultyAdjustStartBlock = 5000;
        consensus.nFixedDifficulty = 0x2000ffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x2070ffff;  // !!!! change it to the real value
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = INT_MAX;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        /**
          * btzc: testnet params
          * nTime: 1414776313
          * nNonce: 1620571
          */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x08;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 414098459, 0x207fffff, 1, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();
        //btzc: update regtest zcoin hashGenesisBlock and hashMerkleRoot
//        std::cout << "zcoin regtest genesisBlock hash: " << consensus.hashGenesisBlock.ToString() << std::endl;
//        std::cout << "zcoin regtest hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;
        //btzc: update testnet zcoin hashGenesisBlock and hashMerkleRoot
        //assert(consensus.hashGenesisBlock ==
        //       uint256S("0x0080c7bf30bb2579ed9c93213475bf8fafc1f53807da908cde19cf405b9eb55b"));
        //assert(genesis.hashMerkleRoot ==
        //       uint256S("0x25b361d60bc7a66b311e72389bf5d9add911c735102bcb6425f63aceeff5b7b8"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
                0,
                0,
                0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 178);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) {
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
