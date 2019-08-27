//
// Created by Top1s on 8/22/2019.
//

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "bip47.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"
#include "wallet/sigmaspendbuilder.h"
#include "amount.h"
#include "base58.h"
#include "checkpoints.h"
#include "chain.h"
#include "coincontrol.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "zerocoin.h"
#include "sigma.h"
#include "../sigma/coinspend.h"
#include "../sigma/spend_metadata.h"
#include "../sigma/coin.h"
#include "../sigma/remint.h"
#include "../libzerocoin/SpendMetaData.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "darksend.h"
#include "instantx.h"
#include "znode.h"
#include "znode-sync.h"
#include "random.h"
#include "init.h"
#include "hdmint/wallet.h"
#include "rpc/protocol.h"

#include "hdmint/tracker.h"

#include <assert.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

using namespace std;
#include <stdexcept>

extern void noui_connect();

#include <string>
#include <vector>
#include <string.h>


namespace bip47 {

    using namespace std;


//    int PaymentCode::PUBLIC_KEY_Y_OFFSET = 2;
//    int PaymentCode::PUBLIC_KEY_X_OFFSET = 3;
//    int PaymentCode::CHAIN_OFFSET = 35;
//    int PaymentCode::PUBLIC_KEY_X_LEN = 32;
//    int PaymentCode::PUBLIC_KEY_Y_LEN = 1;
//    int PaymentCode::CHAIN_LEN = 32;
//    int PaymentCode::PAYLOAD_LEN = 80;

    bool PaymentCode::valid() const {
        return true;
    }

    PaymentCode::PaymentCode() {
    }

    PaymentCode::PaymentCode(byte pkey[PUBLIC_KEY_LEN], byte ch[CHAIN_LEN]) {
        memcpy(pubkey, pkey, PUBLIC_KEY_LEN);
        memcpy(chain, ch, CHAIN_LEN);
        strPaymentCode = makeV1();
    }

    PaymentCode::PaymentCode(string payment_code) {
        strPaymentCode = payment_code;
        parse_payment_code();
    }

    string PaymentCode::makeV1() {
        string ret = "";
        byte payload[PAYLOAD_LEN];
        byte payment_code[PAYLOAD_LEN + 1];

        memset(payload, 0, PAYLOAD_LEN);
        memset(payment_code, 0, PAYLOAD_LEN + 1);

        // byte 0: type. required value: 0x01
        payload[0] = (byte)0x01;
        // byte 1: features bit field. All bits must be zero except where specified elsewhere in this specification
        //      bit 0: Bitmessage notification
        //      bits 1-7: reserved
        payload[1] = 0;
        // replace sign & x code (33 bytes)
        memcpy(payload + 2, pubkey, PUBLIC_KEY_LEN);
        // replace chain code (32 bytes)
        memcpy(payload + 35, chain, CHAIN_LEN);

        payment_code[0] = (byte)0x47;
        memcpy(payment_code + 1, payload, PAYLOAD_LEN);

        vector<byte> payment_code_checksum(std::begin(payment_code), std::end(payment_code));
        ret = EncodeBase58Check(payment_code_checksum);

        printf("encode ret = %s\n", ret.c_str());

        return ret;
    };

    bool PaymentCode::parse_payment_code() {
        vector<byte> payment_code_checksum;
        DecodeBase58Check(strPaymentCode, payment_code_checksum);
        return true;
    }



}

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
        TestVector("000102030405060708090a0b0c0d0e0f")
                ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                 "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                 0x80000000)
                ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                 "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                 1)
                ("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                 "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                 0x80000002)
                ("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                 "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                 2)
                ("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                 "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                 1000000000)
                ("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                 "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                 0);

void init_test_config() {
    SoftSetBoolArg("-dandelion", false);
    ECC_Start();
    SetupEnvironment();
    SoftSetBoolArg("-dandelion", false);
    SetupNetworking();
    SoftSetBoolArg("-dandelion", false);
    fPrintToDebugLog = false; // don't want to write to debug.log file
    fCheckBlockIndex = true;
    SoftSetBoolArg("-dandelion", false);
    SelectParams(CBaseChainParams::REGTEST);
    SoftSetBoolArg("-dandelion", false);
    noui_connect();
}


int main(int argc, char* argv[]) {

    init_test_config();

//    std::vector<unsigned char> seed = ParseHex(test1.strHexMaster);
//    CExtKey key;
//    CExtPubKey pubkey;
//    key.SetMaster(&seed[0], seed.size());
//    pubkey = key.Neuter();
//    const TestDerivation &derive = test1.vDerive[0];
//
//    unsigned char data[74];
//    key.Encode(data);
//    pubkey.Encode(data);
//
//    // Test private key
//    CBitcoinExtKey b58key; b58key.SetKey(key);
//
//    printf("b58key = %s ,\n derive.prv = %s \n",
//            b58key.ToString().c_str(),
//            derive.prv.c_str());
//
//    CBitcoinExtKey b58keyDecodeCheck(derive.prv);
//    CExtKey checkKey = b58keyDecodeCheck.GetKey();
//    assert(checkKey == key);
//
//    printf("Test Passed\n");

//    std::string strHexMaster = "b7b8706d714d9166e66e7ed5b3c61048";
    std::string strHexMaster = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    std::vector<unsigned char> seed = ParseHex(strHexMaster);

    CExtKey masterKey;             //bip47 master key
    CExtKey purposeKey;            //key at m/47'
    CExtKey coinTypeKey;           //key at m/47'/<1/136>' (Testnet or Zcoin Coin Type respectively, according to SLIP-0047)
    CExtKey identityKey;           //key identity
    CExtKey childKey;              // index

    masterKey.SetMaster(&seed[0], seed.size());

    masterKey.Derive(purposeKey, BIP47_INDEX | BIP32_HARDENED_KEY_LIMIT);
    purposeKey.Derive(coinTypeKey, 0);
    coinTypeKey.Derive(identityKey, 0);

//    CExtKey key;
    unsigned char data[80];
    CExtPubKey pubkey;
    pubkey = identityKey.Neuter();
    identityKey.Encode(data);
    pubkey.Encode(data);

    printf("Encoded Data\n");
    for(int i = 0; i < 80; i++) {
        printf("%x", data[i]);
    }
    printf("\n");

    CBitcoinExtKey b58key; b58key.SetKey(identityKey);

    printf("%s\n", b58key.ToString().c_str());

    CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);

    printf("Pubkey value is %s\n",b58pubkey.ToString().c_str());






//    SelectParams(CBaseChainParams::REGTEST);

//    string strAddress = "TPj1wZxMM7TRWeBdKWWMn34G6XNeobCq9K";
//    string privstr = "cSaagnTkEJymA6amdQ5kpdPTszfKzdjiXZmJm42qy7Fd4MnTwZeB";
//    CBitcoinSecret vchSecret;
//    vchSecret.SetString(privstr);
//    CKey key = vchSecret.GetKey();
//    printf("%s\n", key.IsValid() ? "true" : "false");
//
//    LOCK(pwalletMain->cs_wallet);
//    CPubKey pubKey = key.GetPubKey();


//    assert(key.VerifyPubKey(pubKey));


//    CBitcoinAddress addr(strAddress);
//    CKeyID keyId;
//    addr.GetKeyID(keyId);

//    pwalletMain->GetKey(hdChain.masterKeyID, key);

    return 0;
}