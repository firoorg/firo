// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "base58.h"
#include "key.h"
#include "uint256.h"
#include "util.h"
#include "wallet/wallet.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "bip47/secretpoint.h"
#include "bip47/paymentcode.h"
#include "bip47/paymentaddress.h"

#include <string>
#include <vector>

TestVector bip47_tv1 =
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

TestVector bip47_tv2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
     "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
     0)
    ("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
     "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
     0xFFFFFFFF)
    ("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
     "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
     1)
    ("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
     "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
     0xFFFFFFFE)
    ("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
     "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
     2)
    ("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
     "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
     0);

bool RunTest(TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);

    CExtKey key;
    CExtPubKey pubkey;
    key.SetMaster(&seed[0], seed.size());
    pubkey = key.Neuter();
    
    for(std::vector<TestDerivation>::iterator it = test.vDerive.begin();it != test.vDerive.end();++it) {
        const TestDerivation &derive  = *it;
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        CBitcoinExtKey b58key; b58key.SetKey(key);
        BOOST_CHECK_EQUAL((b58key.ToString() == derive.prv), true);
   
        CBitcoinExtKey b58keyDecodeCheck(derive.prv);
        CExtKey checkKey = b58keyDecodeCheck.GetKey();
        BOOST_CHECK_EQUAL((checkKey == key), true); //ensure a base58 decoded key also matches

        // Test public key
        CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);
        BOOST_CHECK_EQUAL((b58pubkey.ToString() == derive.pub), true);

        CBitcoinExtPubKey b58PubkeyDecodeCheck(derive.pub);
        CExtPubKey checkPubKey = b58PubkeyDecodeCheck.GetKey();
        BOOST_CHECK_EQUAL((checkPubKey == pubkey), true); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK_EQUAL((key.Derive(keyNew, derive.nChild)), true);
        printf("keynew valid = %d \n",keyNew.key.IsValid());
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK_EQUAL((pubkey.Derive(pubkeyNew2, derive.nChild)), true);
            BOOST_CHECK_EQUAL((pubkeyNew == pubkeyNew2), true);
        }
        key = keyNew;
        pubkey = pubkeyNew;

        CDataStream ssPub(SER_DISK, CLIENT_VERSION);
        ssPub << pubkeyNew;
        BOOST_CHECK_EQUAL((ssPub.size() == 75), true);

        CDataStream     ssPriv(SER_DISK, CLIENT_VERSION);
        ssPriv << keyNew;
        BOOST_CHECK_EQUAL((ssPriv.size() == 75), true);

        CExtPubKey pubCheck;
        CExtKey privCheck;
        ssPub >> pubCheck;
        ssPriv >> privCheck;

        BOOST_CHECK_EQUAL((pubCheck == pubkeyNew), true);
        BOOST_CHECK_EQUAL((privCheck == keyNew), true);
    }
    return true;
}

BOOST_FIXTURE_TEST_SUITE(bip47_tests, TestingSetup)

/**
 * 
 * Glossary Of Definitions:
 * @incoming_address
 * 
 * b`  .pubkey : The incoming address is the Zcoin address with which the receiver expects to be paid.
 * 
 * @outgoing_address
 * 
 * B` : The outgoing address is the Zcoin address which the sender is going to send a transaction,
 *   with the expectation that the receiver will get this deposit.
 * 
 * 
 * This function is the one of UnitTest that can able to check the PaymentAddress generate incoming and outgoing addresses derived between alice and bob payment codes.
 * 
 * Calculate the New Public Key as    B` = B + Gs
 * Calcualte the New Private Key as   b` = b + s
 * 
 * B is pubkey derived from payment code of reciever (This shared from bob to Alice via payment code)
 * b is the private key dervived from payment code of reciever (This is only bob knows)
 * 
 * s is Shared Secret between alice and bob    calcaulted via Bob pubkey and Alice private or Bob private key and alice public key
 * 
 * G is the generator point of EC params
 * 
 * Now the checkable point is that
 * 
 * New found public key B` is verifiable from new found private key b`
 * 
 * key.VerifyPubKey(pubkey)
 * 
 * @Status false
 * @expect result true
 *  
 * */

BOOST_AUTO_TEST_CASE(payment_address)
{
    
    CPaymentCode toPcode("PM8TJK7t44xGE2DSbFGCk2wCypTzeq3L5i5r5iUGyNruaFLMCshtANUiBN1d9LCyQ9JrfDt3LFwRPSRkWPFBJAT7kdJgCaLDc3kQpQuwEVWxa6UmpR64");
    
    CPaymentAddress payaddr = CBIP47Util::getPaymentAddress(toPcode, 0, pwalletMain->getBIP47Account(0).keyPrivAt(0));
    
    CExtPubKey extPubkey = pwalletMain->getBIP47Account(0).keyAt(0);
    CExtKey extKey = pwalletMain->getBIP47Account(0).keyPrivAt(0);
    CExtPubKey neutPubkey = extKey.Neuter();
    
    printf("extPubkey = %s\nneutPubkey = %s\n", extPubkey.pubkey.GetHash().GetHex().c_str(), neutPubkey.pubkey.GetHash().GetHex().c_str());
    
    
    CPubKey pubkey = payaddr.getReceiveECPubKey();
    CBitcoinAddress addr(pubkey.GetID());
    printf("Self Test Address get is %s\n", addr.ToString().c_str());
    
    CKey key = payaddr.getReceiveECKey();

    BOOST_CHECK_EQUAL(key.VerifyPubKey(pubkey), true);
}


BOOST_AUTO_TEST_CASE(chaincode)
{
    std::string strHexMaster = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    std::vector<unsigned char> seed = ParseHex(strHexMaster);

    CExtKey masterKey;             //bip47 master key
    CExtKey purposeKey;            //key at m/47'
    CExtKey coinTypeKey;           //key at m/47'/<1/136>' (Testnet or Zcoin Coin Type respectively, according to SLIP-0047)
    CExtKey identityKey;           //key identity
    CExtKey childKey;              // index

    masterKey.SetMaster(&seed[0], seed.size());

    masterKey.Derive(purposeKey, 0x2F | BIP32_HARDENED_KEY_LIMIT);
    purposeKey.Derive(coinTypeKey, 0 | BIP32_HARDENED_KEY_LIMIT);
    coinTypeKey.Derive(identityKey, 0 | BIP32_HARDENED_KEY_LIMIT);

    //    CExtKey key;
    unsigned char data[80];
    CExtPubKey pubkey;
    pubkey = identityKey.Neuter();
    identityKey.Encode(data);
    pubkey.Encode(data);

    unsigned char alicepubkey[33];
    unsigned char alicechian[32];
    std::copy(pubkey.pubkey.begin(), pubkey.pubkey.end(), alicepubkey);
    std::copy(pubkey.chaincode.begin(), pubkey.chaincode.end(), alicechian);
    printf("creating PaymentCode...");
    CPaymentCode alicePcode(alicepubkey, alicechian);
    printf("\n Payment code of alice \n%s\n", alicePcode.toString().c_str());


    printf("Encoded Data\n");
    for(int i = 0; i < 80; i++) {
        printf("%u", data[i]);
    }
    printf("\n");

    CBitcoinExtKey b58key; b58key.SetKey(identityKey);

    printf("%s\n", b58key.ToString().c_str());

    CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);

    printf("Pubkey value is %s\n", b58pubkey.ToString().c_str());

    std::string strPcode = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    CPaymentCode paymentCode(strPcode);
    CPubKey masterPubkey = paymentCode.getPubKey();
    printf("\n master pubkey size %d\n", masterPubkey.size());

    if (masterPubkey.IsValid()) {
        printf("\nmaster Pubkey is valid\n");
        CBitcoinAddress address(masterPubkey.GetID());
        std::cout << " Address from masterPubkey " << address.ToString() << std::endl;
    } else {
        printf("\nmaster Pubkey is not valid\n");
    }


    CExtPubKey extPubKey;
    paymentCode.isValid();
    std::vector<unsigned char> payloads;
    payloads = paymentCode.getPayload();


    CBitcoinAddress newaddress("TN5pADYZMSDyKpcgicC1d2Z2adHdTgHRGG");
    CKeyID keyID;
    newaddress.GetKeyID(keyID);
    CPubKey vchPubKey;
}

BOOST_AUTO_TEST_CASE(secret_point)
{
    CKey key1, key2;
    
    CPubKey pubkey1, pubkey2;

    std::vector<unsigned char> pubkeyPcode = ParseHex("03c5f5da29143d68b2415bf9214bc8dcfe059c640f416deb7ba4021e3b33857237");
    std::vector<unsigned char> scriptSigPub = ParseHex("02b6d7f89a01b9b3bf0bb45c24cee0127586578869b1c43968ad311158eb7e2e40");
    
    std::vector<unsigned char> designatedKey = ParseHex("32e4b85b7efe7e91e6cee5d1ae7cda2b61cd5fa7c09a6afe107b277183864daa");
    std::vector<unsigned char> pcodeKey = ParseHex("72968cda4d199f3e4899c483523241fc1f8844f24b2d0c4b24a0bfaf1a1ef64e");
    
    pubkey1.Set(pubkeyPcode.begin(), pubkeyPcode.end());
    pubkey2.Set(scriptSigPub.begin(), scriptSigPub.end());

    std::vector<unsigned char> key1bytes(key1.begin(), key1.end());
    std::vector<unsigned char> key2bytes(key2.begin(), key2.end());
    
    std::vector<unsigned char> pubkey1bytes(pubkey1.begin(), pubkey1.end());
    std::vector<unsigned char> pubkey2bytes(pubkey2.begin(), pubkey2.end());
    
    SecretPoint scretp1(key1bytes, pubkey2bytes);
    SecretPoint scretp2(key2bytes, pubkey1bytes);

    bool isShared = scretp1.isShared(scretp2);
    BOOST_CHECK_EQUAL(isShared, true);
}


BOOST_AUTO_TEST_CASE(bip47_basic_tests)
{
    BOOST_CHECK_EQUAL(RunTest(bip47_tv1), true);
    BOOST_CHECK_EQUAL(RunTest(bip47_tv2), true);
}

BOOST_AUTO_TEST_SUITE_END()