#include "amount.h"
#include "base58.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "serialize.h"
#include "util.h"
#include "wallet/wallet.h"
#include "validation.h"
#include "llmq/quorums_instantsend.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/coincontrol.h"
#include <boost/test/unit_test.hpp>

std::string GetAddress(const CTxDestination& dest) {
    CBitcoinAddress addr;
    addr.Set(dest);
    return addr.ToString();
}

std::string GetAddress(const CScript& script) {
    CTxDestination dest;
    ExtractDestination(script, dest);
    return GetAddress(dest);
}

CTransparentTxout GetFakeTransparentTxout(const CScript& dest, CAmount value, bool isMine) {
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));

    CTxOut txout(value, dest);
    COutPoint outpoint(hash, GetRand(128));

    CTransparentTxout transparentTxout(outpoint, txout);
    transparentTxout._mockupIsMine = isMine;
    transparentTxout._mockupDepthInMainChain = 1;
    return transparentTxout;
}

CScript GetRandomDest() {
    CKey key;
    key.MakeNewKey(true);

    return GetScriptForDestination(key.GetPubKey().GetID());
}

CScript GetRandomWalletAddress() {
    AssertLockHeld(pwalletMain->cs_wallet);

    CPubKey key;
    pwalletMain->GetKeyFromPool(key);
    return GetScriptForDestination(key.GetID());
}

CTransparentTxout GetFakeTransparentTxout(CAmount value, bool isMine=true) {
    if (isMine)
        return GetFakeTransparentTxout(GetRandomWalletAddress(), value, isMine);
    else
        return GetFakeTransparentTxout(GetRandomDest(), value, isMine);
}

std::vector<CTransparentTxout> GetFakeTransparentTxouts(std::vector<CAmount> values) {
    std::vector<CTransparentTxout> vTxouts;
    for (CAmount value: values) {
        vTxouts.emplace_back(GetFakeTransparentTxout(value));
    }
    return vTxouts;
}

std::vector<CRecipient> GetFakeRecipients(std::vector<CAmount> values) {
    std::vector<CRecipient> vRecipients;
    for (CAmount value: values) {
        vRecipients.emplace_back(CRecipient{GetRandomDest(), value, false});
    }
    return vRecipients;
}

void AssertVinValue(const std::vector<CTransparentTxout>& vTxouts, const CWalletTx& wtx, uint32_t n, CAmount value) {
    for (const CTransparentTxout& txout: vTxouts) {
        if (txout.GetOutpoint() == COutPoint(wtx.tx->vin[n].prevout)) {
            BOOST_ASSERT(txout.GetValue() == value);
            return;
        }
    }
    BOOST_ASSERT(false);
}

void AssertVoutAddr(const std::vector<CRecipient>& vRecipients, const CWalletTx& wtx, uint32_t voutN, uint32_t recipientN) {
    BOOST_ASSERT(wtx.tx->vout.at(voutN).scriptPubKey == vRecipients.at(recipientN).scriptPubKey);
}

void AssertVoutValue(const CWalletTx& wtx, uint32_t n, CAmount value) {
    BOOST_ASSERT(wtx.tx->vout.at(n).nValue == value);
}

void AssertHasKey(CReserveKey& reservekey, const CWalletTx& wtx, uint32_t voutN) {
    AssertLockHeld(pwalletMain->cs_wallet);

    reservekey.KeepKey();

    BOOST_ASSERT(pwalletMain->IsMine(wtx.tx->vout.at(voutN)));
}

#define ASSERT_VIN_VALUE(vinN, value) AssertVinValue(vTxouts, wtx, vinN, value)
#define ASSERT_VOUT_ADDR(voutN, addrN) AssertVoutAddr(vRecipients, wtx, voutN, addrN)
#define ASSERT_VIN_SIZE(sizeN) BOOST_ASSERT(wtx.tx->vin.size() == sizeN)
#define ASSERT_VOUT_SIZE(sizeN) BOOST_ASSERT(wtx.tx->vout.size() == sizeN)
#define ASSERT_VOUT_VALUE(voutN, value) AssertVoutValue(wtx, voutN, value)
#define ASSERT_VOUT_ADDR_VALUE(voutN, addrN, value) \
    ASSERT_VOUT_ADDR(voutN, addrN); \
    ASSERT_VOUT_VALUE(voutN, value)
#define ASSERT_HAS_KEY(voutN) AssertHasKey(reservekey, wtx, voutN)
#define ASSERT_SUCCESS() if (!strFailReason.empty()) BOOST_FAIL(strFailReason)
#define ASSERT_FAILURE(reason) BOOST_ASSERT(strFailReason == reason)

BOOST_FIXTURE_TEST_SUITE(createtransaction_tests, WalletTestingSetup)
    BOOST_AUTO_TEST_CASE(sends_money) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 20});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 19});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 20);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 19);
            ASSERT_VOUT_VALUE(1, (1 << 20) - (1 << 19) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(multiple_recipients) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 20});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 19, 1 << 18, 1 << 17, 1 << 16, 1 << 15});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 20);
            ASSERT_VOUT_SIZE(6);
            for (uint32_t i = 0; i < 5; i++) {
                ASSERT_VOUT_ADDR_VALUE(i, i, 1 << (19 - i));
            }
            ASSERT_VOUT_VALUE(5, (1 << 20) - (1 << 19) - (1 << 18) - (1 << 17) - (1 << 16) - (1 << 15) - nFeeRet);
            ASSERT_HAS_KEY(5);
        }
    }

    BOOST_AUTO_TEST_CASE(mints_change) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 20});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 19, 1 << 18, 1 << 17, 1 << 16, 1 << 15});

        CAmount changeOutputValue = 0;
        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 20);
            ASSERT_VOUT_SIZE(6);
            for (uint32_t i = 0; i < 5; i++) {
                ASSERT_VOUT_ADDR_VALUE(i, i, 1 << (19 - i));
            }
            changeOutputValue = (1 << 20) - (1 << 19) - (1 << 18) - (1 << 17) - (1 << 16) - (1 << 15) - nFeeRet;
            ASSERT_VOUT_VALUE(5, changeOutputValue);
            ASSERT_HAS_KEY(5);
        }

        vRecipients = GetFakeRecipients({1 << 19, 1 << 18, 1 << 17, 1 << 16, 1 << 15, changeOutputValue - 30});
        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            BOOST_ASSERT(nChangePosInOut == -1);
            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 20);
            ASSERT_VOUT_SIZE(6);
            for (uint32_t i = 0; i < 5; i++) {
                ASSERT_VOUT_ADDR_VALUE(i, i, 1 << (19 - i));
            }
            ASSERT_VOUT_ADDR_VALUE(5, 5, changeOutputValue - 30);
        }
    }

    BOOST_AUTO_TEST_CASE(selects_smallest_input_required) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 15});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 16);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 15);
            ASSERT_VOUT_VALUE(1, (1 << 16) - (1 << 15) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(insufficient_funds) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 15});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 15});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        vTxouts = GetFakeTransparentTxouts({1 << 16});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 16);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 15);
            ASSERT_VOUT_VALUE(1, (1 << 16) - (1 << 15) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(no_unconfirmed_inputs) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 17});

        vTxouts.at(0)._mockupDepthInMainChain = 0;

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        vTxouts.at(0)._mockupDepthInMainChain = 1;

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 15);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
            ASSERT_VOUT_VALUE(1, (1 << 15) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(takes_from_front_and_back) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({(1 << 17) + (1 << 16) + (1 << 14)});

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(4);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 16);
            ASSERT_VIN_VALUE(3, 1 << 14);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, (1 << 17) + (1 << 16) + (1 << 14));
            ASSERT_VOUT_VALUE(1, (1 << 13) - nFeeRet);
        }
    }

    BOOST_AUTO_TEST_CASE(doesnt_select_used_inputs) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 16});

        vTxouts.at(0)._mockupIsSpent = true;
        vTxouts.at(4)._mockupIsSpent = true;

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 16);
            ASSERT_VIN_VALUE(1, 1 << 14);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 16);
            ASSERT_VOUT_VALUE(1, (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(instantsend) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 17});

        vTxouts.at(0)._mockupDepthInMainChain = 0;

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        vTxouts.at(0)._mockupIsLLMQInstantSendLocked = true;

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
            ASSERT_VOUT_VALUE(1, (1 << 13) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }

        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, false, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }
    }

    BOOST_AUTO_TEST_CASE(change_position) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 16, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 17, 1 << 13, 1 << 16});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            BOOST_ASSERT(nChangePosInOut == 3);
            ASSERT_VIN_SIZE(4);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 16);
            ASSERT_VIN_VALUE(3, 1 << 14);
            ASSERT_VOUT_SIZE(4);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
            ASSERT_VOUT_ADDR_VALUE(1, 1, 1 << 13);
            ASSERT_VOUT_ADDR_VALUE(2, 2, 1 << 16);
            ASSERT_VOUT_VALUE(3, (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(3);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = 0;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            BOOST_ASSERT(nChangePosInOut == 0);
            ASSERT_VIN_SIZE(4);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 16);
            ASSERT_VIN_VALUE(3, 1 << 14);
            ASSERT_VOUT_SIZE(4);
            ASSERT_VOUT_VALUE(0, (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(0);
            ASSERT_VOUT_ADDR_VALUE(1, 0, 1 << 17);
            ASSERT_VOUT_ADDR_VALUE(2, 1, 1 << 13);
            ASSERT_VOUT_ADDR_VALUE(3, 2, 1 << 16);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = 2;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            BOOST_ASSERT(nChangePosInOut == 2);
            ASSERT_VIN_SIZE(4);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 16);
            ASSERT_VIN_VALUE(3, 1 << 14);
            ASSERT_VOUT_SIZE(4);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
            ASSERT_VOUT_ADDR_VALUE(1, 1, 1 << 13);
            ASSERT_VOUT_VALUE(2, (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(2);
            ASSERT_VOUT_ADDR_VALUE(3, 2, 1 << 16);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = 7;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            BOOST_ASSERT(nChangePosInOut == -1);
            ASSERT_FAILURE("Change index out of range");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -5;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            BOOST_ASSERT(nChangePosInOut == -1);
            ASSERT_FAILURE("Change index out of range");
        }
    }

    BOOST_AUTO_TEST_CASE(watch_only_address) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 16});

        vTxouts.emplace_back(GetFakeTransparentTxout(1 << 17, false));
        vTxouts.at(3)._mockupIsMineWatchOnly = true;

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            BOOST_ASSERT(strFailReason == "Insufficient funds");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.fAllowWatchOnly = true;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, false, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 16);
            ASSERT_VOUT_VALUE(1, (1 << 17) - (1 << 16) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.fAllowWatchOnly = true;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Signing transaction failed");
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_coin_type) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1000 * COIN});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({999 * COIN});


        {
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           nullptr, true, 0, true, vTxouts);


            ASSERT_FAILURE("Insufficient funds");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nCoinType = CoinType::ONLY_1000;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1000 * COIN);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 999 * COIN);
            ASSERT_VOUT_VALUE(1, (1 * COIN) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nCoinType = CoinType::ONLY_NONDENOMINATED_NOT1000IFMN;

            bool fMasternodeModeTemp = fMasternodeMode;
            fMasternodeMode = false;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("fMasternode must be enabled to use CoinType::ONLY_NONDENOMINATED_NOT1000IFMN");

            fMasternodeMode = fMasternodeModeTemp;
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nCoinType = CoinType::ONLY_NONDENOMINATED_NOT1000IFMN;

            bool fMasternodeModeTemp = fMasternodeMode;
            fMasternodeMode = true;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_FAILURE("Insufficient funds");

            fMasternodeMode = fMasternodeModeTemp;
        }

        vTxouts = GetFakeTransparentTxouts({1001 * COIN, 1000 * COIN});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nCoinType = CoinType::ONLY_NONDENOMINATED_NOT1000IFMN;

            bool fMasternodeModeTemp = fMasternodeMode;
            fMasternodeMode = true;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1001 * COIN);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 999 * COIN);
            ASSERT_VOUT_VALUE(1, 2 * COIN - nFeeRet);
            ASSERT_HAS_KEY(1);

            fMasternodeMode = fMasternodeModeTemp;
        }

        vRecipients = GetFakeRecipients({2000 * COIN});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nCoinType = CoinType::WITH_1000;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1001 * COIN);
            ASSERT_VIN_VALUE(1, 1000 * COIN);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 2000 * COIN);
            ASSERT_VOUT_VALUE(1, 1 * COIN - nFeeRet);
            ASSERT_HAS_KEY(1);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.Select(vTxouts.at(1).GetOutpoint());
            coinControl.nCoinType = CoinType::WITH_1000;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.Select(vTxouts.at(1).GetOutpoint());
            coinControl.fAllowOtherInputs = true;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Some coin control inputs could not be selected.");
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_input_count_limit) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({(1 << 17) + (1 << 15)});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nFeeRate = CFeeRate(1000);
            coinControl.nMaxInputs = 2;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nFeeRate = CFeeRate(1000);
            coinControl.nMaxInputs = 3;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(3);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 15);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, (1 << 17) + (1 << 15));
            ASSERT_VOUT_VALUE(1, (1 << 13) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_transaction_size_limit) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({(1 << 17) + (1 << 14)});

        size_t n3TxSize = 0;
        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nFeeRate = CFeeRate(1000);
            coinControl.nMaxInputs = 3;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(3);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VIN_VALUE(2, 1 << 15);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, (1 << 17) + (1 << 14));
            ASSERT_VOUT_VALUE(1, (1 << 15) + (1 << 13) - (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(1);

            // nFeeRet is based on the transaction size with maximum-length signatures, which is what is used as the
            // transaction size when calculating the transaction size for input selection. It may be slightly greater
            // than the final transaction size.
            BOOST_ASSERT(nFeeRet >= ::GetSerializeSize(*wtx.tx, SER_NETWORK, PROTOCOL_VERSION));
            n3TxSize = nFeeRet;
        }

        size_t n2TxSize = 0;
        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nFeeRate = CFeeRate(1000);
            coinControl.nMaxSize = n3TxSize - 1;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);


            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 15);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, (1 << 17) + (1 << 14));
            ASSERT_VOUT_VALUE(1, (1 << 15) - (1 << 14) - nFeeRet);
            ASSERT_HAS_KEY(1);

            BOOST_ASSERT(nFeeRet >= ::GetSerializeSize(*wtx.tx, SER_NETWORK, PROTOCOL_VERSION));
            n2TxSize = nFeeRet;
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nFeeRate = CFeeRate(1000);
            coinControl.nMaxSize = n2TxSize - 1;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_destination_address) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 16});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.destChange = GetRandomDest();

            pwalletMain->CreateTransaction(vRecipients, wtx, nullptr, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 16);
            ASSERT_VOUT_VALUE(1, (1 << 17) - (1 << 16) - nFeeRet);
            BOOST_ASSERT(GetAddress(wtx.tx->vout.at(1).scriptPubKey) == GetAddress(coinControl.destChange));
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_minimum_total_fee) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 17});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nMinimumTotalFee = 1 << 13;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            BOOST_ASSERT(nFeeRet == 1 << 13);
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VOUT_SIZE(1);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nMinimumTotalFee = 1 << 20;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nMinimumTotalFee = 100;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            BOOST_ASSERT(nFeeRet > 100);
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 13);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 17);
            ASSERT_VOUT_VALUE(1, (1 << 13) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_confirm_target) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1 << 16});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nConfirmTarget = 5;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_FAILURE("Insufficient funds");
        }

        vTxouts.at(0)._mockupDepthInMainChain = 5;

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.nConfirmTarget = 5;

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1 << 16);
            ASSERT_VOUT_VALUE(1, (1 << 17) - (1 << 16) - nFeeRet);
            ASSERT_HAS_KEY(1);
        }
    }

    BOOST_AUTO_TEST_CASE(coincontrol_require_all_inputs) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        std::vector<CTransparentTxout> vTxouts = GetFakeTransparentTxouts({1 << 17, 1 << 15, 1 << 14, 1 << 13});
        std::vector<CRecipient> vRecipients = GetFakeRecipients({1});

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.fRequireAllInputs = true;
            coinControl.Select(vTxouts.at(0).GetOutpoint());
            coinControl.Select(vTxouts.at(1).GetOutpoint());

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(2);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VIN_VALUE(1, 1 << 15);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1);
            ASSERT_VOUT_VALUE(1, (1 << 17) + (1 << 15) - nFeeRet - 1);
            ASSERT_HAS_KEY(1);
        }

        {
            CCoinControl coinControl;
            CWalletTx wtx;
            CAmount nFeeRet = 0;
            int nChangePosInOut = -1;
            std::string strFailReason;

            coinControl.fRequireAllInputs = false;
            coinControl.Select(vTxouts.at(0).GetOutpoint());
            coinControl.Select(vTxouts.at(1).GetOutpoint());

            CReserveKey reservekey(pwalletMain);
            pwalletMain->CreateTransaction(vRecipients, wtx, &reservekey, nFeeRet, nChangePosInOut, strFailReason,
                                           &coinControl, true, 0, true, vTxouts);

            ASSERT_SUCCESS();
            ASSERT_VIN_SIZE(1);
            ASSERT_VIN_VALUE(0, 1 << 17);
            ASSERT_VOUT_SIZE(2);
            ASSERT_VOUT_ADDR_VALUE(0, 0, 1);
            ASSERT_VOUT_VALUE(1, (1 << 17) - nFeeRet - 1);
            ASSERT_HAS_KEY(1);
        }
    }
BOOST_AUTO_TEST_SUITE_END()
