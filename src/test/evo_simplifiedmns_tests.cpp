// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "bls/bls.h"
#include "evo/deterministicmns.h"
#include "evo/simplifiedmns.h"
#include "netbase.h"
#include "script/script.h"

#include <boost/test/unit_test.hpp>

#include <functional>

BOOST_FIXTURE_TEST_SUITE(evo_simplifiedmns_tests, BasicTestingSetup)

static CBLSPublicKey MakeTestBLSPublicKey(unsigned char value)
{
    std::vector<unsigned char> bytes{value};
    bytes.resize(CBLSSecretKey::SerSize);
    return CBLSSecretKey(bytes).GetPublicKey();
}

static CService MakeTestService(uint16_t port)
{
    CService service;
    BOOST_REQUIRE(Lookup("127.0.0.1", service, port, false));
    return service;
}

static CDeterministicMNState MakeTestMNState()
{
    CDeterministicMNState state;
    state.nRegisteredHeight = 1;
    state.nLastPaidHeight = 2;
    state.nPoSePenalty = 3;
    state.nPoSeRevivedHeight = 4;
    state.nPoSeBanHeight = -1;
    state.nRevocationReason = 5;
    state.confirmedHash.SetHex(strprintf("%064x", 6));
    state.confirmedHashWithProRegTxHash.SetHex(strprintf("%064x", 7));
    state.keyIDOwner.SetHex(strprintf("%040x", 8));
    state.pubKeyOperator.Set(MakeTestBLSPublicKey(9));
    state.keyIDVoting.SetHex(strprintf("%040x", 10));
    state.addr = MakeTestService(11000);
    state.scriptPayout = CScript() << OP_1;
    state.scriptOperatorPayout = CScript() << OP_2;
    return state;
}

static CDeterministicMN MakeTestMN(const CDeterministicMNState& state)
{
    CDeterministicMN dmn;
    dmn.proTxHash.SetHex(strprintf("%064x", 1));
    dmn.pdmnState = std::make_shared<CDeterministicMNState>(state);
    return dmn;
}

BOOST_AUTO_TEST_CASE(simplifiedmns_merkleroots)
{
    std::vector<CSimplifiedMNListEntry> entries;
    for (size_t i = 0; i < 15; i++) {
        CSimplifiedMNListEntry smle;
        smle.proRegTxHash.SetHex(strprintf("%064x", i));
        smle.confirmedHash.SetHex(strprintf("%064x", i));

        std::string ip = strprintf("%d.%d.%d.%d", 0, 0, 0, i);
        Lookup(ip.c_str(), smle.service, i, false);

        std::vector<unsigned char> vecBytes(CBLSSecretKey::SerSize, 0);
        if (!vecBytes.empty()) {
            vecBytes[0] = static_cast<unsigned char>(i);
        }

        smle.pubKeyOperator.Set(CBLSSecretKey(vecBytes).GetPublicKey());
        smle.keyIDVoting.SetHex(strprintf("%040x", i));
        smle.isValid = true;
        
        entries.emplace_back(smle);
    }

    std::vector<std::string> expectedHashes = {
        "373b549f6380d8f7b04d7b04d7c58a749c5cbe3bf41536785ba819879c4870f1",
        "3a1010e28226558560e5296bcee6bf0b9b963b73a1514f5aa2885e270f6b90c1",
        "85d3d93b28689128daf3a41d706ae5002f447b9b6372776f0ca9d53b31146884",
        "8930eee6bd2e7971a7090edfb79f74c00a12280e59adfc2cc99d406a01e368f9",
        "dc2e69caa0ef97e8f5cf40a9530641bd4933dd8c9ad533054537728f7e5f58c2",
        "3e4a0e0a0d2ed397fa27221de3047de21f50d17d0ba43738cbdb9fee96c7cb46",
        "eb18476a1496e1cb912b1d4dd93314b78c6a679d83cae8e144a717b967dc4b8c",
        "6c0d01fa40ac11d7b523facd2bf5632c83f7e4df3f60fd1b364ea90f6c852156",
        "c9e3e69d54e6e95b280ae102593fe114cf4620fa89dd88da1a146ada08815d68",
        "1023f67f735e8e9403d5f083e7a17489619b1790feac4f6b133e9dda15999ae6",
        "5d5fc77944f7c72df236a5baf460c7b9a947144d54d0953521f1494c8a2f7aaa",
        "ac7db66820de3c7506f8c6415fd352e36ac5f27c6adbdfb74de3e109d0d277df",
        "cbc25ca965d0fa69a1fdc1d796b8ee2726a0e2137414e92fb9541630e3189901",
        "ac9934c4049ae952d41fb38e7e9659a558a5ce748bdb7fb613741598d1b16a27",
        "a61177eb14450bb8c56e5f0547035e0f3a70fe46f36901351cc568b2e48e29d0",
    };
    std::vector<std::string> calculatedHashes;

    for (auto& smle : entries) {
        calculatedHashes.emplace_back(smle.CalcHash().ToString());
        //printf("\"%s\",\n", calculatedHashes.back().c_str());
    }

    BOOST_CHECK(expectedHashes == calculatedHashes);

    CSimplifiedMNList sml(entries);

    std::string expectedMerkleRoot = "b2303aca677ae2091c882e44b58f57869fa88a6db1f4e1a5d71975e5387fa195";
    std::string calculatedMerkleRoot = sml.CalcMerkleRoot(nullptr).ToString();
    //printf("merkleRoot=\"%s\",\n", calculatedMerkleRoot.c_str());

    BOOST_CHECK(expectedMerkleRoot == calculatedMerkleRoot);
}

BOOST_AUTO_TEST_CASE(deterministicmn_diff_cbtx_merkle_relevance)
{
    CDeterministicMNListDiff diff;
    BOOST_CHECK(!diff.HasCbTxMerkleRootChanges());

    auto checkUpdatedField = [](uint32_t field, const std::function<void(CDeterministicMNState&)>& update) {
        CDeterministicMNState oldState = MakeTestMNState();
        CDeterministicMNState newState = oldState;
        update(newState);

        const CDeterministicMN oldDmn = MakeTestMN(oldState);
        const CDeterministicMN newDmn = MakeTestMN(newState);
        const bool changesMerkleEntry = CSimplifiedMNListEntry(oldDmn) != CSimplifiedMNListEntry(newDmn);

        CDeterministicMNListDiff diff;
        CDeterministicMNStateDiff stateDiff(oldState, newState);
        BOOST_CHECK_EQUAL(stateDiff.fields, field);
        diff.updatedMNs.emplace(1, stateDiff);
        BOOST_CHECK_EQUAL(diff.HasCbTxMerkleRootChanges(), changesMerkleEntry);
    };

    checkUpdatedField(CDeterministicMNStateDiff::Field_nRegisteredHeight, [](auto& state) { state.nRegisteredHeight = 11; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_nLastPaidHeight, [](auto& state) { state.nLastPaidHeight = 12; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_nPoSePenalty, [](auto& state) { state.nPoSePenalty = 13; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_nPoSeRevivedHeight, [](auto& state) { state.nPoSeRevivedHeight = 14; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_nRevocationReason, [](auto& state) { state.nRevocationReason = 15; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_confirmedHashWithProRegTxHash, [](auto& state) { state.confirmedHashWithProRegTxHash.SetHex(strprintf("%064x", 16)); });
    checkUpdatedField(CDeterministicMNStateDiff::Field_keyIDOwner, [](auto& state) { state.keyIDOwner.SetHex(strprintf("%040x", 17)); });
    checkUpdatedField(CDeterministicMNStateDiff::Field_scriptPayout, [](auto& state) { state.scriptPayout = CScript() << OP_3; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_scriptOperatorPayout, [](auto& state) { state.scriptOperatorPayout = CScript() << OP_4; });

    checkUpdatedField(CDeterministicMNStateDiff::Field_nPoSeBanHeight, [](auto& state) { state.nPoSeBanHeight = 18; });
    checkUpdatedField(CDeterministicMNStateDiff::Field_confirmedHash, [](auto& state) { state.confirmedHash.SetHex(strprintf("%064x", 19)); });
    checkUpdatedField(CDeterministicMNStateDiff::Field_pubKeyOperator, [](auto& state) { state.pubKeyOperator.Set(MakeTestBLSPublicKey(20)); });
    checkUpdatedField(CDeterministicMNStateDiff::Field_keyIDVoting, [](auto& state) { state.keyIDVoting.SetHex(strprintf("%040x", 21)); });
    checkUpdatedField(CDeterministicMNStateDiff::Field_addr, [](auto& state) { state.addr = MakeTestService(12000); });

    diff.updatedMNs.clear();
    diff.addedMNs.emplace_back();
    BOOST_CHECK(diff.HasCbTxMerkleRootChanges());

    diff.addedMNs.clear();
    diff.removedMns.emplace(1);
    BOOST_CHECK(diff.HasCbTxMerkleRootChanges());
}
BOOST_AUTO_TEST_SUITE_END()
