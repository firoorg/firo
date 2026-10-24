// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spark/assetstate.h"
#include "spark/primitives.h"
#include "spark/sparkasset.h"
#include "spark/state.h"
#include "base58.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "libspark/keys.h"
#include "libspark/mint_transaction.h"
#include "primitives/transaction.h"
#include "policy/policy.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_bitcoin.h"

#include <limits>
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

namespace {

using secp_primitives::Scalar;

std::vector<unsigned char> SerializeAsset(const spark::CSparkAssetTxData& asset)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << asset;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

spark::CSparkAssetTxData RoundTrip(const spark::CSparkAssetTxData& asset)
{
    const std::vector<unsigned char> raw = SerializeAsset(asset);
    CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
    spark::CSparkAssetTxData out;
    ss >> out;
    BOOST_CHECK(ss.empty());
    const std::vector<unsigned char> again = SerializeAsset(out);
    BOOST_CHECK_EQUAL_COLLECTIONS(raw.begin(), raw.end(), again.begin(), again.end());
    return out;
}

const std::string kTransparentAdmin = "aFA2TbqG9cnhhzX5Yny2pBJRK5EaEqLCH7";

} // namespace

BOOST_FIXTURE_TEST_SUITE(sparkasset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(register_roundtrip)
{
    spark::CSparkAssetTxData asset;
    asset.setOperationType(spark::CSparkAssetTxData::opRegister);
    asset.setSymbol("FIRO");
    asset.setName("Firo");
    asset.setDescription("desc");
    asset.setMetadata("meta");
    asset.setAdminPublicAddress(kTransparentAdmin);
    asset.setIdentifier(0);
    asset.setPrecision(8);
    asset.setMaxSupply(1000);

    const spark::CSparkAssetTxData out = RoundTrip(asset);
    BOOST_CHECK(out.isRegister());
    BOOST_CHECK_EQUAL(out.getSymbol(), "FIRO");
    BOOST_CHECK_EQUAL(out.getAdminPublicAddress(), kTransparentAdmin);

    const std::vector<unsigned char> raw = SerializeAsset(asset);
    BOOST_CHECK_EQUAL(raw[0], 1);
    BOOST_REQUIRE(!raw.empty());
    const std::vector<unsigned char> trimmed(raw.begin(), raw.end() - 1);
    CDataStream truncated(trimmed, SER_NETWORK, PROTOCOL_VERSION);
    spark::CSparkAssetTxData decoded;
    BOOST_CHECK_THROW(truncated >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(fields_follow_operation)
{
    spark::CSparkAssetTxData nameModify;
    nameModify.setOperationType(spark::CSparkAssetTxData::opModifyName);
    nameModify.setSymbol("FIRO");
    nameModify.setName("New");
    nameModify.setDescription("short");
    nameModify.setAdminPublicAddress(kTransparentAdmin);

    spark::CSparkAssetTxData nameModifyLongDesc = nameModify;
    nameModifyLongDesc.setDescription(std::string(300, 'x'));
    BOOST_CHECK_EQUAL(SerializeAsset(nameModify).size(), SerializeAsset(nameModifyLongDesc).size());

    spark::CSparkAssetTxData nameModifyLongName = nameModify;
    nameModifyLongName.setName(std::string(40, 'N'));
    BOOST_CHECK(SerializeAsset(nameModifyLongName).size() > SerializeAsset(nameModify).size());

    const spark::CSparkAssetTxData nameOut = RoundTrip(nameModify);
    BOOST_CHECK(nameOut.isNameModify());
    BOOST_CHECK_EQUAL(nameOut.getAdminPublicAddress(), kTransparentAdmin);

    spark::CSparkAssetTxData descriptionModify;
    descriptionModify.setOperationType(spark::CSparkAssetTxData::opModifyDescription);
    descriptionModify.setSymbol("FIRO");
    descriptionModify.setDescription("updated");
    descriptionModify.setName("ignored");
    descriptionModify.setAdminPublicAddress(kTransparentAdmin);
    spark::CSparkAssetTxData descriptionModifyLongName = descriptionModify;
    descriptionModifyLongName.setName(std::string(40, 'N'));
    BOOST_CHECK_EQUAL(SerializeAsset(descriptionModify).size(), SerializeAsset(descriptionModifyLongName).size());
    BOOST_CHECK(RoundTrip(descriptionModify).isDescriptionModify());

    spark::CSparkAssetTxData metadataModify;
    metadataModify.setOperationType(spark::CSparkAssetTxData::opModifyMetadata);
    metadataModify.setSymbol("FIRO");
    metadataModify.setMetadata("{ok}");
    metadataModify.setDescription("ignored");
    metadataModify.setAdminPublicAddress(kTransparentAdmin);
    BOOST_CHECK(RoundTrip(metadataModify).isMetadataModify());
    BOOST_CHECK_EQUAL(RoundTrip(metadataModify).getAdminPublicAddress(), kTransparentAdmin);

    spark::CSparkAssetTxData transfer;
    transfer.setOperationType(spark::CSparkAssetTxData::opTransfer);
    transfer.setSymbol("FIRO");
    transfer.setName("ignored");
    transfer.setAdminPublicAddress(kTransparentAdmin);
    transfer.setTransferAddress("aDifferentAdminAddress111111111111");
    const std::vector<unsigned char> receiverProof{0x01, 0x02, 0x03};
    transfer.setReceiverProof(receiverProof);
    const spark::CSparkAssetTxData transferOut = RoundTrip(transfer);
    BOOST_CHECK(transferOut.isTransfer());
    BOOST_CHECK_EQUAL(transferOut.getAdminPublicAddress(), kTransparentAdmin);
    BOOST_CHECK_EQUAL(transferOut.getTransferAddress(), "aDifferentAdminAddress111111111111");
    BOOST_CHECK_EQUAL_COLLECTIONS(
        transferOut.getReceiverOwnershipProof().begin(),
        transferOut.getReceiverOwnershipProof().end(),
        receiverProof.begin(),
        receiverProof.end());

    spark::CSparkAssetTxData transferLongName = transfer;
    transferLongName.setName(std::string(40, 'N'));
    BOOST_CHECK_EQUAL(SerializeAsset(transfer).size(), SerializeAsset(transferLongName).size());
}

BOOST_AUTO_TEST_CASE(transfer_receiver_proof_is_checked)
{
    const auto* params = spark::Params::get_default();
    spark::SpendKey currentKey(params);
    spark::Address currentAddr(spark::IncomingViewKey(spark::FullViewKey(currentKey)), 1);
    spark::SpendKey receiverKey(params);
    spark::IncomingViewKey receiverView{spark::FullViewKey(receiverKey)};
    spark::Address receiverAddr(receiverView, 1);

    const std::uint64_t assetType = 7;
    const std::string currentAdmin = currentAddr.encode(spark::GetNetworkType());
    const std::string dest = receiverAddr.encode(spark::GetNetworkType());

    spark::CSparkAssetTxData transfer;
    transfer.setOperationType(spark::CSparkAssetTxData::opTransfer);
    transfer.setSymbol("FIRO");
    transfer.setAdminPublicAddress(currentAdmin);
    transfer.setTransferAddress(dest);
    std::string error;
    BOOST_CHECK(!transfer.Verify(error));
    BOOST_CHECK_EQUAL(error, "Missing receiver ownership proof");
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(assetType, currentAdmin, dest, {}));

    spark::OwnershipProof proof;
    receiverAddr.prove_own(
        spark::GetSpatsAssetTransferReceiverM(assetType, currentAdmin, dest),
        receiverKey,
        receiverView,
        proof);
    spark::CSparkAssetTxData signedProof;
    signedProof.setReceiverProof(proof);
    const std::vector<unsigned char>& proofBytes = signedProof.getReceiverOwnershipProof();
    BOOST_CHECK(spark::VerifySpatsAssetReceiverProof(assetType, currentAdmin, dest, proofBytes));
    transfer.setReceiverProof(proofBytes);
    BOOST_CHECK(transfer.Verify());

    // The proof is bound to registry fields, not to a constructed transfer payload.
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(assetType + 1, currentAdmin, dest, proofBytes));
    spark::SpendKey otherAdminKey(params);
    spark::Address otherAdminAddr(spark::IncomingViewKey(spark::FullViewKey(otherAdminKey)), 1);
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(
        assetType, otherAdminAddr.encode(spark::GetNetworkType()), dest, proofBytes));

    spark::SpendKey otherKey(params);
    spark::Address otherAddr(spark::IncomingViewKey(spark::FullViewKey(otherKey)), 1);
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(
        assetType, currentAdmin, otherAddr.encode(spark::GetNetworkType()), proofBytes));

    // A Spark destination with a broken proof must not fall through to ECDSA.
    const std::vector<unsigned char> garbage(8, 0xff);
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(assetType, currentAdmin, dest, garbage));

    CKey transparentKey;
    transparentKey.MakeNewKey(true);
    const CBitcoinAddress transparentAddr(transparentKey.GetPubKey().GetID());
    BOOST_REQUIRE(transparentAddr.IsValid());
    const std::string transparentDest = transparentAddr.ToString();
    std::vector<unsigned char> transparentProof;
    BOOST_REQUIRE(transparentKey.SignCompact(
        spark::GetSpatsAssetTransferReceiverHash(assetType, currentAdmin, transparentDest),
        transparentProof));
    BOOST_CHECK(spark::VerifySpatsAssetReceiverProof(
        assetType, currentAdmin, transparentDest, transparentProof));
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(
        assetType + 1, currentAdmin, transparentDest, transparentProof));
    BOOST_CHECK(!spark::VerifySpatsAssetReceiverProof(
        assetType, currentAdmin, dest, transparentProof));

    const std::string encoded = spark::EncodeSpatsAssetReceiveData(dest, proofBytes);
    std::string parsedAddress = "sentinel";
    std::vector<unsigned char> parsedProof{0x01};
    BOOST_REQUIRE(spark::ParseSpatsAssetReceiveData(encoded, parsedAddress, parsedProof));
    BOOST_CHECK_EQUAL(parsedAddress, dest);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        parsedProof.begin(), parsedProof.end(), proofBytes.begin(), proofBytes.end());
    BOOST_CHECK(spark::VerifySpatsAssetReceiverProof(assetType, currentAdmin, parsedAddress, parsedProof));

    const std::string transparentEncoded = spark::EncodeSpatsAssetReceiveData(
        transparentDest, transparentProof);
    BOOST_REQUIRE(spark::ParseSpatsAssetReceiveData(transparentEncoded, parsedAddress, parsedProof));
    BOOST_CHECK_EQUAL(parsedAddress, transparentDest);
    BOOST_CHECK(spark::VerifySpatsAssetReceiverProof(
        assetType, currentAdmin, parsedAddress, parsedProof));

    parsedAddress = "sentinel";
    parsedProof = {0x01};
    BOOST_CHECK(!spark::ParseSpatsAssetReceiveData(dest, parsedAddress, parsedProof));
    BOOST_CHECK_EQUAL(parsedAddress, "sentinel");
    BOOST_CHECK_EQUAL(parsedProof.size(), 1u);
    BOOST_CHECK(!spark::ParseSpatsAssetReceiveData(dest + ":", parsedAddress, parsedProof));
    BOOST_CHECK_EQUAL(parsedAddress, "sentinel");
    BOOST_CHECK(!spark::ParseSpatsAssetReceiveData("not-an-address:ab", parsedAddress, parsedProof));
    BOOST_CHECK_EQUAL(parsedAddress, "sentinel");
    BOOST_CHECK_EQUAL(parsedProof.size(), 1u);
}

BOOST_AUTO_TEST_CASE(admin_proof_is_checked)
{
    const auto* params = spark::Params::get_default();
    spark::SpendKey adminKey(params);
    spark::IncomingViewKey adminView{spark::FullViewKey(adminKey)};
    spark::Address adminAddr(adminView, 1);
    const std::string admin = adminAddr.encode(spark::GetNetworkType());
    const secp_primitives::Scalar m(uint64_t(42));
    const uint256 dummy;

    BOOST_CHECK(!spark::VerifySpatsAssetAdminProof(admin, m, dummy, {}));

    spark::OwnershipProof proof;
    adminAddr.prove_own(m, adminKey, adminView, proof);
    spark::CSparkAssetTxData signedProof;
    signedProof.setOwnershipProof(proof);
    BOOST_CHECK(spark::VerifySpatsAssetAdminProof(
        admin, m, dummy, signedProof.getOwnershipProof()));
    BOOST_CHECK(!spark::VerifySpatsAssetAdminProof(
        admin, secp_primitives::Scalar(uint64_t(43)), dummy, signedProof.getOwnershipProof()));

    CKey transparentKey;
    transparentKey.MakeNewKey(true);
    const CBitcoinAddress transparentAddr(transparentKey.GetPubKey().GetID());
    BOOST_REQUIRE(transparentAddr.IsValid());
    const std::string transparentAdmin = transparentAddr.ToString();
    const uint256 hash = uint256S("11");
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(transparentKey.SignCompact(hash, signature));
    BOOST_CHECK(spark::VerifySpatsAssetAdminProof(transparentAdmin, m, hash, signature));
    BOOST_CHECK(!spark::VerifySpatsAssetAdminProof(transparentAdmin, m, uint256S("22"), signature));
    BOOST_CHECK(!spark::VerifySpatsAssetAdminProof(admin, m, hash, signature));
}

BOOST_AUTO_TEST_CASE(transparent_admin_must_be_p2pkh)
{
    CKey key;
    key.MakeNewKey(true);
    const CBitcoinAddress p2pkh(key.GetPubKey().GetID());
    BOOST_REQUIRE(p2pkh.IsValid());
    BOOST_CHECK(spark::IsValidAssetAdminAddress(p2pkh.ToString()));

    const CScript redeem = GetScriptForDestination(key.GetPubKey().GetID());
    const CBitcoinAddress p2sh{CScriptID(redeem)};
    BOOST_REQUIRE(p2sh.IsValid());
    BOOST_CHECK(p2sh.IsScript());
    BOOST_CHECK(!spark::IsValidAssetAdminAddress(p2sh.ToString()));

    spark::CSparkAssetTxData asset;
    asset.setOperationType(spark::CSparkAssetTxData::opRegister);
    asset.setSymbol("FIRO");
    asset.setName("Firo");
    asset.setAdminPublicAddress(p2sh.ToString());
    std::string error;
    BOOST_CHECK(!asset.Verify(error));
}

BOOST_AUTO_TEST_CASE(ownership_proof_is_stored_and_excluded_from_registre_message)
{
    spark::CSparkAssetTxData asset;
    asset.setOperationType(spark::CSparkAssetTxData::opRegister);
    asset.setSymbol("FIRO");
    asset.setName("Firo");
    asset.setAdminPublicAddress(kTransparentAdmin);

    const secp_primitives::Scalar message = spark::GetSpatsRegistreM(asset);
    const std::vector<unsigned char> rawBefore = SerializeAsset(asset);
    const uint256 bindBefore = spark::GetSpatsAssetBindHash(asset);

    spark::OwnershipProof proof;
    proof.t1 = secp_primitives::Scalar(uint64_t(7));
    asset.setOwnershipProof(proof);

    const std::vector<unsigned char> rawAfter = SerializeAsset(asset);
    BOOST_CHECK(rawBefore != rawAfter);
    BOOST_CHECK(spark::GetSpatsAssetBindHash(asset) == bindBefore);
    BOOST_CHECK(spark::GetSpatsRegistreM(asset) == message);

    asset.setName("Other");
    BOOST_CHECK(spark::GetSpatsAssetBindHash(asset) != bindBefore);
    asset.setName("Firo");

    const spark::CSparkAssetTxData out = RoundTrip(asset);
    BOOST_CHECK(SerializeAsset(out) == rawAfter);
    BOOST_CHECK(spark::GetSpatsRegistreM(out) == message);
}

BOOST_AUTO_TEST_CASE(unsupported_version_and_operation_fail)
{
    CDataStream badVersion(SER_NETWORK, PROTOCOL_VERSION);
    const std::uint32_t version = 99;
    badVersion << version;
    spark::CSparkAssetTxData decoded;
    BOOST_CHECK_THROW(badVersion >> decoded, std::ios_base::failure);

    spark::CSparkAssetTxData asset;
    asset.setOperationType(spark::CSparkAssetTxData::opRegister);
    asset.setSymbol("FIRO");
    asset.setAdminPublicAddress(kTransparentAdmin);
    std::vector<unsigned char> raw = SerializeAsset(asset);
    BOOST_REQUIRE(raw.size() > 4);
    raw[4] = 0xff;
    CDataStream badOp(raw, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(badOp >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(asset_supply_rejects_underflow_and_overflow)
{
    spark::CAssetState state;
    BOOST_CHECK(state.AddCirculatingSupply(1, 0, 5));
    BOOST_CHECK(!state.SubCirculatingSupply(1, 0, 6));
    BOOST_CHECK_EQUAL(state.GetCirculatingSupply(1, 0), 5u);
    BOOST_CHECK(!state.SubCirculatingSupply(2, 0, 1));
    BOOST_CHECK_EQUAL(state.GetCirculatingSupply(2, 0), 0u);
    BOOST_CHECK(state.SubCirculatingSupply(1, 0, 5));
    BOOST_CHECK_EQUAL(state.GetCirculatingSupply(1, 0), 0u);

    BOOST_CHECK(state.AddCirculatingSupply(1, 0, 1));
    BOOST_CHECK(!state.AddCirculatingSupply(1, 0, std::numeric_limits<std::uint64_t>::max()));
    BOOST_CHECK_EQUAL(state.GetCirculatingSupply(1, 0), 1u);
}

BOOST_AUTO_TEST_CASE(asset_registry_tracks_symbol_admin_and_nft_ids)
{
    spark::CAssetState state;

    spark::CSparkAssetTxData registered;
    registered.setOperationType(spark::CSparkAssetTxData::opRegister);
    registered.setSymbol("Firox");
    registered.setName("Example");
    registered.setAdminPublicAddress("admin1");
    registered.setMaxSupply(100);

    uint256 registerTx;
    registerTx.SetHex("11");
    BOOST_CHECK(state.CanRegister(registered));
    const auto assetType = state.Put(registered, registerTx, 10);
    BOOST_REQUIRE(assetType);
    BOOST_CHECK_EQUAL(*assetType, 1);
    BOOST_CHECK(state.IsSymbolTaken("firox"));
    BOOST_CHECK(!state.CanRegister(registered));

    spark::CSparkAssetTxData duplicate = registered;
    duplicate.setSymbol("FIROX");
    uint256 otherTx;
    otherTx.SetHex("22");
    BOOST_CHECK(!state.Put(duplicate, otherTx, 11));

    const auto replay = state.Put(registered, registerTx, 99);
    BOOST_REQUIRE(replay);
    BOOST_CHECK_EQUAL(*replay, *assetType);

    spark::CSparkAssetTxData rename;
    rename.setOperationType(spark::CSparkAssetTxData::opModifyName);
    rename.setSymbol("firox");
    rename.setName("Renamed");
    rename.setAdminPublicAddress("someone-else");
    BOOST_CHECK(!state.CanModify(rename));
    BOOST_CHECK(!state.Put(rename, otherTx, 12));

    rename.setAdminPublicAddress("admin1");
    BOOST_CHECK(state.CanModify(rename));
    uint256 renameTx;
    renameTx.SetHex("33");
    BOOST_REQUIRE(state.Put(rename, renameTx, 12));
    const auto afterRename = state.Get(*assetType);
    BOOST_REQUIRE(afterRename);
    BOOST_CHECK_EQUAL(afterRename->name, "Renamed");
    BOOST_CHECK_EQUAL(afterRename->adminPublicAddress, "admin1");

    spark::CSparkAssetTxData transfer;
    transfer.setOperationType(spark::CSparkAssetTxData::opTransfer);
    transfer.setSymbol("FIROX");
    transfer.setAdminPublicAddress("admin1");
    BOOST_CHECK(!state.CanTransfer(transfer));
    transfer.setTransferAddress("admin2");
    BOOST_CHECK(state.CanTransfer(transfer));
    uint256 transferTx;
    transferTx.SetHex("44");
    BOOST_REQUIRE(state.Put(transfer, transferTx, 13));
    const auto afterTransfer = state.Get(*assetType);
    BOOST_REQUIRE(afterTransfer);
    BOOST_CHECK_EQUAL(afterTransfer->adminPublicAddress, "admin2");
    BOOST_CHECK(!state.CanModify(rename));

    spark::CAssetState nfts;
    BOOST_CHECK_EQUAL(nfts.NextNFTIdentifier("Art"), 1);
    BOOST_CHECK(!nfts.HasNFTIdentifier("Art", 1));

    spark::CSparkAssetTxData nft;
    nft.setOperationType(spark::CSparkAssetTxData::opRegister);
    nft.setSymbol("Art");
    nft.setName("Art");
    nft.setAssetKind(spark::AssetKind::NonFungible);
    nft.setIdentifier(4);
    nft.setAdminPublicAddress("admin1");
    uint256 nftTx;
    nftTx.SetHex("55");
    BOOST_REQUIRE(nfts.Put(nft, nftTx, 1));
    BOOST_CHECK(nfts.HasNFTIdentifier("art", 4));
    BOOST_CHECK(!nfts.HasNFTIdentifier("art", 1));
    BOOST_CHECK_EQUAL(nfts.NextNFTIdentifier("ART"), 5);
}

BOOST_AUTO_TEST_CASE(registry_ops_require_spark_spend)
{
    spark::CSparkAssetTxData asset;
    asset.setOperationType(spark::CSparkAssetTxData::opRegister);
    asset.setSymbol("SIGH");
    asset.setName("Sighash");
    asset.setAdminPublicAddress(kTransparentAdmin);

    const auto& consensus = Params().GetConsensus();
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_SPARK;
    tx.vout.emplace_back(
        static_cast<CAmount>(consensus.nSpatsRegFee[asset.getSymbol().size()]) * COIN,
        GetScriptForDestination(CBitcoinAddress(consensus.stage3CommunityFundAddress).Get()));
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << asset;
    tx.vExtraPayload.assign(payload.begin(), payload.end());

    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    CValidationState state;
    spark::CSparkAssetPending pending;
    spark::CSparkAssetTxEffects effects;
    BOOST_CHECK(!spark::CheckSparkAssetTransaction(
        CTransaction(tx), view, state, consensus.nSpatsStartBlock + 1,
        false, true, pending, effects));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-spats-asset-admin-tx");
}

BOOST_AUTO_TEST_CASE(spats_mint_rejects_nft_value_other_than_one)
{
    const auto* params = spark::Params::get_default();
    const spark::SpendKey spendKey(params);
    const spark::FullViewKey fullViewKey(spendKey);
    const spark::IncomingViewKey incomingViewKey(fullViewKey);
    const spark::Address address(incomingViewKey, 1);
    std::vector<unsigned char> serialContext(spark::SCALAR_ENCODING, 0);
    const int height = Params().GetConsensus().nSpatsStartBlock + 1;

    spark::MintedCoinData minted;
    minted.address = address;
    minted.v = 2;
    minted.memo = "nft";
    minted.a = Scalar(uint64_t(3));
    minted.iota = Scalar(uint64_t(4));
    spark::MintTransaction mint(params, {minted}, serialContext);
    const std::vector<CDataStream> serialized = mint.getMintedCoinsSerialized();
    BOOST_REQUIRE_EQUAL(serialized.size(), 1U);
    CScript script;
    script << OP_SPATSMINT;
    script.insert(script.end(), serialized[0].begin(), serialized[0].end());
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_SPARK;
    tx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    tx.vout.emplace_back(0, script);

    CValidationState state;
    spark::CSparkTxInfo info;
    BOOST_CHECK(!spark::CheckSparkTransaction(
        CTransaction(tx), state, tx.GetHash(),
        false, height, false, true, &info));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "CheckSpatsMintTransaction : nft value must be 1");
    BOOST_CHECK(info.mints.empty());
}

BOOST_AUTO_TEST_CASE(spark_mint_rejects_asset_type)
{
    const auto* params = spark::Params::get_default();
    const spark::SpendKey spendKey(params);
    const spark::FullViewKey fullViewKey(spendKey);
    const spark::IncomingViewKey incomingViewKey(fullViewKey);
    const spark::Address address(incomingViewKey, 1);
    std::vector<unsigned char> serialContext(spark::SCALAR_ENCODING, 0);
    const auto& consensus = Params().GetConsensus();
    const int height = consensus.nSpatsStartBlock + 1;

    const auto makeMint = [&](const Scalar& a, const Scalar& iota) {
        spark::MintedCoinData minted;
        minted.address = address;
        minted.v = 1;
        minted.memo = "spark-mint";
        minted.a = a;
        minted.iota = iota;
        spark::MintTransaction mint(params, {minted}, serialContext);
        const std::vector<CDataStream> serialized = mint.getMintedCoinsSerialized();
        BOOST_REQUIRE_EQUAL(serialized.size(), 1U);
        CScript script;
        script << OP_SPARKMINT;
        script.insert(script.end(), serialized[0].begin(), serialized[0].end());
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint(uint256S("01"), 0));
        tx.vout.emplace_back(1, script);
        return tx;
    };

    const CMutableTransaction firoMint = makeMint(Scalar(uint64_t(0)), Scalar(uint64_t(0)));
    CValidationState firoState;
    spark::CSparkTxInfo firoInfo;
    BOOST_CHECK(spark::CheckSparkTransaction(
        CTransaction(firoMint), firoState, firoMint.GetHash(),
        false, height, false, true, &firoInfo));
    BOOST_CHECK_EQUAL(firoInfo.mints.size(), 1U);

    const CMutableTransaction assetMint = makeMint(Scalar(uint64_t(2)), Scalar(uint64_t(0)));
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    CValidationState assetState;
    spark::CSparkAssetPending pending;
    spark::CSparkAssetTxEffects effects;
    BOOST_CHECK(spark::CheckSparkAssetTransaction(
        CTransaction(assetMint), view, assetState, height,
        false, true, pending, effects));
    BOOST_CHECK(effects.minted.empty());

    spark::CSparkTxInfo mintInfo;
    BOOST_CHECK(!spark::CheckSparkTransaction(
        CTransaction(assetMint), assetState, assetMint.GetHash(),
        false, height, false, true, &mintInfo));
    int dos = 0;
    BOOST_CHECK(assetState.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);
    BOOST_CHECK_EQUAL(
        assetState.GetRejectReason(),
        "CheckSparkMintTransaction : spark mint with asset type");
    BOOST_CHECK(mintInfo.mints.empty());

    CValidationState iotaState;
    spark::CSparkTxInfo iotaInfo;
    const CMutableTransaction iotaMint = makeMint(Scalar(uint64_t(0)), Scalar(uint64_t(1)));
    BOOST_CHECK(!spark::CheckSparkTransaction(
        CTransaction(iotaMint), iotaState, iotaMint.GetHash(),
        false, height, false, true, &iotaInfo));
    BOOST_CHECK_EQUAL(
        iotaState.GetRejectReason(),
        "CheckSparkMintTransaction : spark mint with asset type");
    BOOST_CHECK(iotaInfo.mints.empty());
}

BOOST_AUTO_TEST_CASE(two_spats_mints_are_rejected)
{
    const int height = Params().GetConsensus().nSpatsStartBlock + 1;
    CScript mint;
    mint << OP_SPATSMINT;
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    tx.vout.emplace_back(0, mint);
    tx.vout.emplace_back(0, mint);

    CValidationState state;
    spark::CSparkTxInfo info;
    BOOST_CHECK(!spark::CheckSparkTransaction(
        CTransaction(tx), state, tx.GetHash(), false, height, false, true, &info));
    int dos = 0;
    BOOST_CHECK(state.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-mint-invalid");
    BOOST_CHECK(info.mints.empty());
}

BOOST_AUTO_TEST_CASE(spats_spend_payload_must_be_canonical)
{
    const auto* params = spark::Params::get_default();
    spats::SpendTransaction spend(params);
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << spend;
    std::vector<unsigned char> raw(serialized.begin(), serialized.end());

    secp_primitives::GroupElement infinity;
    secp_primitives::GroupElement generator;
    generator.set_base_g();
    CDataStream infinityBytes(SER_NETWORK, PROTOCOL_VERSION);
    infinityBytes << infinity;
    CDataStream generatorBytes(SER_NETWORK, PROTOCOL_VERSION);
    generatorBytes << generator;
    const std::vector<unsigned char> infinityEncoding(infinityBytes.begin(), infinityBytes.end());
    const std::vector<unsigned char> generatorEncoding(generatorBytes.begin(), generatorBytes.end());
    BOOST_REQUIRE_EQUAL(infinityEncoding.size(), 34u);
    BOOST_REQUIRE_EQUAL(generatorEncoding.size(), 34u);

    int replaced = 0;
    for (std::size_t i = 0; i + infinityEncoding.size() <= raw.size(); ) {
        if (std::equal(infinityEncoding.begin(), infinityEncoding.end(), raw.begin() + i)) {
            std::copy(generatorEncoding.begin(), generatorEncoding.end(), raw.begin() + i);
            ++replaced;
            i += infinityEncoding.size();
        } else {
            ++i;
        }
    }
    BOOST_REQUIRE(replaced > 0);

    const auto makeTx = [](const std::vector<unsigned char>& payload) {
        CMutableTransaction tx;
        tx.nVersion = 3;
        tx.nType = TRANSACTION_SPARK_V2;
        tx.vin.resize(1);
        tx.vin[0].scriptSig << OP_SPATSSPEND;
        tx.vExtraPayload = payload;
        return tx;
    };

    BOOST_CHECK_NO_THROW(spark::ParseSpatsSpend(makeTx(raw)));

    const auto generatorAt = std::search(
        raw.begin(), raw.end(), generatorEncoding.begin(), generatorEncoding.end());
    BOOST_REQUIRE(generatorAt != raw.end());
    std::vector<unsigned char> mutated = raw;
    mutated[static_cast<std::size_t>(generatorAt - raw.begin()) + 33] = 2;
    bool rejected = false;
    try {
        spark::ParseSpatsSpend(makeTx(mutated));
    } catch (const std::invalid_argument& error) {
        rejected = std::string(error.what()).find("Non-canonical Spats spend payload") != std::string::npos;
    }
    BOOST_CHECK(rejected);
}

BOOST_AUTO_TEST_CASE(spats_mint_and_burn_are_pruned_from_utxo_set)
{
    CScript mint;
    mint << OP_SPATSMINT;
    BOOST_CHECK(mint.IsSpatsMint());
    BOOST_CHECK(mint.IsUnspendable());

    CScript burn;
    burn << OP_SPATSBURN;
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << std::make_pair(Scalar(uint64_t(2)), Scalar(uint64_t(0)));
    payload << CAmount(COIN);
    burn.insert(burn.end(), payload.begin(), payload.end());
    BOOST_CHECK(burn.IsSpatsBurn());
    BOOST_CHECK(burn.IsUnspendable());

    std::pair<Scalar, Scalar> assetId;
    CAmount amount = 0;
    BOOST_REQUIRE(spark::ParseSpatsBurn(burn, assetId, amount));
    BOOST_CHECK_EQUAL(amount, COIN);
    BOOST_CHECK(assetId.first == Scalar(uint64_t(2)));
    BOOST_CHECK(assetId.second.isZero());

    CScript leftover = burn;
    leftover << OP_TRUE;
    BOOST_CHECK(!spark::ParseSpatsBurn(leftover, assetId, amount));

    CScript noAmount;
    noAmount << OP_SPATSBURN;
    CDataStream idOnly(SER_NETWORK, PROTOCOL_VERSION);
    idOnly << std::make_pair(Scalar(uint64_t(2)), Scalar(uint64_t(0)));
    noAmount.insert(noAmount.end(), idOnly.begin(), idOnly.end());
    BOOST_CHECK(!spark::ParseSpatsBurn(noAmount, assetId, amount));

    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    const COutPoint mintOut(uint256S("aa"), 0);
    const COutPoint burnOut(uint256S("bb"), 1);
    view.AddCoin(mintOut, Coin(CTxOut(0, mint), 1, false), false);
    view.AddCoin(burnOut, Coin(CTxOut(0, burn), 1, false), false);
    BOOST_CHECK(view.AccessCoin(mintOut).IsSpent());
    BOOST_CHECK(view.AccessCoin(burnOut).IsSpent());

    txnouttype whichType;
    BOOST_CHECK(IsStandard(burn, whichType));
    BOOST_CHECK_EQUAL(whichType, TX_SPATSBURN);
    BOOST_CHECK(!IsStandard(leftover, whichType));
    BOOST_CHECK(!IsStandard(noAmount, whichType));
    CScript shortBurn;
    shortBurn << OP_SPATSBURN;
    BOOST_CHECK(!IsStandard(shortBurn, whichType));
}

BOOST_AUTO_TEST_CASE(asset_type_from_scalar_fails_closed)
{
    BOOST_CHECK_EQUAL(*spark::GetSpatsScalarAsUint64(Scalar(uint64_t(0))), 0u);
    BOOST_CHECK_EQUAL(*spark::GetSpatsScalarAsUint64(Scalar(uint64_t(10))), 10u);
    BOOST_CHECK_EQUAL(
        *spark::GetSpatsScalarAsUint64(Scalar(std::numeric_limits<std::uint64_t>::max())),
        std::numeric_limits<std::uint64_t>::max());

    unsigned char oversized[32] = {};
    oversized[0] = 1;
    BOOST_CHECK(!spark::GetSpatsScalarAsUint64(Scalar(oversized)));

    CSparkMintMeta meta;
    meta.a = Scalar(uint64_t(7));
    meta.iota = Scalar(uint64_t(0));
    BOOST_REQUIRE(meta.GetAssetType());
    BOOST_CHECK_EQUAL(*meta.GetAssetType(), 7u);
    BOOST_REQUIRE(meta.GetIdentifier());
    BOOST_CHECK_EQUAL(*meta.GetIdentifier(), 0u);

    meta.a = Scalar(oversized);
    BOOST_CHECK(!meta.GetAssetType());
}

BOOST_AUTO_TEST_SUITE_END()
