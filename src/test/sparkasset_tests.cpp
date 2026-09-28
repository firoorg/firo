// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spark/assetstate.h"
#include "spark/sparkasset.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

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

BOOST_AUTO_TEST_CASE(register_roundtrip_includes_proof_for_transparent_admin)
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
    BOOST_REQUIRE(raw.size() > spark::OwnershipProof::memoryRequired());
    const std::vector<unsigned char> trimmed(raw.begin(), raw.end() - spark::OwnershipProof::memoryRequired());
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
    transfer.setRecieverProof("receiver-proof");
    const spark::CSparkAssetTxData transferOut = RoundTrip(transfer);
    BOOST_CHECK(transferOut.isTransfer());
    BOOST_CHECK_EQUAL(transferOut.getAdminPublicAddress(), kTransparentAdmin);
    BOOST_CHECK_EQUAL(transferOut.getTransferAddress(), "aDifferentAdminAddress111111111111");
    BOOST_CHECK_EQUAL(transferOut.getRecieverOwnershipProof(), "receiver-proof");

    spark::CSparkAssetTxData transferLongName = transfer;
    transferLongName.setName(std::string(40, 'N'));
    BOOST_CHECK_EQUAL(SerializeAsset(transfer).size(), SerializeAsset(transferLongName).size());
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

    spark::OwnershipProof proof;
    proof.t1 = secp_primitives::Scalar(uint64_t(7));
    asset.setOwnershipProof(proof);

    const std::vector<unsigned char> rawAfter = SerializeAsset(asset);
    BOOST_CHECK(rawBefore != rawAfter);
    BOOST_CHECK(spark::GetSpatsRegistreM(asset) == message);

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

BOOST_AUTO_TEST_SUITE_END()
