#include <boost/exception/diagnostic_information.hpp>

#include "state.h"
#include "sparkname.h"
#include "../validation.h"
#include "../batchproof_container.h"
#include "../base58.h"	// for CBitcoinAddress
#include "../spats/actions.hpp"
#include "../spats/wallet.hpp"
#include "../libspark/keys.h"

namespace spark {

static CSparkState sparkState;

static bool CheckLTag(
        CValidationState &state,
        CSparkTxInfo *sparkTxInfo,
        const GroupElement& lTag,
        int nHeight,
        bool fConnectTip) {
    // check for Spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
            sparkTxInfo->spentLTags.find(lTag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same linking tag in the same block"));

    // check for used linking tags in state
    if (sparkState.IsUsedLTag(lTag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark coin has been used"));
        }
    }
    return true;
}

bool BuildSparkStateFromIndex(CChain *chain) {
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        sparkState.AddBlock(blockIndex);
        CSparkNameManager::GetInstance()->AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
            "Latest ID for Spark coin group  %d\n",
            sparkState.GetLatestCoinID());
    return true;
}

// CSparkTxInfo
void CSparkTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it.
    sort(mints.begin(), mints.end(),
         [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
             CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
             ds1 << m1;
             ds2 << m2;
             return ds1.str() < ds2.str();
         });

    // Mark this info as complete
    fInfoIsComplete = true;
}

bool IsSparkAllowed()
{
    LOCK(cs_main);
    return IsSparkAllowed(chainActive.Height());
}

bool IsSparkAllowed(int height)
{
    return height >= ::Params().GetConsensus().nSparkStartBlock;
}

bool IsSpatsStarted()
{
    LOCK(cs_main);
    return IsSpatsStarted(chainActive.Height());
}

bool IsSpatsStarted(int height)
{
    return height >= ::Params().GetConsensus().nSpatsStartBlock;
}

unsigned char GetNetworkType() {
    if (::Params().GetConsensus().IsMain())
        return ADDRESS_NETWORK_MAINNET;
    if (::Params().GetConsensus().IsTestnet())
        return ADDRESS_NETWORK_TESTNET;
    if (::Params().GetConsensus().IsDevnet())
        return ADDRESS_NETWORK_DEVNET;
    return ADDRESS_NETWORK_REGTEST;
}

/*
 * Util funtions
 */
size_t CountCoinInBlock(CBlockIndex *index, int id) {
    return index->sparkMintedCoins.count(id) > 0
    ? index->sparkMintedCoins[id].size() : 0;
}

std::vector<unsigned char> GetAnonymitySetHash(CBlockIndex *index, int group_id, bool generation = false) {
    std::vector<unsigned char> out_hash;

    CSparkState::SparkCoinGroupInfo coinGroup;
    if (!sparkState.GetCoinGroupInfo(group_id, coinGroup))
        return out_hash;

    if ((coinGroup.firstBlock == coinGroup.lastBlock && generation) || (coinGroup.nCoins == 0))
        return out_hash;

    while (index != coinGroup.firstBlock) {
        if (index->sparkSetHash.count(group_id) > 0) {
            out_hash = index->sparkSetHash[group_id];
            break;
        }
        index = index->pprev;
    }
    return out_hash;
}

void ParseSparkMintTransaction(const std::vector<CScript>& scripts, MintTransaction& mintTransaction)
{
    std::vector<CDataStream> serializedCoins;
    for (const auto& script : scripts) {
        if (!script.IsSparkMintType())
            throw std::invalid_argument("Script is not a Spark mint");

        std::vector<unsigned char> serialized(script.begin() + 1, script.end());
        size_t size = spark::Coin::memoryRequired() + 8; // 8 is the size of uint64_t
        if (serialized.size() < size) {
            throw std::invalid_argument("Script is not a valid Spark mint");
        }

        CDataStream stream(
                std::vector<unsigned char>(serialized.begin(), serialized.end()),
                SER_NETWORK,
                PROTOCOL_VERSION
        );

        serializedCoins.push_back(stream);
    }
    try {
        mintTransaction.setMintTransaction(serializedCoins);
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spark mint transaction");
    }
}

void ParseSpatsMintCoinTransaction(const CScript& script, MintTransaction& mintTransaction, spark::OwnershipProof& ownershipProof,
                                   spats::public_address_t& initiator_public_address)
{
    if (!script.IsSpatsMintCoin())
        throw std::invalid_argument("Script is not a Spats coin mint");

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    const std::size_t proofsize = ownershipProof.memoryRequired();

    const size_t size = spark::Coin::memoryRequiredSpats() + proofsize; // TODO match to additionalTxSize in CSparkWallet::CreateSpatsMintTransaction() closer
    if (serialized.size() < size) {
        throw std::invalid_argument("Script is not a valid Spats coin mint");
    }

    std::vector<CDataStream> serializedCoins = { CDataStream( serialized, SER_NETWORK, PROTOCOL_VERSION ) };

    try {
        mintTransaction.setMintTransaction(serializedCoins);
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spats coin mint");
    }

    auto& stream = serializedCoins.front();
    stream >> initiator_public_address >> ownershipProof;
}

void ParseSparkMintCoin(const CScript& script, spark::Coin& txCoin)
{
    if (!script.IsSparkMintType())
        throw std::invalid_argument("Script is not a Spark mint");

    if (script.size() < 213) {
        throw std::invalid_argument("Script is not a valid Spark Mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    CDataStream stream(
            std::vector<unsigned char>(serialized.begin(), serialized.end()),
            SER_NETWORK,
            PROTOCOL_VERSION
    );

    try {
        stream >> txCoin;
    } catch (const std::exception &) {
        throw std::invalid_argument("Unable to deserialize Spark mint");
    }
}

spark::SpendTransaction ParseSparkSpend(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND && tx.nVersion >= 3 && tx.nType == TRANSACTION_SPARK) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else {
        throw CBadTxIn();
    }
    const spark::Params* params = spark::Params::get_default();
    spark::SpendTransaction spendTransaction(params);
    serialized >> spendTransaction;
    return spendTransaction;
}

static spats::CreateAssetAction ParseSpatsCreateTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsCreate());
    if (tx.vout.size() < 3)
        throw CBadTxIn();
    const CScript& creation_script = tx.vout.front().scriptPubKey;
    if (!creation_script.IsSpatsCreate())
        throw CBadTxIn();

    try{
        std::vector<unsigned char> serialized(creation_script.begin() + 1, creation_script.end());
        auto asset_serialization_size = serialized.size();
        const void* const asset_serialization_start_address = serialized.data();
        CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        assert(stream.size() == asset_serialization_size);
        spats::CreateAssetAction action(deserialize, stream);
        const auto &new_asset = action.get();
        asset_serialization_size -= stream.size();
#if 0   // TODO remove
        spark::OwnershipProof proof;
        stream >> proof;
        LogPrintf("ParseSpatsCreateTransaction address ownership proof: %s\n", proof);
#endif
        const auto& b = get_base(new_asset);
        const auto& admin_public_address = b.admin_public_address();
        const Address a = CSparkWallet::decodeAddress(admin_public_address);
#if 0   // TODO remove
        const auto scalar_of_proof = spats::Wallet::compute_new_spark_asset_serialization_scalar(
            b, {static_cast<const unsigned char*>(asset_serialization_start_address), asset_serialization_size});
        LogPrintf("ParseSpatsCreateTransaction scalar_of_proof: %s\n", scalar_of_proof);
        if (!a.verify_own(scalar_of_proof, proof))
            throw CBadTxIn();
#endif
        const auto& burntx = tx.vout[1];
        // If somehow the creation fee is greater than required, i.e. the originator wants to burn more of his money than required, then it's fine with us, I think.
        // But less than required is not allowed, of course.
        if (burntx.nValue < spats::compute_new_spark_asset_fee(b.naming().symbol.get()))
            throw CBadTxIn();
        if (GetScriptForDestination(CBitcoinAddress(std::string(firo_burn_address)).Get()) != burntx.scriptPubKey)
            throw CBadTxIn();

        const auto& potential_coin_script = tx.vout.back().scriptPubKey;
        const bool has_coin_script = potential_coin_script.IsSpatsMintCoin();
        if (!has_coin_script)   // 07/25 new guarantee
            throw CBadTxIn();
        if (std::find_if(tx.vout.begin(), tx.vout.end() - 1, [](const CTxOut& out) { return out.scriptPubKey.IsSpatsMintCoin(); }) != tx.vout.end() - 1)
            throw CBadTxIn();   // more than 1 spats coin in one tx is not allowed

        const auto initial_supply = spats::get_total_supply(action.get());
#if 0   // TODO remove
        if (has_coin_script != !!initial_supply)
            throw CBadTxIn();   // has initial supply but no spats coin, or doesn't have initial supply but has spats coin
#endif
        if (has_coin_script) {  // TODO remove the condition, as it will always be true here from now on (07/25)
            const auto& coin_script = potential_coin_script;
            const spark::Params* params = spark::Params::get_default();
            MintTransaction mint_transaction(params);
            spark::OwnershipProof ownership_proof;
            spats::public_address_t initiator_public_address;
            ParseSpatsMintCoinTransaction(coin_script, mint_transaction, ownership_proof, initiator_public_address);	// may throw
            if (!mint_transaction.verify())
                throw CBadTxIn();
            if (!a.verify_own(GetSpatsMintM(tx), ownership_proof))
                throw CBadTxIn();
            if (initiator_public_address != admin_public_address)
                throw CBadTxIn();
            const auto& coins = mint_transaction.getCoins();
            if (coins.size() != 1)
                throw CBadTxIn();
            auto coin = coins.front();
            if (coin.v != tx.vout.back().nValue || coin.v != initial_supply.raw())
                throw CBadTxIn();
            if (spats::asset_type_t{std::stoull(coin.a.tostring())} != b.asset_type())
                throw CBadTxIn();
            if (spats::identifier_t{std::stoull(coin.iota.tostring())} != spats::get_identifier(new_asset).value_or(spats::identifier_t{}))
                throw CBadTxIn();
            // TODO should we check that coin.type is COIN_TYPE_MINT_V2?
            action.set_coin(std::move(coin));
        }

        return action;
    }
    catch (...) {
        throw CBadTxIn();
    }
}

static spats::UnregisterAssetAction ParseSpatsUnregisterTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsUnregister());
    if (tx.vout.size() < 1)
        throw CBadTxIn();
    const CScript& unregistration_script = tx.vout.front().scriptPubKey;
    if (!unregistration_script.IsSpatsUnregister())
        throw CBadTxIn();

    try{
        std::vector<unsigned char> serialized(unregistration_script.begin() + 1, unregistration_script.end());
        auto action_serialization_size = serialized.size();
        const void* const action_serialization_start_address = serialized.data();
        CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        assert(stream.size() == action_serialization_size);
        spats::UnregisterAssetAction action(deserialize, stream);
        const auto &unreg_params = action.get();
        action_serialization_size -= stream.size();
        spark::OwnershipProof proof;
        stream >> proof;
        LogPrintf("ParseSpatsUnregisterTransaction address ownership proof: %s\n", proof);
        Address a(spark::Params::get_default());
        a.decode(unreg_params.initiator_public_address());
        const auto scalar_of_proof = spats::Wallet::compute_unregister_spark_asset_serialization_scalar(
            unreg_params, {static_cast<const unsigned char*>(action_serialization_start_address), action_serialization_size});
        LogPrintf("ParseSpatsUnregisterTransaction scalar_of_proof: %s\n", scalar_of_proof);
        if (!a.verify_own(scalar_of_proof, proof))
            throw CBadTxIn();
        return action;
    }
    catch (...) {
        throw CBadTxIn();
    }
}

static spats::ModifyAssetAction ParseSpatsModifyTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsModify());
    if (tx.vout.size() < 1)
        throw CBadTxIn();
    const CScript& modification_script = tx.vout.front().scriptPubKey;
    if (!modification_script.IsSpatsModify())
        throw CBadTxIn();

    try{
        std::vector<unsigned char> serialized(modification_script.begin() + 1, modification_script.end());
        auto action_serialization_size = serialized.size();
        const void* const action_serialization_start_address = serialized.data();
        CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        assert(stream.size() == action_serialization_size);
        spats::ModifyAssetAction action(deserialize, stream);
        const auto &asset_modification = action.get();
        action_serialization_size -= stream.size();
        spark::OwnershipProof proof;
        stream >> proof;
        LogPrintf("ParseSpatsModifyTransaction address ownership proof: %s\n", proof);
        const auto& b = get_base(asset_modification);
        Address a(spark::Params::get_default());
        a.decode(b.initiator_public_address());
        const auto scalar_of_proof = spats::Wallet::compute_modify_spark_asset_serialization_scalar(
            b, {static_cast<const unsigned char*>(action_serialization_start_address), action_serialization_size});
        LogPrintf("ParseSpatsModifyTransaction scalar_of_proof: %s\n", scalar_of_proof);
        if (!a.verify_own(scalar_of_proof, proof))
            throw CBadTxIn();
        return action;
    }
    catch (...) {
        throw CBadTxIn();
    }
}

#if 0   // TODO remove
static spats::MintAction ParseSpatsMintTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsMint());
    if (tx.vout.size() < 2)
        throw CBadTxIn();

    const CScript& mint_script = tx.vout.front().scriptPubKey;
    // there may (always, rather?) be 1 more OP_SPARKSMINT outs in-between these two endpoints
    const CScript& coin_script = tx.vout.back().scriptPubKey;
    if (!mint_script.IsSpatsMint())
        throw CBadTxIn();

    try{
        std::vector<unsigned char> serialized(mint_script.begin() + 1, mint_script.end());
        auto action_serialization_size = serialized.size();
        const void* const action_serialization_start_address = serialized.data();
        CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        assert(stream.size() == action_serialization_size);
        spats::MintAction action(deserialize, stream);
        const auto &mint_params = action.get();
        action_serialization_size -= stream.size();
        spark::OwnershipProof proof;
        stream >> proof;
        LogPrintf("ParseSpatsMintTransaction address ownership proof: %s\n", proof);
        Address a(spark::Params::get_default());
        a.decode(mint_params.initiator_public_address());
        const auto scalar_of_proof = spats::Wallet::compute_mint_asset_supply_serialization_scalar(
            mint_params, {static_cast<const unsigned char*>(action_serialization_start_address), action_serialization_size});
        LogPrintf("ParseSpatsMintTransaction scalar_of_proof: %s\n", scalar_of_proof);
        if (!a.verify_own(scalar_of_proof, proof))
            throw CBadTxIn();

        const spark::Params* params = spark::Params::get_default();
        MintTransaction mintTransaction(params);
        spark::OwnershipProof ownershipProof;
        ParseSpatsMintCoinTransaction(coin_script, mintTransaction, ownershipProof);	// may throw
        if (!mintTransaction.verify())
            throw CBadTxIn();
        const auto& coins = mintTransaction.getCoins();
        if (coins.size() != 1)
            throw CBadTxIn();
        auto coin = coins.front();
        if (coin.v != tx.vout.back().nValue || coin.v != mint_params.raw_new_supply())
            throw CBadTxIn();
        action.set_coin(std::move(coin));

        return action;
    }
    catch (...) {
        throw CBadTxIn();
    }
}

static spats::BurnAction<> ParseSpatsBurnTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsBurn());
    if (tx.vout.size() != 2)
        throw CBadTxIn();
    const CScript& burn_script = tx.vout.front().scriptPubKey;
    if (!burn_script.IsSpatsBurn())
        throw CBadTxIn();
    const auto& burn_out = tx.vout.back();
    if (!burn_out.scriptPubKey.IsSpatsBurnAmount())
        throw CBadTxIn();

    try{
        std::vector<unsigned char> serialized(burn_script.begin() + 1, burn_script.end());
        auto action_serialization_size = serialized.size();
        const void* const action_serialization_start_address = serialized.data();
        CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        assert(stream.size() == action_serialization_size);
        spats::BurnAction<> action(deserialize, stream);
        const auto &burn_params = action.get();
        action_serialization_size -= stream.size();
        spark::OwnershipProof proof;
        stream >> proof;
        LogPrintf("ParseSpatsBurnTransaction address ownership proof: %s\n", proof);
        Address a(spark::Params::get_default());
        a.decode(burn_params.initiator_public_address());
        const auto scalar_of_proof = spats::Wallet::compute_burn_asset_supply_serialization_scalar(
            burn_params, {static_cast<const unsigned char*>(action_serialization_start_address), action_serialization_size});
        LogPrintf("ParseSpatsBurnTransaction scalar_of_proof: %s\n", scalar_of_proof);
        if (!a.verify_own(scalar_of_proof, proof))
            throw CBadTxIn();

        if (burn_out.nValue != burn_params.burn_amount().raw())
            throw CBadTxIn();
        serialized.assign(burn_out.scriptPubKey.begin() + 1, burn_out.scriptPubKey.end());
        CDataStream burn_out_stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
        Scalar asset_type;
        stream >> asset_type;
        if (std::stoull(asset_type.tostring()) != utils::to_underlying(burn_params.asset_type()))
            throw CBadTxIn();

        return action;
    }
    catch (...) {
        throw CBadTxIn();
    }
}
#endif

static spats::Action ParseSpatsTransaction(const CTransaction &tx)
{
    assert(tx.IsSpatsTransaction());
    if (tx.IsSpatsCreate())
        return ParseSpatsCreateTransaction(tx);
    if (tx.IsSpatsUnregister())
        return ParseSpatsUnregisterTransaction(tx);
    if (tx.IsSpatsModify())
        return ParseSpatsModifyTransaction(tx);
    assert(!tx.IsSpatsCreate());    // Important, handled and taken out of the way above.
    if (tx.HasSpatsMintCoin()) {    // So this for sure is just a mint tx, not a 'create'.
        auto [action, coin] = ExtractSpatsMintAction(tx);
        action.set_coin(std::move(coin));
        return action;
    }
    if (tx.HasSpatsBurnAmount())
        return ExtractSpatsBurnAction(tx);
    // TODO more
    throw CBadTxIn();
}

spats::SpendTransaction ParseSpatsSpend(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND && tx.nVersion >= 3 && tx.nType == TRANSACTION_SPARK) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else {
        throw CBadTxIn();
    }
    const spark::Params* params = spark::Params::get_default();
    spats::SpendTransaction spendTransaction(params);
    serialized >> spendTransaction;
    return std::move(spendTransaction);
}


Scalar GetSpatsMintM(const CTransaction& tx)
{
    CMutableTransaction txTemp = tx;
    for (auto& txout : txTemp.vout)
        if (txout.scriptPubKey.IsSpatsMintCoin()) {
            const auto proof_size = spark::OwnershipProof::memoryRequired();
            assert(txout.scriptPubKey.size() >= proof_size);
            std::fill_n(txout.scriptPubKey.end() - proof_size, proof_size, 0);
        }
    spark::Hash hash(LABEL_TRANSCRIPT_SPATS_MINT);
    CDataStream serializedTx(SER_NETWORK, PROTOCOL_VERSION);
    serializedTx << txTemp;

    hash.include(serializedTx);
    return hash.finalize_scalar();
}

std::vector<GroupElement> GetSparkUsedTags(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND) {
        spark::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSparkSpend(tx);
        return  spendTransaction.getUsedLTags();
    } else if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
        spats::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSpatsSpend(tx);
        return  spendTransaction.getUsedLTags();
    }

    return std::vector<GroupElement>();
}

CAmount GetSparkFee(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();
    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND) {
        spark::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSparkSpend(tx);
        return  spendTransaction.getFee();
    } else if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
        spats::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSpatsSpend(tx);
        return  spendTransaction.getFee();
    }
    return CAmount();
}

std::map<uint64_t, uint256> getBlockHashes(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND) {
        spark::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSparkSpend(tx);
        return  spendTransaction.getBlockHashes();
    }
    else if (tx.vin[0].scriptSig[0] == OP_SPATSSPEND) {
        spats::SpendTransaction spendTransaction(params);
        spendTransaction = ParseSpatsSpend(tx);
        return  spendTransaction.getBlockHashes();
    }
    return std::map<uint64_t, uint256>();
}

std::vector<spark::Coin> GetSparkMintCoins(const CTransaction &tx)
{
    std::vector<spark::Coin> result;

    if (tx.IsSparkTransaction()) {
        std::vector<unsigned char> serial_context = getSerialContext(tx);
        for (const auto& vout : tx.vout) {
            const auto& script = vout.scriptPubKey;
            if (script.IsSparkMintType()) {
                try {
                    spark::Coin coin(Params::get_default());
                    ParseSparkMintCoin(script, coin);
                    coin.setSerialContext(serial_context);
                    result.push_back(coin);
                } catch (const std::exception &) {
                    //Continue
                }
            }
        }
    }

    return result;
}

size_t GetSpendInputs(const CTransaction &tx) {
    return tx.IsSparkSpend() ?
           GetSparkUsedTags(tx).size() : 0;
}

CAmount GetSpendTransparentAmount(const CTransaction& tx) {
    CAmount result = 0;
    if (!tx.IsSparkSpend())
        return 0;

    for (const CTxOut &txout : tx.vout)
        result += txout.nValue;
    return result;
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockSpark(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {

    bool fBackupRewrittenSparkNames = false;
    
    // Add spark transaction information to index
    if (pblock && pblock->sparkTxInfo) {
        if (!fJustCheck) {
            pindexNew->sparkMintedCoins.clear();
            pindexNew->spentLTags.clear();
            pindexNew->sparkSetHash.clear();
            pindexNew->spats_actions.clear();
        }

        if (!CheckSparkBlock(state, *pblock)) {
            return false;
        }

        BOOST_FOREACH(auto& lTag, pblock->sparkTxInfo->spentLTags) {
            if (!CheckLTag(
                    state,
                    pblock->sparkTxInfo.get(),
                    lTag.first,
                    pindexNew->nHeight,
                    true /* fConnectTip */
            )) {
                return false;
            }
        }

        try {
            sparkState.GetSpatsManager().registry().validate(pblock->sparkTxInfo->spats_actions, pindexNew->nHeight);
        } catch (...) {
            LogPrintf("Spats validation at block height %d failed: %s\n",
              pindexNew->nHeight, boost::current_exception_diagnostic_information().c_str());
            return false;
        }

        if (!fJustCheck) {
            BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->spentLTags) {
                pindexNew->spentLTags.insert(lTag);
                sparkState.AddSpend(lTag.first, lTag.second);
            }

            if (!pblock->sparkTxInfo->spats_actions.empty()) {
                pindexNew->spats_actions.insert(pindexNew->spats_actions.end(),
                    pblock->sparkTxInfo->spats_actions.begin(), pblock->sparkTxInfo->spats_actions.end());
                sparkState.AddSpatsActions(pblock->sparkTxInfo->spats_actions, pindexNew->nHeight,
                                           pindexNew->phashBlock ? std::optional(*pindexNew->phashBlock) : std::nullopt);
            }

            if (GetBoolArg("-mobile", false)) {
                BOOST_FOREACH (auto& lTag, pblock->sparkTxInfo->ltagTxhash) {
                    pindexNew->ltagTxhash.insert(lTag);
                    sparkState.AddLTagTxHash(lTag.first, lTag.second);
                }
            }
        }
        else {
            return true;
        }

        const auto& params = ::Params().GetConsensus();
        CHash256 hash;
        bool updateHash = false;

        if (!pblock->sparkTxInfo->mints.empty()) {
            sparkState.AddMintsToStateAndBlockIndex(pindexNew, pblock);
            int latestCoinId  = sparkState.GetLatestCoinID();
            // add  coins into hasher, for generating set hash
            updateHash = true;
            // get previous hash of the set, if there is no such, don't write anything
            std::vector<unsigned char> prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId, true);
            if (!prev_hash.empty())
                hash.Write(prev_hash.data(), 32);
            else {
                if (latestCoinId > 1) {
                    prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId - 1, true);
                    hash.Write(prev_hash.data(), 32);
                }
            }

            for (auto &coin : pindexNew->sparkMintedCoins[latestCoinId]) {
                CDataStream serializedCoin(SER_NETWORK, 0);
                serializedCoin << coin;
                std::vector<unsigned char> data(serializedCoin.begin(), serializedCoin.end());
                hash.Write(data.data(), data.size());
            }
        }

        if (!pblock->sparkTxInfo->sparkNames.empty()) {
            CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
            for (const auto &sparkName : pblock->sparkTxInfo->sparkNames) {
                pindexNew->addedSparkNames[sparkName.first] =
                        CSparkNameBlockIndexData(sparkName.second.name,
                            sparkName.second.sparkAddress,
                            pindexNew->nHeight + sparkName.second.sparkNameValidityBlocks,
                            sparkName.second.additionalInfo);
            }

            // names were added, backup rewritten names if necessary
            fBackupRewrittenSparkNames = true;
        }

        // generate hash if we need it
        if (updateHash) {
            unsigned char hash_result[CSHA256::OUTPUT_SIZE];
            hash.Finalize(hash_result);
            auto &out_hash = pindexNew->sparkSetHash[sparkState.GetLatestCoinID()];
            out_hash.clear();
            out_hash.insert(out_hash.begin(), std::begin(hash_result), std::end(hash_result));
        }
    }
    else if (!fJustCheck) {
        sparkState.AddBlock(pindexNew);
    }

    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    pindexNew->removedSparkNames = sparkNameManager->RemoveSparkNamesLosingValidity(pindexNew->nHeight);
    sparkNameManager->AddBlock(pindexNew, fBackupRewrittenSparkNames);

    return true;
}

void RemoveSpendReferencingBlock(CTxMemPool& pool, CBlockIndex* blockIndex) {
    LOCK2(cs_main, pool.cs);
    std::vector<CTransaction> txn_to_remove;
    for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); ++mi) {
        const CTransaction& tx = mi->GetTx();
        if (tx.IsSparkSpend()) {
            // Run over all the inputs, check if their CoinGroup block hash is equal to
            // block removed. If any one is equal, remove txn from mempool.
            for (const CTxIn& txin : tx.vin) {
                if (txin.scriptSig.IsSparkSpend()) {
                    std::map<uint64_t, uint256> coinGroupIdAndBlockHash;
                    try {
                        coinGroupIdAndBlockHash = getBlockHashes(tx);
                    }
                    catch (const std::exception &) {
                        txn_to_remove.push_back(tx);
                        break;
                    }


                    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
                        if (idAndHash.second == blockIndex->GetBlockHash()) {
                            // Do not remove transaction immediately, that will invalidate iterator mi.
                            txn_to_remove.push_back(tx);
                            break;
                        }
                    }
                }
            }
        }
    }
    for (const CTransaction& tx: txn_to_remove) {
        // Remove txn from mempool.
        pool.removeRecursive(tx);
        LogPrintf("DisconnectTipSpark: removed spark spend which referenced a removed blockchain tip.");
    }
}

void DisconnectTipSpark(CBlock& block, CBlockIndex *pindexDelete) {
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    sparkNameManager->RemoveBlock(pindexDelete);

    sparkState.RemoveBlock(pindexDelete);

    // Also remove from mempool spends that reference given block hash.
    RemoveSpendReferencingBlock(mempool, pindexDelete);
    RemoveSpendReferencingBlock(txpools.getStemTxPool(), pindexDelete);
}

bool CheckSparkBlock(CValidationState &state, const CBlock& block) {
    auto& consensus = ::Params().GetConsensus();

    size_t blockSpendsValue = 0;

    for (const auto& tx : block.vtx) {
        auto txSpendsValue =  GetSpendTransparentAmount(*tx);

        if (txSpendsValue > consensus.nMaxValueSparkSpendPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-spark-spend-invalid");
        }
        blockSpendsValue += txSpendsValue;
    }

    if (blockSpendsValue > consensus.nMaxValueSparkSpendPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-spark-spend-invalid");
    }

    return true;
}


bool CheckSparkMintTransaction(
        const std::vector<CTxOut>& txOuts,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkMintTransaction txHash = %s\n", hashTx.GetHex());
    const spark::Params* params = spark::Params::get_default();
    std::vector<CScript> scripts;
    for (const auto& txOut : txOuts) {
        scripts.push_back(txOut.scriptPubKey);
    }

    MintTransaction mintTransaction(params);
    try {
        ParseSparkMintTransaction(scripts, mintTransaction);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CTransaction::CheckTransaction() : SparkMint parsing failure.");
    }

    //checking whether MintTransaction is valid
    if (!mintTransaction.verify()) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction : mintTransaction verification failed");
    }
    std::vector<Coin> coins;
    mintTransaction.getCoins(coins);

    if (coins.size() != txOuts.size())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction : mintTransaction parsing failed");


    for (size_t i = 0; i < coins.size(); i++) {
        auto& coin = coins[i];
        if (coin.v != txOuts[i].nValue)
            return state.DoS(100,
                             false,
                             PUBCOIN_NOT_VALIDATE,
                             "CheckSparkMintTransaction : mintTransaction failed, wrong amount");

//        if (coin.v > ::Params().GetConsensus().nMaxValueLelantusMint)
//            return state.DoS(100,
//                             false,
//                             REJECT_INVALID,
//                             "CTransaction::CheckTransaction() : Spark Mint is out of limit.");

        if (sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
            // Update coin list in the info
            sparkTxInfo->mints.push_back(coin);
            sparkTxInfo->spTransactions.insert(hashTx);
        }
    }

    return true;
}

#if 0	// TODO remove
bool CheckSpatsMintTransaction(
        const CTransaction &tx,
        CTxOut& txOut,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSpatsMintTransaction txHash = %s\n", hashTx.GetHex());
    const spark::Params* params = spark::Params::get_default();

    MintTransaction mintTransaction(params);
    spark::OwnershipProof ownershipProof;
    try {
        ParseSpatsMintTransaction(txOut.scriptPubKey, mintTransaction, ownershipProof);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CTransaction::CheckTransaction() : SpatsMint parsing failure.");
    }

    //checking whether MintTransaction is valid
    if (!mintTransaction.verify()) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : mintTransaction verification failed");
    }
    std::vector<Coin> coins;
    mintTransaction.getCoins(coins);

    if (coins.size() != 1)
        return state.DoS(100,
                     false,
                     PUBCOIN_NOT_VALIDATE,
                     "CheckSpatsMintTransaction : More than one spats mint");

    Scalar m = spark::GetSpatsMintM(tx);
    //TODO levon get address from the registry and verify ownership
//    spark::Address address(params);
//    if (!address.verify_own(m, ownershipProof))
//        return state.DoS(100,
//                             false,
//                             PUBCOIN_NOT_VALIDATE,
//                             "CheckSpatsMintTransaction : Address ownership proof verification failed");

    auto& coin = coins[0];
    if (coin.v != txOut.nValue)
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSpatsMintTransaction : mintTransaction failed, wrong amount");
    //TODO levon verify against asset regystry and get address
    coin.a;
    coin.iota;
    if (sparkTxInfo != nullptr && !sparkTxInfo->fInfoIsComplete) {
        // Update coin list in the info
        sparkTxInfo->mints.push_back(coin);
        sparkTxInfo->spTransactions.insert(hashTx);
    }

    return true;
}
#endif

bool CheckSparkSMintTransaction(
        const std::vector<CTxOut>& vout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        std::vector<Coin>& out_coins,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkSMintTransaction txHash = %s\n", hashTx.ToString());
    for (const auto& out : vout) {
        const auto& script = out.scriptPubKey;
        if (script.IsSparkSMint()) {
            try {
                spark::Coin coin(Params::get_default());
                ParseSparkMintCoin(script, coin);
                out_coins.emplace_back(coin);
            } catch (const std::exception &) {
                return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "CTransaction::CheckTransaction() : Spark Mint is invalid.");
            }
        }
    }

    for (auto& coin : out_coins) {
        if (sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
            // Update coin list in the info
            sparkTxInfo->mints.push_back(coin);
        }
    }

    return true;
}

bool CheckSparkSpendTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo)
{
    std::unordered_set<GroupElement, spark::CLTagHash> txLTags;

    if (tx.vin.size() != 1 || !tx.vin[0].scriptSig.IsSparkSpend()) {
        // mixing spark spend input with non-spark inputs is prohibited
        return state.DoS(100, false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: can't mix spark spend input with other tx types or have more than one spend");
    }

    Consensus::Params const & params = ::Params().GetConsensus();
    const int height = nHeight == INT_MAX ? chainActive.Height()+1 : nHeight;
    if (!isVerifyDB) {
            if (height >= params.nSparkStartBlock) {
                // data should be moved to v3 payload
                if (tx.nVersion < 3 || tx.nType != TRANSACTION_SPARK)
                    return state.DoS(100, false, NSEQUENCE_INCORRECT,
                                     "CheckSparkSpendTransaction: spark data should reside in transaction payload");
            }
    }

    bool spatsStarted = height >= params.nSpatsStartBlock;

    std::unique_ptr<spark::BaseSpendTransaction> spend;

    try {
        if (spatsStarted)
            spend = std::make_unique<spats::SpendTransaction>(ParseSpatsSpend(tx));
        else
            spend = std::make_unique<spark::SpendTransaction>(ParseSparkSpend(tx));
    }
    catch (CBadTxIn&) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: invalid spend transaction");
    }
    catch (const std::exception &) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: failed to deserialize spend");
    }

    uint256 txHashForMetadata;
    // Obtain the hash of the transaction sans the Spark part
    CMutableTransaction txTemp = tx;
    txTemp.vExtraPayload.clear();
    std::erase_if(txTemp.vout, [] (const CTxOut& out) { return out.scriptPubKey.IsSparkSMint() || out.scriptPubKey.IsSpatsMintCoin() || out.scriptPubKey.IsSpatsBurnAmount(); });
    txHashForMetadata = txTemp.GetHash();

    LogPrintf("CheckSparkSpendTransaction: tx metadata hash=%s\n", txHashForMetadata.ToString());

    if (!fStatefulSigmaCheck) {
        return true;
    }

    bool passVerify = false;

    uint64_t Vout = 0;
    uint64_t burn = 0;
    std::size_t private_num = 0;
    for (const CTxOut &txout : tx.vout) {
        const auto& script = txout.scriptPubKey;
        if (!script.empty() && script.IsSparkSMint()) {
            private_num++;
        } else if (script.IsSparkMint() ||
                script.IsLelantusMint() ||
                script.IsLelantusJMint() ||
                script.IsSigmaMint()) {
            return false;
        } else if (script.IsSpatsMint() || script.IsSpatsMintCoin()) {
            continue;
        } else if (script.IsSpatsBurnAmount()) {
            burn += txout.nValue;
        } else {
            Vout += txout.nValue;
        }
    }

    if (private_num > ::Params().GetConsensus().nMaxSparkOutLimitPerTx)
        return false;

    std::vector<Coin> out_coins;
    out_coins.reserve(private_num);
    if (!CheckSparkSMintTransaction(tx.vout, state, hashTx, fStatefulSigmaCheck, out_coins, sparkTxInfo))
        return false;
    spend->setOutCoins(out_coins);
    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    const auto idAndBlockHashes = spend->getBlockHashes();

    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    bool useBatching = batchProofContainer->fCollectProofs && !isVerifyDB && !isCheckWallet && sparkTxInfo && !sparkTxInfo->fInfoIsComplete;

    for (const auto& idAndHash : idAndBlockHashes) {
        CSparkState::SparkCoinGroupInfo coinGroup;
        if (!sparkState.GetCoinGroupInfo(idAndHash.first, coinGroup))
                return state.DoS(100, false, NO_MINT_ZEROCOIN,
                                 "CheckSparkSpendTransaction: Error: no coins were minted with such parameters");

        CBlockIndex *index = coinGroup.lastBlock;
        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
            index = index->pprev;

        // take the hash from last block of anonymity set
        std::vector<unsigned char> set_hash = GetAnonymitySetHash(index, idAndHash.first);

        std::vector<Coin> cover_set;
        cover_set.reserve(coinGroup.nCoins);
        std::size_t set_size = 0;
        // Build a vector with all the public coins with given id before
        // the block on which the spend occurred.
        // This list of public coins is required by function "Verify" of spend.
        while (true) {
            int id = 0;
            if (CountCoinInBlock(index, idAndHash.first)) {
                id = idAndHash.first;
            } else if (CountCoinInBlock(index, idAndHash.first - 1)) {
                id = idAndHash.first - 1;
            }
            if (id) {
                if (index->sparkMintedCoins.count(id) > 0) {
                    BOOST_FOREACH(
                    const auto& coin,
                    index->sparkMintedCoins[id]) {
                        set_size++;
                        if (!useBatching)
                            cover_set.push_back(coin);
                    }
                }
            }

            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }

        CoverSetData setData;
        setData.cover_set_size = set_size;
        if (!set_hash.empty())
            setData.cover_set_representation = set_hash;
        setData.cover_set_representation.insert(setData.cover_set_representation.end(), txHashForMetadata.begin(), txHashForMetadata.end());

        cover_sets[idAndHash.first] = std::move(cover_set);
        cover_set_data [idAndHash.first] = setData;
    }
    spend->setCoverSets(cover_set_data);
    spend->setVout(Vout);
    spend->setBurn(burn);

    const std::vector<uint64_t>& ids = spend->getCoinGroupIds();
    for (const auto& id : ids) {
        if (!cover_sets.count(id) || !cover_set_data.count(id))
            return state.DoS(100,
                             error("CheckSparkSpendTransaction: No cover set found."));
    }
    
    // if we are collecting proofs, skip verification and collect proofs
    // add proofs into container
    if (useBatching) {
        passVerify = true;
        batchProofContainer->add(*spend);
    } else {
        try {
            if (spatsStarted) {
                auto* typed = static_cast<spats::SpendTransaction*>(spend.get());
                passVerify = spats::SpendTransaction::verify(*typed, cover_sets);
            } else {
                auto* typed = static_cast<spark::SpendTransaction*>(spend.get());
                passVerify = spark::SpendTransaction::verify(*typed, cover_sets);
            }
        } catch (const std::exception &) {
            passVerify = false;
        }
    }

    if (passVerify) {
        const std::vector<GroupElement>& lTags = spend->getUsedLTags();

        if (lTags.size() != ids.size()) {
            return state.DoS(100,
                             error("CheckSparkSpendTransaction: size of lTags and group ids don't match."));
        }

        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(sparkTxInfo && sparkTxInfo->spTransactions.count(hashTx) > 0)) {
            for (size_t i = 0; i < lTags.size(); ++i) {
                    if (!CheckLTag(state, sparkTxInfo, lTags[i], nHeight, false)) {
                        LogPrintf("CheckSparkSpendTransaction: lTag check failed, ltag=%s\n", lTags[i]);
                        return false;
                    }
            }
        }

        // check duplicated linking tags in same transaction.
        for (const auto &lTag : lTags) {
            if (!txLTags.insert(lTag).second) {
                return state.DoS(100,
                                 error("CheckSparkSpendTransaction: two or more spends with same linking tag in the same transaction"));
            }
        }

        if (!isVerifyDB && !isCheckWallet) {
            // add spend information to the index
            if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
                for (size_t i = 0; i < lTags.size(); i++) {
                    sparkTxInfo->spentLTags.insert(std::make_pair(lTags[i], ids[i]));
                    if (GetBoolArg("-mobile", false)) {
                        sparkTxInfo->ltagTxhash.insert(std::make_pair(primitives::GetLTagHash(lTags[i]), hashTx));
                    }
                }
            }
        }
    }
    else {
        LogPrintf("CheckSparkSpendTransaction: verification failed at block %d\n", nHeight);
        return false;
    }

    // Check Spats
    // It is proper to do it here, because all spats transactions are created as spark spends, due to having to process the regular tx fee at the very least
    std::optional<spats::Action> action;
    if (tx.IsSpatsTransaction()) {
         if (!isVerifyDB) {    // TODO what is this, do I need to keep this check?
              if (height < params.nSpatsStartBlock) {
                  // TODO is the check and the error message correct?
                  return state.DoS(100, false, NSEQUENCE_INCORRECT, "CheckSparkSpendTransaction: block too young for supporting Spats transactions");
              }
              try {
                  action = ParseSpatsTransaction(tx);
              }
              catch (CBadTxIn&) {
                  return state.DoS(100,
                                   false,
                                   REJECT_MALFORMED,
                                   "CheckSparkSpendTransaction: invalid spats transaction");
              }
              catch (const std::exception &e) {
                  return state.DoS(100,
                                   false,
                                   REJECT_MALFORMED,
                                   "CheckSparkSpendTransaction: failed to deserialize spats tx: "s + e.what());
              }

              try {
                  sparkState.GetSpatsManager().registry().validate(*action, height);
              } catch (...) {
                  return state.DoS(100,
                                   false,
                                   REJECT_INVALID,
                                   "CheckSparkSpendTransaction: Spats action validation failed: " + boost::current_exception_diagnostic_information());
              }
        }
    }

    if (!isVerifyDB && !isCheckWallet) {
        if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
            if (action) {
                for (auto&& coin : get_coins(*action))
                    sparkTxInfo->mints.push_back(std::move(coin));
                sparkTxInfo->spats_actions.push_back(std::move(*action));
            }
            sparkTxInfo->spTransactions.insert(hashTx);
        }
    }

    return true;
}

bool CheckSparkTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo)
{
    Consensus::Params const & consensus = ::Params().GetConsensus();

    bool const allowSpark = IsSparkAllowed();

    // Check Spark Mint Transaction
    if (allowSpark && !isVerifyDB && tx.IsSparkMint()) {
        std::vector<CTxOut> txOuts;
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSparkMint()) {
                txOuts.push_back(txout);
            }
        }
        if (!txOuts.empty()) {
            try {
                if (!CheckSparkMintTransaction(txOuts, state, hashTx, fStatefulSigmaCheck, sparkTxInfo)) {
                    LogPrintf("CheckSparkTransaction::Mint verification failed.\n");
                    return false;
                }
            }
            catch (const std::exception &x) {
                return state.Error(x.what());
            }
        } else {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-mint-invalid");
        }
    }

#if 0
    // Check Spats Mint Transaction
    if (allowSpark && !isVerifyDB && tx.IsSpatsMint()) {
        std::vector<CTxOut> txOuts;
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSpatsMintCoin()) {
                txOuts.push_back(txout);
            }
        }

        if (txOuts.size() > 1) {
            LogPrintf("CheckSparkTransaction::More than one spats mint.\n");
            return false;
        }

        if (!txOuts.empty()) {
            try {
                if (!CheckSpatsMintTransaction(tx, txOuts[0], state, hashTx, fStatefulSigmaCheck, sparkTxInfo)) {
                    LogPrintf("CheckSparkTransaction::Spats Mint verification failed.\n");
                    return false;
                }
            }
            catch (const std::exception &x) {
                return state.Error(x.what());
            }
        } else {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-mint-invalid");
        }
    }
#endif

    // Check Spark Spend
    if (tx.IsSparkSpend()) {
        if (GetSpendTransparentAmount(tx) > consensus.nMaxValueSparkSpendPerTransaction) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-spend-invalid");
        }

        if (!isVerifyDB) {
            try {
                if (!CheckSparkSpendTransaction(
                        tx, state, hashTx, isVerifyDB, nHeight,
                        isCheckWallet, fStatefulSigmaCheck, sparkTxInfo)) {
                    return false;
                }

                CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
                CSparkNameTxData sparkTxData;
                if (sparkNameManager->CheckSparkNameTx(tx, nHeight, state, &sparkTxData)) {
                    if (!sparkTxData.name.empty() && sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
                        // Check if the block already contains conflicting spark name
                        if (CSparkNameManager::IsInConflict(sparkTxData, sparkTxInfo->sparkNames,
                                [=](decltype(sparkTxInfo->sparkNames)::const_iterator it)->std::string {
                                    return it->second.sparkAddress;
                                }))
                            return false;

                        sparkTxInfo->sparkNames[CSparkNameManager::ToUpper(sparkTxData.name)] = sparkTxData;
                    }
                }
                else {
                    return false;
                }

            }
            catch (const std::exception &x) {
                return state.Error(x.what());
            }
        }
    }

    return true;
}

uint256 GetTxHashFromCoin(const spark::Coin& coin) {
    COutPoint outPoint;
    GetOutPoint(outPoint, coin);
    return  outPoint.hash;
}

bool GetOutPoint(COutPoint& outPoint, const spark::Coin& coin)
{
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    auto mintedCoinHeightAndId = sparkState->GetMintedCoinHeightAndId(coin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if (mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    //TODO levon, try to optimize this
    if (!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus())) {
        LogPrintf("can't read block from disk.\n");
        return false;
    }

    return GetOutPointFromBlock(outPoint, coin, block);
}

bool GetOutPoint(COutPoint& outPoint, const uint256& coinHash)
{
    spark::Coin coin(Params::get_default());
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    if (!sparkState->HasCoinHash(coin, coinHash)) {
        return false;
    }

    return GetOutPoint(outPoint, coin);
}

bool GetOutPointFromBlock(COutPoint& outPoint, const spark::Coin& coin, const CBlock &block) {
    spark::Coin txCoin(coin.params);
    // cycle transaction hashes, looking for this coin
    for (CTransactionRef tx : block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout : tx->vout) {
            if (txout.scriptPubKey.IsSparkMintType()) {
                try {
                    ParseSparkMintCoin(txout.scriptPubKey, txCoin);
                }
                catch (const std::exception &) {
                    continue;
                }
                if (coin == txCoin) {
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    return true;
                }
            }
            nIndex++;
        }
    }
    return false;
}

std::vector<unsigned char> getSerialContext(const CTransaction &tx) {
    CDataStream serialContextStream(SER_NETWORK, PROTOCOL_VERSION);
    if (tx.IsSparkSpend()) {
        serialContextStream << GetSparkUsedTags(tx);
    } else {
        for (auto input: tx.vin) {
            input.scriptSig.clear();
            serialContextStream << input;
        }
    }

    std::vector<unsigned char> serial_context(serialContextStream.begin(), serialContextStream.end());
    return serial_context;
}

static bool CheckSparkSpendTAg(
        CValidationState& state,
        CSparkTxInfo* sparkTxInfo,
        const GroupElement& tag,
        int nHeight,
        bool fConnectTip) {
    // check for spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
        sparkTxInfo->spentLTags.find(tag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spark spends with same tag in the same block"));

    // check for used tags in sparkState
    if (sparkState.IsUsedLTag(tag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark spend tag has been used"));
        }
    }
    return true;
}

/******************************************************************************/
// CSparkState
/******************************************************************************/

CSparkState::CSparkState(
        size_t maxCoinInGroup,
        size_t startGroupSize)
        :
        maxCoinInGroup(maxCoinInGroup),
        startGroupSize(startGroupSize)
{
    Reset();
}

void CSparkState::Reset() {
    ShutdownWallet();
    coinGroups.clear();
    latestCoinId = 0;
    mintedCoins.clear();
    usedLTags.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
    spats_manager_.reset();
}

std::pair<int, int> CSparkState::GetMintedCoinHeightAndId(const spark::Coin& coin) {
    auto coinIt = mintedCoins.find(coin);

    if (coinIt != mintedCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.coinGroupId);
    }
    return std::make_pair(-1, -1);
}

bool CSparkState::HasCoin(const spark::Coin& coin) {
    return mintedCoins.find(coin) != mintedCoins.end();

}

bool CSparkState::HasCoinHash(spark::Coin& coin, const uint256& coinHash) {
    for (auto it = mintedCoins.begin(); it != mintedCoins.end(); ++it ){
        const spark::Coin& coin_ = (*it).first;
        if (primitives::GetSparkCoinHash(coin_) == coinHash) {
            coin = coin_;
            return true;
        }
    }
    return false;
}

bool CSparkState::GetCoinGroupInfo(
        int group_id,
        SparkCoinGroupInfo& result) {
    if (coinGroups.count(group_id) == 0)
        return false;

    result = coinGroups[group_id];
    return true;
}

int CSparkState::GetLatestCoinID() const {
    return latestCoinId;
}

bool CSparkState::IsUsedLTag(const GroupElement& lTag) {
    return usedLTags.count(lTag) != 0;
}

bool CSparkState::IsUsedLTagHash(GroupElement& lTag, const uint256 &coinLTaglHash) {
    for ( auto it = GetSpends().begin(); it != GetSpends().end(); ++it ) {
        if (primitives::GetLTagHash(it->first) == coinLTaglHash) {
            lTag = it->first;
            return true;
        }
    }
    return false;
}


bool CSparkState::CanAddSpendToMempool(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return !IsUsedLTag(lTag) && !mempool.sparkState.HasLTag(lTag);
}

bool CSparkState::CanAddMintToMempool(const spark::Coin& coin){
    LOCK(mempool.cs);
    return !HasCoin(coin) && !mempool.sparkState.HasMint(coin);
}

void CSparkState::AddMint(const spark::Coin& coin, const CMintedCoinInfo& coinInfo) {
    mintedCoins.insert(std::make_pair(coin, coinInfo));
    mintMetaInfo[coinInfo.coinGroupId] += 1;
}

void CSparkState::RemoveMint(const spark::Coin& coin) {
    auto iter = mintedCoins.find(coin);
    if (iter != mintedCoins.end()) {
        mintMetaInfo[iter->second.coinGroupId] -= 1;
        mintedCoins.erase(iter);
    }
}

void CSparkState::AddMintsToStateAndBlockIndex(
        CBlockIndex *index,
        const CBlock* pblock) {

    std::vector<spark::Coin> blockMints = pblock->sparkTxInfo->mints;

    latestCoinId = std::max(1, latestCoinId);
    auto &coinGroup = coinGroups[latestCoinId];

    if (coinGroup.nCoins + blockMints.size() <= maxCoinInGroup) {
        if (coinGroup.nCoins == 0) {
            // first group of coins
            assert(coinGroup.firstBlock == nullptr);
            assert(coinGroup.lastBlock == nullptr);

            coinGroup.firstBlock = coinGroup.lastBlock = index;
        } else {
            assert(coinGroup.firstBlock != nullptr);
            assert(coinGroup.lastBlock != nullptr);
            assert(coinGroup.lastBlock->nHeight <= index->nHeight);

            coinGroup.lastBlock = index;
        }
        coinGroup.nCoins += blockMints.size();
    } else {
        auto& newCoinGroup = coinGroups[++latestCoinId];

        CBlockIndex *first;
        auto coins = CountLastNCoins(latestCoinId - 1, startGroupSize, first);
        newCoinGroup.firstBlock = first ? first : index;
        newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = coins + blockMints.size();
    }

    for (const auto& mint : blockMints) {
        AddMint(mint, CMintedCoinInfo::make(latestCoinId, index->nHeight));
        LogPrintf("AddMintsToStateAndBlockIndex: Spark mint added id=%d\n", latestCoinId);
        index->sparkMintedCoins[latestCoinId].push_back(mint);
        if (GetBoolArg("-mobile", false)) {
            COutPoint outPoint;
            GetOutPointFromBlock(outPoint, mint, *pblock);
            CTransactionRef tx;
            for (CTransactionRef itr : pblock->vtx) {
                if (outPoint.hash == itr->GetHash())
                    tx = itr;
            }
            index->sparkTxHashContext[mint.S] = {outPoint.hash, getSerialContext(*tx)};
        }
    }
}

void CSparkState::AddSpend(const GroupElement& lTag, int coinGroupId) {
    if (mintMetaInfo.count(coinGroupId) > 0) {
        usedLTags[lTag] = coinGroupId;
        spendMetaInfo[coinGroupId] += 1;
    }
}

void CSparkState::AddLTagTxHash(const uint256& lTagHash, const uint256& txHash) {
    ltagTxhash[lTagHash] = txHash;
}

void CSparkState::RemoveSpend(const GroupElement& lTag) {
    auto iter = usedLTags.find(lTag);
    if (iter != usedLTags.end()) {
        spendMetaInfo[iter->second] -= 1;
        usedLTags.erase(iter);
    }
}

void CSparkState::AddBlock(CBlockIndex *index) {
    for (auto const& coins : index->sparkMintedCoins) {
        if (coins.second.empty())
            continue;

        auto &coinGroup = coinGroups[coins.first];

        if (coinGroup.firstBlock == nullptr) {
            coinGroup.firstBlock = index;

            if (coins.first > 1) {
                CBlockIndex *first;
                coinGroup.nCoins = CountLastNCoins(coins.first - 1, startGroupSize, first);
                coinGroup.firstBlock = first ? first : index;
            }
        }
        coinGroup.lastBlock = index;
        coinGroup.nCoins += coins.second.size();

        latestCoinId = coins.first;
        for (auto const &coin : coins.second) {
            AddMint(coin, CMintedCoinInfo::make(coins.first, index->nHeight));
        }
    }

    for (auto const &lTags : index->spentLTags) {
        AddSpend(lTags.first, lTags.second);
    }
    if (GetBoolArg("-mobile", false)) {
        for (auto const &elem : index->ltagTxhash) {
            AddLTagTxHash(elem.first, elem.second);
        }
    }

    spats_manager_.add_block(*index);
}

void CSparkState::RemoveBlock(CBlockIndex *index) {
    // roll back coin group updates
    for (auto &coins : index->sparkMintedCoins)
    {
        if (coinGroups.count(coins.first) == 0)
            continue;

        SparkCoinGroupInfo& coinGroup = coinGroups[coins.first];
        auto nMintsToForget = coins.second.size();

        if (nMintsToForget == 0)
            continue;

        assert(coinGroup.nCoins >= nMintsToForget);
        auto isExtended = coins.first > 1;
        coinGroup.nCoins -= nMintsToForget;

        // if `index` is edged block we need to erase group
        auto isEdgedBlock = false;
        if (isExtended) {
            auto prevBlockContainMints = index;
            size_t prevGroupCount = 0;

            // find block that contain some Spark mints
            do {
                prevBlockContainMints = prevBlockContainMints->pprev;
            } while (prevBlockContainMints
                     && CountCoinInBlock(prevBlockContainMints, coins.first) == 0
                     && (prevGroupCount = CountCoinInBlock(prevBlockContainMints, coins.first - 1)) == 0);

            isEdgedBlock = prevGroupCount > 0 && (coinGroup.nCoins - prevGroupCount) < startGroupSize;
        }

        if ((!isExtended && coinGroup.nCoins == 0) || (isExtended && isEdgedBlock)) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coins.first);
            // decrease pubcoin id
            latestCoinId--;
        } else {
            // roll back lastBlock to previous position
            assert(coinGroup.lastBlock == index);

            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->sparkMintedCoins.count(coins.first) == 0);
        }
    }

    // roll back mints
    for (auto const&coins : index->sparkMintedCoins) {
        for (auto const& coin : coins.second) {
            auto mintCoins = GetMints().equal_range(coin);
            auto coinIt = find_if(
                    mintCoins.first, mintCoins.second,
                    [&coins](const std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash>::value_type& v) {
                        return v.second.coinGroupId == coins.first;
                    });
            assert(coinIt != mintCoins.second);
            RemoveMint(coinIt->first);
        }
    }

    // roll back spends
    for (auto const& lTag : index->spentLTags) {
        RemoveSpend(lTag.first);
    }

    spats_manager_.remove_block(*index);
}

bool CSparkState::AddSpendToMempool(const std::vector<GroupElement>& lTags, uint256 txHash) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags){
        if (IsUsedLTag(lTag) || mempool.sparkState.HasLTag(lTag))
            return false;

        mempool.sparkState.AddSpendToMempool(lTag, txHash);
    }

    return true;
}

void CSparkState::RemoveSpendFromMempool(const std::vector<GroupElement>& lTags) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags) {
        mempool.sparkState.RemoveSpendFromMempool(lTag);
    }
}

void CSparkState::AddMintsToMempool(const std::vector<spark::Coin>& coins) {
    LOCK(mempool.cs);
    for (const auto& coin : coins) {
        mempool.sparkState.AddMintToMempool(coin);
    }
}

void CSparkState::RemoveMintFromMempool(const spark::Coin& coin) {
    LOCK(mempool.cs);
    mempool.sparkState.RemoveMintFromMempool(coin);
}

uint256 CSparkState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolConflictingTxHash(lTag);
}

CSparkState* CSparkState::GetState() {
    return &sparkState;
}

void CSparkState::GetCoinSet(
        int coinGroupID,
        std::vector<spark::Coin>& coins_out) {
    int maxHeight;
    uint256 blockHash;
    std::vector<unsigned char> setHash;
    {
        const auto &params = ::Params().GetConsensus();
        LOCK(cs_main);
        maxHeight = chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1);
    }
    GetCoinSetForSpend(
            &chainActive,
            maxHeight,
            coinGroupID,
            blockHash,
            coins_out,
            setHash);
}

int CSparkState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<spark::Coin>& coins_out,
        std::vector<unsigned char>& setHash_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0) {
        return 0;
    }

    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    coins_out.reserve(coinGroup.nCoins);
    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {

        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }

        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id);
            }
            numberOfCoins += block->sparkMintedCoins[id].size();
            if (block->sparkMintedCoins.count(id) > 0) {
                for (const auto &coin : block->sparkMintedCoins[id]) {
                    coins_out.push_back(coin);
                }
            }
        }

        if (block == coinGroup.firstBlock) {
            break ;
        }
    }

    return numberOfCoins;
}

void CSparkState::GetCoinsForRecovery(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        std::string start_block_hash,
        uint256& blockHash_out,
        std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins,
        std::vector<unsigned char>& setHash_out) {
    coins.clear();
    if (coinGroups.count(coinGroupID) == 0) {
        return;
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {
        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }
        if (block->GetBlockHash().GetHex() == start_block_hash) {
            break;
        }
        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id);
            }
            numberOfCoins += block->sparkMintedCoins[id].size();
            if (block->sparkMintedCoins.count(id) > 0) {
                for (const auto &coin : block->sparkMintedCoins[id]) {
                    std::pair<uint256, std::vector<unsigned char>> txHashContext;
                    if (block->sparkTxHashContext.count(coin.S))
                        txHashContext = block->sparkTxHashContext[coin.S];
                    coins.push_back({coin, txHashContext});
                }
            }
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
}

void CSparkState::GetAnonSetMetaData(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<unsigned char>& setHash_out,
        int& size) {
    if (coinGroups.count(coinGroupID) == 0) {
        return;
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    size = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {
        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            if (size == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id);
            }
            size += block->sparkMintedCoins[id].size();
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
}

void CSparkState::GetCoinsForRecovery(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        int startIndex,
        int endIndex,
        uint256& blockHash,
        std::vector<std::pair<spark::Coin, std::pair<uint256, std::vector<unsigned char>>>>& coins) {
    coins.clear();
    if (!coinGroups.contains(coinGroupID)) {
        throw std::runtime_error("There is no anonymity set with this id: " + std::to_string(coinGroupID));
    }
    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    CBlockIndex *index = coinGroup.lastBlock;
    // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
    while (index != coinGroup.firstBlock && index->GetBlockHash() != blockHash)
        index = index->pprev;

    if (index == coinGroup.firstBlock && coinGroup.firstBlock != coinGroup.lastBlock)
        throw std::runtime_error(std::string("Incorrect blockHash provided: " + blockHash.GetHex()));

    std::size_t counter = 0;
    for (CBlockIndex *block = index;; block = block->pprev) {
        // ignore block higher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }
        if (id) {
            if (block->sparkMintedCoins.count(id) > 0) {
                for (const auto &coin : block->sparkMintedCoins[id]) {
                    if (counter < startIndex) {
                        ++counter;
                        continue;
                    }
                    if (counter >= endIndex) {
                        break;
                    }
                    std::pair<uint256, std::vector<unsigned char>> txHashContext;
                    if (block->sparkTxHashContext.count(coin.S))
                        txHashContext = block->sparkTxHashContext[coin.S];
                    coins.push_back({coin, txHashContext});
                    ++counter;
                }
            }
        }
        if (block == coinGroup.firstBlock || counter >= endIndex) {
            break ;
        }
    }
}

std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> const & CSparkState::GetMints() const {
    return mintedCoins;
}
std::unordered_map<GroupElement, int, spark::CLTagHash> const & CSparkState::GetSpends() const {
    return usedLTags;
}

std::unordered_map<uint256, uint256> const& CSparkState::GetSpendTxIds() const {
    return ltagTxhash;
}

std::unordered_map<int, CSparkState::SparkCoinGroupInfo> const& CSparkState::GetCoinGroups() const {
    return coinGroups;
}

std::unordered_map<GroupElement, uint256, spark::CLTagHash> const& CSparkState::GetMempoolLTags() const {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolLTags();
}

// private
size_t CSparkState::CountLastNCoins(int groupId, size_t required, CBlockIndex* &first) {
    first = nullptr;
    size_t coins = 0;

    if (coinGroups.count(groupId)) {
        auto &group = coinGroups[groupId];

        for (auto block = group.lastBlock
                ; coins < required && block
                ; block = block->pprev) {

            size_t inBlock;
            if (block->sparkMintedCoins.count(groupId)
                && (inBlock = block->sparkMintedCoins[groupId].size())) {

                coins += inBlock;
                first = block;
            }
        }
    }

    return coins;
}

// CSparkMempoolState
bool CSparkMempoolState::HasMint(const spark::Coin& coin) {
    return mempoolMints.count(coin) > 0;
}

void CSparkMempoolState::AddMintToMempool(const spark::Coin& coin) {
    mempoolMints.insert(coin);
}

void CSparkMempoolState::RemoveMintFromMempool(const spark::Coin& coin) {
    mempoolMints.erase(coin);
}

bool CSparkMempoolState::HasLTag(const GroupElement& lTag) {
    return mempoolLTags.count(lTag) > 0;
}

bool CSparkMempoolState::AddSpendToMempool(const GroupElement& lTag, uint256 txHash) {
    return mempoolLTags.insert({lTag, txHash}).second;
}

void CSparkMempoolState::RemoveSpendFromMempool(const GroupElement& lTag) {
    mempoolLTags.erase(lTag);
}

uint256 CSparkMempoolState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    if (mempoolLTags.count(lTag) == 0)
        return uint256();

    return mempoolLTags[lTag];
}

void CSparkState::AddSpatsActions(const spats::Actions& actions, int block_height, const std::optional<uint256>& block_hash)
{
    GetSpatsManager().add_spats_actions(actions, block_height, block_hash);
}

void CSparkMempoolState::Reset() {
    mempoolLTags.clear();
    mempoolMints.clear();
}

std::pair<spats::MintAction, spark::Coin> ExtractSpatsMintAction(const CTransaction& tx)
{
    assert(!tx.IsSpatsCreate());
    assert(tx.HasSpatsMintCoin());
    if (tx.vout.empty())
        throw CBadTxIn();
    const auto &mintcoin_script = tx.vout.back().scriptPubKey;
    if (!mintcoin_script.IsSpatsMintCoin())
        throw CBadTxIn();
    if (std::find_if(tx.vout.begin(), tx.vout.end() - 1, [](const CTxOut& out) { return out.scriptPubKey.IsSpatsMintCoin(); }) != tx.vout.end() - 1)
        throw CBadTxIn();   // more than 1 spats coin in one tx is not allowed

    MintTransaction mintTransaction(spark::Params::get_default());
    spark::OwnershipProof ownershipProof;
    spats::public_address_t initiator_public_address;
    ParseSpatsMintCoinTransaction(mintcoin_script, mintTransaction, ownershipProof, initiator_public_address);	// may throw
    if (!mintTransaction.verify())
        throw CBadTxIn();
    // ATTENTION: Assuming the receiver address is the same as initiator_public_address!
    //            It is always true in the current design, but if that ever changes, then this code needs to be adjusted accordingly!
    if (!CSparkWallet::decodeAddress(initiator_public_address).verify_own(spark::GetSpatsMintM(tx), ownershipProof))
        throw CBadTxIn();
    const auto& coins = mintTransaction.getCoins();
    if (coins.size() != 1)
        throw CBadTxIn();
    auto coin = coins.front();
    if (coin.v != tx.vout.back().nValue)
        throw CBadTxIn();
    if (!coin.iota.isZero())
        throw CBadTxIn();
    const auto asset_type = std::stoull(coin.a.tostring());
    // ATTENTION: Assuming the receiver address is the same as initiator_public_address!
    //            It is always true in the current design, but if that ever changes, then this code needs to be adjusted accordingly!
    spats::MintParameters params(spats::asset_type_t{asset_type}, coin.v, initiator_public_address, initiator_public_address, std::nullopt);
    // ATTENTION: Deliberately NOT putting the coin in the action here. If needed, that can be done by the caller itself.
    return {spats::MintAction(std::move(params)), std::move(coin)};
}

spats::BurnAction<> ExtractSpatsBurnAction(const CTransaction& tx)
{
    assert(tx.HasSpatsBurnAmount());
    if (tx.vout.empty())
        throw CBadTxIn();
    const auto &burnamount_out = tx.vout.back();
    const auto &burnamount_script = burnamount_out.scriptPubKey;
    if (!burnamount_script.IsSpatsBurnAmount())
        throw CBadTxIn();
    if (std::find_if(tx.vout.begin(), tx.vout.end() - 1, [](const CTxOut& out) { return out.scriptPubKey.IsSpatsBurnAmount(); }) != tx.vout.end() - 1)
        throw CBadTxIn();   // more than 1 burnamount outputs in one tx is not allowed

    const auto burn_amount_raw = burnamount_out.nValue;
    if (burn_amount_raw <= 0)
        throw CBadTxIn();
    std::vector<unsigned char> serialized(burnamount_script.begin() + 1, burnamount_script.end());
    CDataStream stream(serialized, SER_NETWORK, PROTOCOL_VERSION );
    Scalar asset_type_scalar;
    stream >> asset_type_scalar;
    const spats::asset_type_t asset_type{std::stoull(asset_type_scalar.tostring())};
    spats::BurnParameters params(asset_type, burn_amount_raw, std::nullopt, std::nullopt);    // may throw
    return spats::BurnAction<>(std::move(params));
}

} // namespace spark
