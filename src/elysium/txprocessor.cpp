#include "txprocessor.h"

#include "rules.h"
#include "sigma.h"
#include "lelantus.h"
#include "lelantusdb.h"
#include "lelantusutils.h"
#include "signaturebuilder.h"

#include "../base58.h"

namespace elysium {

TxProcessor *txProcessor;

int TxProcessor::ProcessTx(CMPTransaction& tx)
{
    LOCK(cs_main);

    tx.unlockLogic();

    auto result = tx.interpretPacket();

    if (result == (PKT_ERROR - 100)) {
        // Unknow transaction type.
        switch (tx.getType()) {
        case ELYSIUM_TYPE_SIMPLE_MINT:
            result = ProcessSimpleMint(tx);
            break;

        case ELYSIUM_TYPE_SIMPLE_SPEND:
            result = ProcessSimpleSpend(tx);
            break;

        case ELYSIUM_TYPE_LELANTUS_MINT:
            result = ProcessLelantusMint(tx);
            break;

        case ELYSIUM_TYPE_LELANTUS_JOINSPLIT:
            result = ProcessLelantusJoinSplit(tx);
            break;

        case ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS:
            result = ProcessChangeLelantusStatus(tx);
            break;
        }
    }

    if (result) {
        return result; // Error.
    }

    TransactionProcessed(tx);

    return 0;
}

int TxProcessor::ProcessSimpleMint(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block
        );
        return PKT_ERROR_SIGMA - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_SIGMA - 24;
    }

    if (!IsSigmaEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable sigma\n", __func__, property);
        return PKT_ERROR_SIGMA - 901;
    }

    std::vector<SigmaDenomination> denominations;
    denominations.reserve(tx.getMints().size());

    auto spendV1IsActivated = IsFeatureActivated(FEATURE_SIGMA_SPENDV1, block);
    for (auto &mint : tx.getMints()) {
        auto denom = mint.first;
        auto& pubkey = mint.second;

        auto isValid = spendV1IsActivated ? pubkey.IsValid() : pubkey.IsMember();

        if (!isValid) {
            PrintToLog("%s(): rejected: public key is invalid\n", __func__);
            return PKT_ERROR_SIGMA - 904;
        }

        denominations.push_back(denom);
    }

    int64_t amount;
    try {
        amount = SumDenominationsValue(property, denominations.begin(), denominations.end());
    } catch (std::invalid_argument const &e) {
        // The only possible cases is invalid denomination.
        PrintToLog("%s(): rejected: error %s\n", __func__, e.what());
        return PKT_ERROR_SIGMA - 905;
    } catch (std::overflow_error const &e) {
        PrintToLog("%s(): rejected: overflow error %s\n", __func__, e.what());
        return PKT_ERROR_SIGMA - 906;
    }

    auto& sender = tx.getSender();
    int64_t balance = getMPbalance(sender, property, BALANCE);

    if (balance < amount) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
            __func__,
            tx.getSender(),
            property,
            FormatMP(property, balance),
            FormatMP(property, amount)
        );
        return PKT_ERROR_SIGMA - 25;
    }

    // subtract balance
    assert(update_tally_map(sender, property, -amount, BALANCE));

    for (auto &mint : tx.getMints()) {
        SigmaMintGroup group;
        SigmaMintIndex index;

        auto denom = mint.first;
        auto& pubkey = mint.second;

        std::tie(group, index) = sigmaDb->RecordMint(property, denom, pubkey, block);

        SimpleMintProcessed(property, denom, group, index, pubkey);
    }

    return 0;
}

int TxProcessor::ProcessSimpleSpend(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block);
        return PKT_ERROR_SIGMA - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_SIGMA - 24;
    }

    if (!IsSigmaEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable sigma\n", __func__, property);
        return PKT_ERROR_SIGMA - 901;
    }

    auto spend = tx.getSpend();
    auto serial = tx.getSerial();
    auto denomination = tx.getDenomination();
    auto group = tx.getGroup();
    auto groupSize = tx.getGroupSize();

    bool const fPadding = block >= ::Params().GetConsensus().nSigmaPaddingBlock;

    assert(spend);
    assert(serial);

    CBitcoinAddress receiver(tx.getReceiver());
    if (!receiver.IsValid()) {
        PrintToLog("%s(): rejected: receiver address is invalid\n", __func__);
        return PKT_ERROR_SIGMA - 45;
    }

    // check signature
    if (version == MP_TX_PKT_V1) {
        int64_t referenceAmount = tx.getReferenceAmount().value();
        auto &publicKey = tx.getECDSAPublicKey();
        if (!publicKey.IsFullyValid()) {
            PrintToLog("%s(): rejected: signature public key is invalid\n", __func__);
            return PKT_ERROR_SIGMA - 907;
        }

        SigmaV1SignatureBuilder sigVerifier(
            receiver,
            referenceAmount,
            *spend);

        if (!sigVerifier.Verify(publicKey, tx.getECDSASignature())) {
            PrintToLog("%s(): rejected: signature is invalid\n", __func__);
            return PKT_ERROR_SIGMA - 907;
        }
    }

    // check serial in database
    uint256 spendTx;
    if (sigmaDb->HasSpendSerial(property, denomination, *serial, spendTx)
        || !VerifySigmaSpend(property, denomination, group, groupSize, *spend, *serial, fPadding)) {
        PrintToLog("%s(): rejected: spend is invalid\n", __func__);
        return PKT_ERROR_SIGMA - 907;
    }
    std::array<uint8_t, 1> denoms = {denomination};

    uint64_t amount;
    try {
        amount = SumDenominationsValue(property, denoms.begin(), denoms.end());
    } catch (std::invalid_argument const& e) {
        PrintToLog("%s(): rejected: error %s\n", __func__, e.what());
        return PKT_ERROR_SIGMA - 905;
    }

    // subtract balance
    sigmaDb->RecordSpendSerial(property, denomination, *serial, block, tx.getHash());
    assert(update_tally_map(tx.getReceiver(), property, amount, BALANCE));

    return 0;
}

int TxProcessor::ProcessLelantusMint(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block
        );
        return PKT_ERROR_LELANTUS - 22;
    }

    auto mintValue = tx.getLelantusMintValue();
    if (mintValue <= 0 || MAX_INT_8_BYTES < mintValue) {
        PrintToLog("%s(): ");
        return PKT_ERROR_LELANTUS - 23;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_LELANTUS - 24;
    }

    if (!IsLelantusEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable lelantus\n", __func__, property);
        return PKT_ERROR_LELANTUS - 901;
    }

    auto coin = tx.getLelantusMint();
    auto rawProof = tx.getLelantusSchnorrProof();

    if (rawProof.size() != 98) {
        PrintToLog("%s(): rejected: schnorr proof size is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    CDataStream ss(rawProof, SER_DISK, CLIENT_VERSION);
    lelantus::SchnorrProof proof;
    ss >> proof;

    if (!lelantus::VerifyMintSchnorrProof(mintValue, coin.getValue(), proof)) {
        PrintToLog("%s(): rejected: schnorr proof is not exist\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    if (lelantusDb->HasMint(property, coin)) {
        PrintToLog("%s(): rejected: public coin are already found on chain\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    auto& sender = tx.getSender();
    int64_t balance = getMPbalance(sender, property, BALANCE);

    if (balance < mintValue) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
            __func__,
            tx.getSender(),
            property,
            FormatMP(property, balance),
            FormatMP(property, mintValue)
        );
        return PKT_ERROR_SIGMA - 25;
    }

    // subtract balance
    assert(update_tally_map(sender, property, -mintValue, BALANCE));
    if (lelantusDb->WriteMint(property, coin, tx.getBlock(), tx.getLelantusMintId(), mintValue, rawProof)) {
        PrintToLog("%s(): rejected: fail to write mint to database\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    return 0;
}

int TxProcessor::ProcessLelantusJoinSplit(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block);
        return PKT_ERROR_LELANTUS - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_LELANTUS - 24;
    }

    if (!IsLelantusEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable lelantus\n", __func__, property);
        return PKT_ERROR_LELANTUS - 901;
    }

    auto joinSplit = tx.getLelantusJoinSplit();

    CBitcoinAddress receiver(tx.getReceiver());
    if (!receiver.IsValid()) {
        PrintToLog("%s(): rejected: receiver address is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 45;
    }

    auto metadata = PrepareSpendMetadata(receiver, tx.getReferenceAmount().get());

    // check serials
    auto serials = joinSplit.getCoinSerialNumbers();
    std::unordered_set<secp_primitives::Scalar> txSerials;
    for (auto const &s : serials) {
        uint256 spendTx;
        if (txSerials.count(s) || lelantusDb->HasSerial(property, s, spendTx)) {
            PrintToLog("%s(): rejected: serial is duplicated\n", __func__);
            return PKT_ERROR_LELANTUS - 907;
        }

        txSerials.insert(s);
    }

    // get anons
    auto idAndBlockHashes = joinSplit.getIdAndBlockHashes();

    std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonss;
    for (auto const &idAndBlockHash : idAndBlockHashes) {
        int block = mapBlockIndex[idAndBlockHash.second]->nHeight;
        anonss[idAndBlockHash.first] = lelantusDb->GetAnonimityGroup(
            property, idAndBlockHash.first, SIZE_MAX, block);
    }

    auto spendAmount = tx.getLelantusSpendAmount();
    auto joinSplitMint = tx.getLelantusJoinSplitMint();

    std::vector<lelantus::PublicCoin> cout;
    if (joinSplitMint.has_value()) {
        cout.push_back(joinSplitMint->publicCoin);
    }

    // verify
    if (!joinSplit.Verify(anonss, cout, spendAmount, metadata)) {
        PrintToLog("%s(): rejected: joinsplit is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    // record serial and change
    for (auto const &s : serials) {
        lelantusDb->WriteSerial(property, s, block, tx.getHash());
    }

    if (joinSplitMint.has_value()) {
        lelantusDb->WriteMint(property, joinSplitMint.get(), block);
    }

    assert(update_tally_map(tx.getReceiver(), property, spendAmount, BALANCE));

    return 0;
}

int TxProcessor::ProcessChangeLelantusStatus(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();
    auto status = tx.getLelantusStatus();
    auto sender = tx.getSender();

    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block);
        return PKT_ERROR_LELANTUS - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    if (!IsLelantusStatusUpdatable(property)) {
        PrintToLog("%s(): rejected: lelantus status of property %d is unupdatable\n", __func__, property);
        return (PKT_ERROR_TOKENS -43);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    sp.lelantusStatus = status;
    sp.update_block = blockHash;

    assert(_my_sps->updateSP(property, sp));

    return 0;
}

}
