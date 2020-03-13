#include "txprocessor.h"

#include "rules.h"
#include "sigma.h"
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

    for (auto &mint : tx.getMints()) {
        auto denom = mint.first;
        auto& pubkey = mint.second;

        if (!pubkey.IsValid()) {
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

    if (IsFeatureActivated(FEATURE_SIGMA_SPENDV1, block)) {
        if (!serial->isMember()) {
            PrintToLog("%s() : Serial is invalid\n", __func__);
            return PKT_ERROR_SIGMA - 907;
        }
    }

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


}
