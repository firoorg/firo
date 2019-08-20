#include "txprocessor.h"

#include "rules.h"

namespace exodus {

TxProcessor *txProcessor;

namespace {

bool IsSigmaEnabled(uint32_t propertyId)
{
    CMPSPInfo::Entry sp;

    if (!_my_sps->getSP(propertyId, sp)) {
        return false;
    }

    if (sp.sigmaStatus != SigmaStatus::HardEnabled && sp.sigmaStatus != SigmaStatus::SoftEnabled) {
        return false;
    }

    return true;
}

} // unnamed namespace

int TxProcessor::ProcessTx(CMPTransaction& tx)
{
    LOCK(cs_tally);

    tx.unlockLogic();

    auto result = tx.interpretPacket();

    if (result == (PKT_ERROR - 100)) {
        // Unknow transaction type.
        switch (tx.getType()) {
        case EXODUS_TYPE_SIGMA_SIMPLE_MINT:
            result = ProcessSimpleMint(tx);
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

    std::vector<DenominationId> denominations;
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
        MintGroupId group;
        MintGroupIndex index;

        auto denom = mint.first;
        auto& pubkey = mint.second;

        std::tie(group, index) = p_mintlistdb->RecordMint(property, denom, pubkey, block);

        SimpleMintProcessed(property, denom, group, index, pubkey);
    }

    return 0;
}

}
