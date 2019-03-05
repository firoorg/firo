#include "txbuilder.h"

#include "../libzerocoin/sigma/Coin.h"
#include "../libzerocoin/sigma/CoinSpend.h"
#include "../libzerocoin/sigma/Params.h"
#include "../libzerocoin/sigma/SpendMetaDataV3.h"
#include "../main.h"
#include "../policy/policy.h"
#include "../random.h"
#include "../script/script.h"
#include "../txmempool.h"
#include "../uint256.h"
#include "../util.h"
#include "../zerocoin_params.h"
#include "../zerocoin_v3.h"

#include <boost/format.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <tuple>

#include <assert.h>
#include <stddef.h>

TxBuilder::TxBuilder(CWallet& wallet) noexcept : wallet(wallet)
{
}

TxBuilder::~TxBuilder()
{
}

CWalletTx TxBuilder::Build(const std::vector<CRecipient>& recipients, CAmount& fee) const
{
    if (recipients.empty()) {
        throw std::invalid_argument(_("No recipients"));
    }

    // calculate total value to spend
    CAmount spend = 0;
    bool subtractFee = false;

    for (size_t i = 0; i < recipients.size(); i++) {
        auto& recipient = recipients[i];

        if (recipient.nAmount < 0) {
            throw std::invalid_argument(boost::str(boost::format(_("Recipient %zu has negative amount")) % i));
        }

        spend += recipient.nAmount;

        if (spend < 0) {
            throw std::overflow_error(_("Total amount to spend is too large"));
        }

        subtractFee |= recipient.fSubtractFeeFromAmount;
    }

    CWalletTx result;
    CMutableTransaction tx;

    result.fTimeReceivedIsTxTime = true;
    result.BindWallet(&wallet);

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    tx.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0) {
        tx.nLockTime = std::max(0U, tx.nLockTime - GetRandInt(100));
    }

    assert(tx.nLockTime <= static_cast<unsigned>(chainActive.Height()));
    assert(tx.nLockTime < LOCKTIME_THRESHOLD);

    // Start with no fee and loop until there is enough fee;
    for (fee = payTxFee.GetFeePerK();;) {
        CAmount required = spend;

        tx.vin.clear();
        tx.vout.clear();
        tx.wit.SetNull();

        result.fFromMe = true;

        if (!subtractFee) {
            required += fee;
        }

        // outputs
        for (size_t i = 0; i < recipients.size(); i++) {
            auto& recipient = recipients[i];
            CTxOut vout(recipient.nAmount, recipient.scriptPubKey);

            if (vout.IsDust(minRelayTxFee)) {
                throw std::invalid_argument(boost::str(boost::format(_("Amount for recipient %zu is too small")) % i));
            }

            tx.vout.push_back(vout);
        }

        // inputs
        fee += SetupInputs(tx, required);

        // check fee
        static_cast<CTransaction&>(result) = CTransaction(tx);

        if (GetTransactionWeight(result) >= MAX_STANDARD_TX_WEIGHT) {
            throw std::runtime_error(_("Transaction too large"));
        }

        // check fee
        unsigned size = GetVirtualTransactionSize(result);
        CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);
        feeNeeded = AdjustFee(feeNeeded, size);

        // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
        // because we must be at the maximum allowed fee.
        if (feeNeeded < minRelayTxFee.GetFee(size)) {
            throw std::runtime_error(_("Transaction too large for fee policy"));
        }

        if (fee >= feeNeeded) {
            break;
        }

        fee = feeNeeded;
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(tx, 0, 0, 0, 0, false, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            throw std::runtime_error(_("Transaction has too long of a mempool chain"));
        }
    }

    return result;
}

CAmount TxBuilder::AdjustFee(CAmount needed, unsigned txSize) const
{
    return needed;
}

SigmaSpendBuilder::SigmaSpendBuilder(CWallet& wallet, std::vector<CZerocoinEntryV3>& selected) :
    TxBuilder(wallet),
    selected(selected)
{
    cs_main.lock();

    try {
        wallet.cs_wallet.lock();
    } catch (...) {
        cs_main.unlock();
        throw;
    }
}

SigmaSpendBuilder::~SigmaSpendBuilder()
{
    wallet.cs_wallet.unlock();
    cs_main.unlock();
}

static CAmount GetPublicAndPrivateCoins(
    const std::vector<CZerocoinEntryV3>& coins,
    std::vector<sigma::PublicCoinV3>& publics,
    std::vector<sigma::PrivateCoinV3>& privates)
{
    auto params = sigma::ParamsV3::get_default();
    CAmount total = 0;

    for (auto& coin : coins) {
        auto denom = coin.get_denomination();

        // construct public part of the mint
        sigma::PublicCoinV3 pub(coin.value, denom);

        if (!pub.validate()) {
            throw std::runtime_error(_("One of the minted coin is invalid"));
        }

        // construct private part of the mint
        sigma::PrivateCoinV3 priv(params, denom, ZEROCOIN_TX_VERSION_3);

        priv.setSerialNumber(coin.serialNumber);
        priv.setRandomness(coin.randomness);
        priv.setEcdsaSeckey(coin.ecdsaSecretKey);
        priv.setPublicCoin(pub);

        publics.push_back(pub);
        privates.push_back(priv);

        total += coin.get_denomination_value();
    }

    return total;
}

static CScript CreateSigmaSpendScript(
    int groupId,
    const sigma::PublicCoinV3& pub,
    const sigma::PrivateCoinV3& priv,
    const uint256& metahash)
{
    auto state = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();
    auto denom = pub.getDenomination();

    // get all coins in the same group
    std::vector<sigma::PublicCoinV3> group;
    uint256 lastBlockOfGroup;

    if (state->GetCoinSetForSpend(
        &chainActive,
        chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 6 confirmation for mint to spend
        denom,
        groupId,
        lastBlockOfGroup,
        group) < 2) {
        throw std::runtime_error(_("Has to have at least two mint coins with at least 6 confirmation in order to spend a coin"));
    }

    // construct spend
    sigma::SpendMetaDataV3 meta(groupId, lastBlockOfGroup, metahash);
    sigma::CoinSpendV3 spend(params, priv, group, meta);

    spend.setVersion(priv.getVersion());

    if (!spend.Verify(group, meta)) {
        throw std::runtime_error(_("The spend coin transaction failed to verify"));
    }

    // construct spend script
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << spend;

    CScript script;

    script << OP_ZEROCOINSPENDV3;
    script.insert(script.end(), serialized.begin(), serialized.end());

    return script;
}

CAmount SigmaSpendBuilder::SetupInputs(CMutableTransaction& tx, CAmount required) const
{
    auto state = CZerocoinStateV3::GetZerocoinState();

    // get coins to spend
    std::vector<sigma::PublicCoinV3> publics;
    std::vector<sigma::PrivateCoinV3> privates;
    std::vector<sigma::CoinDenominationV3> denomsToChanges;

    selected.clear();

    if (!wallet.GetCoinsToSpend(required, selected, denomsToChanges)) {
        throw std::runtime_error(_("Insufficient funds"));
    }

    CAmount total = GetPublicAndPrivateCoins(selected, publics, privates);

    // fill inputs with empty spend script for calculate metadata
    // we want to sign everything except spend script
    tx.vin.resize(selected.size());

    for (size_t i = 0; i < selected.size(); i++) {
        int groupId;

        std::tie(std::ignore, groupId) = state->GetMintedCoinHeightAndId(publics[i]);

        if (groupId < 0) {
            throw std::runtime_error(_("One of minted coin does not found in the chain"));
        }

        tx.vin[i].nSequence = groupId;
    }

    uint256 metahash = tx.GetHash();

    // populate input list
    for (size_t i = 0; i < selected.size(); i++) {
        tx.vin[i].scriptSig = CreateSigmaSpendScript(tx.vin[i].nSequence, publics[i], privates[i], metahash);
    }

    return total - required;
}
