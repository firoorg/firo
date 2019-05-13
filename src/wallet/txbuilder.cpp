#include "txbuilder.h"

#include "../amount.h"
#include "../main.h"
#include "../policy/policy.h"
#include "../random.h"
#include "../script/script.h"
#include "../txmempool.h"
#include "../uint256.h"
#include "../util.h"

#include <boost/format.hpp>

#include <algorithm>
#include <random>
#include <stdexcept>
#include <string>

#include <assert.h>
#include <stddef.h>

InputSigner::InputSigner() : InputSigner(COutPoint())
{
}

InputSigner::InputSigner(const COutPoint& output, uint32_t seq) : output(output), sequence(seq)
{
}

InputSigner::~InputSigner()
{
}

TxBuilder::TxBuilder(CWallet& wallet) noexcept : wallet(wallet)
{
}

TxBuilder::~TxBuilder()
{
}

CWalletTx TxBuilder::Build(const std::vector<CRecipient>& recipients, CAmount& fee)
{
    if (recipients.empty()) {
        throw std::invalid_argument(_("No recipients"));
    }

    // calculate total value to spend
    CAmount spend = 0;
    unsigned recipientsToSubtractFee = 0;

    for (size_t i = 0; i < recipients.size(); i++) {
        auto& recipient = recipients[i];

        if (!MoneyRange(recipient.nAmount)) {
            throw std::invalid_argument(boost::str(boost::format(_("Recipient %1% has invalid amount")) % i));
        }

        spend += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            recipientsToSubtractFee++;
        }
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
        tx.nLockTime = std::max(0, static_cast<int>(tx.nLockTime) - GetRandInt(100));
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
        result.changes.clear();

        // If no any recipients to subtract fee then the sender need to pay by themself.
        if (!recipientsToSubtractFee) {
            required += fee;
        }

        if (required > Params().GetConsensus().nMaxValueSigmaSpendPerBlock) {
            throw std::runtime_error(
                _("Required amount exceed value spend limit"));
        }

        // fill outputs
        bool remainderSubtracted = false;

        for (size_t i = 0; i < recipients.size(); i++) {
            auto& recipient = recipients[i];
            CTxOut vout(recipient.nAmount, recipient.scriptPubKey);

            if (recipient.fSubtractFeeFromAmount) {
                // Subtract fee equally from each selected recipient.
                vout.nValue -= fee / recipientsToSubtractFee;

                if (!remainderSubtracted) {
                    // First receiver pays the remainder not divisible by output count.
                    vout.nValue -= fee % recipientsToSubtractFee;
                    remainderSubtracted = true;
                }
            }

            if (vout.IsDust(minRelayTxFee)) {
                std::string err;

                if (recipient.fSubtractFeeFromAmount && fee > 0) {
                    if (vout.nValue < 0) {
                        err = boost::str(boost::format(_("Amount for recipient %1% is too small to pay the fee")) % i);
                    } else {
                        err = boost::str(boost::format(_("Amount for recipient %1% is too small to send after the fee has been deducted")) % i);
                    }
                } else {
                    err = boost::str(boost::format(_("Amount for recipient %1% is too small")) % i);
                }

                throw std::invalid_argument(err);
            }

            tx.vout.push_back(vout);
        }

        // get inputs
        std::vector<std::unique_ptr<InputSigner>> signers;
        CAmount total = GetInputs(signers, required);

        // add changes
        CAmount change = total - required;

        if (change > 0) {
            // get changes outputs
            std::vector<CTxOut> changes;
            fee += GetChanges(changes, change);

            // shuffle changes to provide some privacy
            std::vector<std::pair<std::reference_wrapper<CTxOut>, bool>> outputs;
            outputs.reserve(tx.vout.size() + changes.size());

            for (auto& output : tx.vout) {
                outputs.push_back(std::make_pair(std::ref(output), false));
            }

            for (auto& output : changes) {
                outputs.push_back(std::make_pair(std::ref(output), true));
            }

            std::shuffle(outputs.begin(), outputs.end(), std::random_device());

            // replace outputs with shuffled one
            std::vector<CTxOut> shuffled;
            shuffled.reserve(outputs.size());

            for (size_t i = 0; i < outputs.size(); i++) {
                auto& output = outputs[i];

                shuffled.push_back(output.first);

                if (output.second) {
                    result.changes.insert(static_cast<uint32_t>(i));
                }
            }

            tx.vout = std::move(shuffled);
        }

        // fill inputs
        for (auto& signer : signers) {
            tx.vin.emplace_back(signer->output, CScript(), signer->sequence);
        }

        // now every fields is populated then we can sign transaction
        uint256 sig = tx.GetHash();

        for (size_t i = 0; i < tx.vin.size(); i++) {
            tx.vin[i].scriptSig = signers[i]->Sign(tx, sig);
        }

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

CAmount TxBuilder::AdjustFee(CAmount needed, unsigned txSize)
{
    return needed;
}
