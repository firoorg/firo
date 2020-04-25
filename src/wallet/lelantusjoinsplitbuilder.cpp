#include "lelantusjoinsplitbuilder.h"

#include "validation.h"
#include "../policy/policy.h"

#include <boost/format.hpp>

LelantusJoinSplitBuilder::LelantusJoinSplitBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl) :
    wallet(wallet),
    mintWallet(mintWallet)
{
    cs_main.lock();

    try {
        wallet.cs_wallet.lock();
    } catch (...) {
        cs_main.unlock();
        throw;
    }

    this->coinControl = coinControl;
}

LelantusJoinSplitBuilder::~LelantusJoinSplitBuilder()
{
    wallet.cs_wallet.unlock();
    cs_main.unlock();
}

CWalletTx LelantusJoinSplitBuilder::Build(const std::vector<CRecipient>& recipients, const std::vector<CAmount>& newMints)
{
    if (recipients.empty() && newMints.empty()) {
        throw std::invalid_argument(_("At least either recipients or newMints has to be on empty."));
    }

    // calculate total value to spend
    CAmount spend = 0;
    CAmount mint = 0;
    unsigned recipientsToSubtractFee = 0;

    for (size_t i = 0; i < recipients.size(); i++) {
        auto& recipient = recipients[i];

        if (!MoneyRange(recipient.nAmount)) {
            throw std::invalid_argument(boost::str(boost::format(_("Recipient  has invalid amount")) % i));
        }

        spend += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            recipientsToSubtractFee++;
        }
    }

    for(const auto& mintValue : newMints) {
        mint += mintValue;
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
    uint32_t nCountNextUse;
    if (zwalletMain) {
        nCountNextUse = zwalletMain->GetCount();
    }

    CAmount fee;

    for (fee = payTxFee.GetFeePerK();;) {
        // In case of not enough fee, reset mint seed counter
        if (zwalletMain) {
            zwalletMain->SetCount(nCountNextUse);
        }
        CAmount required = spend + mint;

        tx.vin.clear();
        tx.vout.clear();

        result.fFromMe = true;
        result.changes.clear();

        // If no any recipients to subtract fee then the sender need to pay by themself.
        if (!recipientsToSubtractFee) {
            required += fee;
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
//TODO(levon) implement here

        // check fee
        result.SetTx(MakeTransactionRef(tx));

        if (GetTransactionWeight(tx) >= MAX_STANDARD_TX_WEIGHT) {
            throw std::runtime_error(_("Transaction too large"));
        }

        // check fee
        unsigned size = GetVirtualTransactionSize(tx);
        CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);

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
        CTxMemPoolEntry entry(MakeTransactionRef(tx), 0, 0, 0, 0, 0, false, 0, lp);
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
