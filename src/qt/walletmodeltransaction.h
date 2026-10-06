// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODELTRANSACTION_H
#define BITCOIN_QT_WALLETMODELTRANSACTION_H

#include "amount.h"

#include <QList>

#include <memory>

class SendCoinsRecipient;

class CReserveKey;
class CWallet;
class CWalletTx;

/** Data model for a walletmodel transaction. */
class WalletModelTransaction
{
public:
    explicit WalletModelTransaction(const QList<SendCoinsRecipient> &recipients);
    ~WalletModelTransaction();

    WalletModelTransaction(const WalletModelTransaction&) = delete;
    WalletModelTransaction& operator=(const WalletModelTransaction&) = delete;
    WalletModelTransaction(WalletModelTransaction&&) noexcept;
    WalletModelTransaction& operator=(WalletModelTransaction&&) noexcept;

    QList<SendCoinsRecipient> getRecipients();

    CWalletTx *getTransaction();
    unsigned int getTransactionSize();

    void setTransactionFee(const CAmount& newFee);
    CAmount getTransactionFee();

    CAmount getTotalTransactionAmount();

    void newPossibleKeyChange(CWallet *wallet);
    CReserveKey *getPossibleKeyChange();

    void reassignAmounts(int nChangePosRet); // needed for the subtract-fee-from-amount feature

private:
    QList<SendCoinsRecipient> recipients;
    std::unique_ptr<CWalletTx> walletTransaction;
    std::unique_ptr<CReserveKey> keyChange;
    CAmount fee;
};

#endif // BITCOIN_QT_WALLETMODELTRANSACTION_H
