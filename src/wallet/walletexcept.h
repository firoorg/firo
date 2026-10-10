#ifndef FIRO_WALLET_WALLETEXCEPT_H
#define FIRO_WALLET_WALLETEXCEPT_H

#include "amount.h"

#include <stdexcept>

class WalletError : public std::runtime_error
{
public:
    explicit WalletError(const char *what);
    explicit WalletError(const std::string &what);
};

class WalletLocked : public WalletError
{
public:
    WalletLocked();
};

class InsufficientFunds : public WalletError
{
public:
    InsufficientFunds();
    explicit InsufficientFunds(const char *what);
    explicit InsufficientFunds(const std::string& what);
    /** The spend amount fits, but this extra fee does not. */
    explicit InsufficientFunds(CAmount requiredFee);
    CAmount GetRequiredFee() const { return nRequiredFee; }

private:
    CAmount nRequiredFee{0};
};

#endif // FIRO_WALLET_WALLETEXCEPT_H
