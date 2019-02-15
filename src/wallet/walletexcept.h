#ifndef ZCOIN_WALLET_WALLETEXCEPT_H
#define ZCOIN_WALLET_WALLETEXCEPT_H

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
};

#endif // ZCOIN_WALLET_WALLETEXCEPT_H
