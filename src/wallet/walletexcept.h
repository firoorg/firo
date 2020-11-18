#ifndef FIRO_WALLET_WALLETEXCEPT_H
#define FIRO_WALLET_WALLETEXCEPT_H

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
};

#endif // FIRO_WALLET_WALLETEXCEPT_H
