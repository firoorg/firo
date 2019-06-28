#include "walletexcept.h"
#include "../util.h"

// WalletError

WalletError::WalletError(const char *what) : runtime_error(what)
{
}

WalletError::WalletError(const std::string &what) : runtime_error(what)
{
}

// WalletLocked

WalletLocked::WalletLocked() : WalletError(_("Wallet locked, unable to create transaction!"))
{
}

// InsufficientFunds

InsufficientFunds::InsufficientFunds() : WalletError(_("Insufficient funds"))
{
}
