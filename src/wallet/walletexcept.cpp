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

InsufficientFunds::InsufficientFunds(const char *what) : WalletError(what)
{
}

InsufficientFunds::InsufficientFunds(const std::string& what) : WalletError(what)
{
}

// SparkFundsFragmented

SparkFundsFragmented::SparkFundsFragmented() : WalletError(_(
    "Spark multi-input spends are temporarily disabled. "
    "No single available Spark coin can fund this transaction."))
{
}

SparkFundsFragmented::SparkFundsFragmented(const char *what) : WalletError(what)
{
}

SparkFundsFragmented::SparkFundsFragmented(const std::string& what) : WalletError(what)
{
}
