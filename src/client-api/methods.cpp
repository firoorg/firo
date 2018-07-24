// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "client-api/server.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.cpp"
#include <stdint.h>
#include <client-api/protocol.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

using namespace std;

UniValue apistatus(const UniValue& data)
{
    LogPrintf("API status called.");
    return true;
}
UniValue lockwallet(const UniValue& data)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (fHelp || data.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletunlock again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but lockwallet was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return true;
}

UniValue unlockwallet(const UniValue& data)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in data[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make data[0] mlock()'d to begin with.

    LogPrintf("getting values \n");
    vector<UniValue> values = data.getValues();
    LogPrintf("values size: %s\n", to_string(values.size()));
    

    UniValue auth = find_value(data, "auth");
    UniValue password = find_value(data, "password");

    LogPrintf("valtype: %s\n", password.type());

    strWalletPass = password.get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else //TODO length error
        throw runtime_error(
            "walletunlock <passphrase>\n"
            "Stores the wallet decryption key in memory.");

    pwalletMain->TopUpKeyPool();

    return true;
}

static const CAPICommand commands[] =
{ //  type                  collection     actor (function)        authPort  authPassphrase
  //  --------------------- ------------ -----------------------  ---------- --------------
    { "get",         "apistatus",       &apistatus,              false,    false  },
    { "modify",      "lockwallet",      &lockwallet,             true,     false  },
    { "modify",      "unlockwallet",    &unlockwallet,           true,     false  }
};

void RegisterAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
