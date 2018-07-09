// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_APIREGISTER_H
#define BITCOIN_APIREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/client-api/ */
class CAPITable;

/** Register block chain API commands */
void RegisterAPICommands(CAPITable &tableAPI);

static inline void RegisterAllCoreAPICommands(CAPITable &tableAPI)
{
    // maybe readd after
    //RegisterAPICommands(tableAPI);
}

#endif
