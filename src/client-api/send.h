// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <univalue.h>
#include <string>

std::map<std::string, int> nStates = {
        {"active",0},
        {"deleted",1},
        {"hidden",2},
        {"archived",3}
};

bool getPaymentRequest(UniValue &paymentRequestUni, UniValue &paymentRequestData);

bool getPaymentRequestEntry(string address, UniValue &entry);

bool getTxMetadata(UniValue &txMetadataUni, UniValue &txMetadataData);

bool setTxMetadata(UniValue txMetadataUni);