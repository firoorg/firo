// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHAIN_SETTINGS_H
#define CHAIN_SETTINGS_H

namespace llmq {

inline bool IsNewInstantSendEnabled()
{
    return false;
}

inline bool IsChainlocksEnabled()
{
    return false;
}

inline bool IsBlockFilteringEnabled()
{
    return false;
}

inline int GetInstantsendMaxValue()
{
    return 500;
}


}

#endif
