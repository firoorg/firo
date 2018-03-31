// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACTIVEVNODE_H
#define ACTIVEVNODE_H

#include "net.h"
#include "key.h"
#include "wallet/wallet.h"

class CActiveVnode;

static const int ACTIVE_VNODE_INITIAL          = 0; // initial state
static const int ACTIVE_VNODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_VNODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_VNODE_NOT_CAPABLE      = 3;
static const int ACTIVE_VNODE_STARTED          = 4;

extern CActiveVnode activeVnode;

// Responsible for activating the Vnode and pinging the network
class CActiveVnode
{
public:
    enum vnode_type_enum_t {
        VNODE_UNKNOWN = 0,
        VNODE_REMOTE  = 1,
        VNODE_LOCAL   = 2
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    vnode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Vnode
    bool SendVnodePing();

public:
    // Keys for the active Vnode
    CPubKey pubKeyVnode;
    CKey keyVnode;

    // Initialized while registering Vnode
    CTxIn vin;
    CService service;

    int nState; // should be one of ACTIVE_VNODE_XXXX
    std::string strNotCapableReason;

    CActiveVnode()
        : eType(VNODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeyVnode(),
          keyVnode(),
          vin(),
          service(),
          nState(ACTIVE_VNODE_INITIAL)
    {}

    /// Manage state of active Vnode
    void ManageState();

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;

private:
    void ManageStateInitial();
    void ManageStateRemote();
    void ManageStateLocal();
};

#endif
