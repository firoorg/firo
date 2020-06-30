/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BIP47ADDRESS_H
#define BIP47ADDRESS_H
#include "bip47/utils.h"
#include "clientversion.h"
#include "serialize.h"

class CBIP47Address
{
public:
    CBIP47Address(){}
    CBIP47Address(std::string v_address, int v_index): address(v_address), index(v_index) {}
    CBIP47Address(std::string v_address, int v_index, bool v_seen): address(v_address), index(v_index), seen(v_seen) {}

    std::string getAddress();
    int getIndex();
    bool isSeen();
    void setSeen(bool v_seen);
    virtual std::string toString();

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(address);
        READWRITE(index);
        READWRITE(seen);
    }

private:
    std::string address;
    int index = 0;
    bool seen = false;
};

#endif
