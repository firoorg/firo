/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BIP47ADDRESS_H
#define BIP47ADDRESS_H
#include "bip47_common.h"
#include "serialize.h"
#include "clientversion.h"

class Bip47Address {
    private:
     String address;
     int index = 0;
     bool seen = false;
    public:
        Bip47Address();
        Bip47Address(String v_address, int v_index);
        Bip47Address(String v_address, int v_index, bool v_seen) ;
        String getAddress() ;
        int getIndex() ;
        bool isSeen() ;
        void setSeen(bool v_seen) ;
        virtual String toString() ;
        
        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(address);
            READWRITE(index);
            READWRITE(seen);
        }
};

#endif
