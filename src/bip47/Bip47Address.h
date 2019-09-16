/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BIP47ADDRESS_H
#define BIP47ADDRESS_H
#include "bip47_common.h"
class Bip47Address {
    private:
     String address;
     int index = 0;
     boolean seen = false;
    public:
        Bip47Address();
        Bip47Address(String v_address, int v_index);
        Bip47Address(String v_address, int v_index, boolean v_seen) ;
        String getAddress() ;
        int getIndex() ;
        boolean isSeen() ;
        void setSeen(boolean v_seen) ;
        virtual String toString() ;
};

#endif