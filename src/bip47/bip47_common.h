
/* Copyright (c) 2019 jin
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#ifndef COMMON_H
#define COMMON_H
#include <iostream>
#include <list>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <openssl/sha.h>
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"


    typedef std::string  String;
    class Bip47_common{
        public:
        static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
        static unsigned char* copyOfRange(const std::vector<unsigned char> &original, int from, int to,std::vector<unsigned char> &result) ;
        static bool doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result);

    };
    #define HARDENED_BIT    0x80000000
#endif
