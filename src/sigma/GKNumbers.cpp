//
//  GKNumbers.cpp
//  sigma
//
//  Created by David Gray on 16/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#include "GKNumbers.hpp"
#include <cassert>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>


namespace GK {
    
    size_t numberOfBits(size_t x) {
        assert(x >= 5);
        size_t n = 0;
        while (x != 0) {
            x /= 2;
            n++;
        }
        return n;
    }
    
    void initWithRandomSeed(mpz_t seed,size_t N) {
        int file;
        if ((file = open("/dev/urandom",O_RDONLY)) < 0) {
            fprintf(stderr,"%s\n","Unable to open /dev/urandom");
            throw "Unable to open /dev/random";
        } else {
            unsigned char* buffer[64];
            size_t size = 0;
            while (size != N) {
                ssize_t len = read(file,buffer+size,N-size);
                if (len < 0) {
                    fprintf(stderr,"%s (len = %zu\n","Insufficient random data",len);
                    throw "Insufficient random data";
                }
                size += len;
            }
            mpz_import(seed,1,1,N,1,0,buffer);
        }
        close(file);
    }

    gmp_randstate_t randomState;
    mpz_t P;
    mpz_t Q;
    
    bool initNumbers() {
        mpz_init_set_str(P,"7151900323885827944049621500688024363267489938005319556573184762145065514933628872071316749139144798803254458801697495323980113445824705621031620957889307",10);
        mpz_init_set_str(Q,"3575950161942913972024810750344012181633744969002659778286592381072532757466814436035658374569572399401627229400848747661990056722912352810515810478944653",10);
        // mpz_init_set_str(P,"64635119",10);
        // mpz_init_set_str(Q,"32317559",10);
        
        // TODO: The following approach needs to be reviewed as,
        //       at the very least, better seeding is required.
        
        size_t s = mpz_size(P);
        size_t ss =  sizeof(mp_limb_t);
        size_t bits = s * 8 * sizeof(mp_limb_t);
        
        
        
        mpz_t seed;
        GKInit(seed);
        initWithRandomSeed(seed,64);
        gmp_randinit_lc_2exp_size(randomState,128);
        gmp_randseed(randomState,seed);
        mpz_clear(seed);
        return false;
    }
    
    bool start = initNumbers();
    
    void printNumber(const mpz_t number) {
        char* str = mpz_get_str(NULL,10,number);
        std::cerr << str << std::endl;
        free(str);
    }
    
    size_t rand(size_t max) { // 0,1,...,max-1
        mpz_t r;
        mpz_t m;
        
        GKInit(r);
        GKInit(m);
        mpz_set_ui(m,max);
        mpz_urandomm(r,randomState,m);
        size_t result = mpz_get_ui(r);
        
        mpz_clear(m);
        mpz_clear(r);
        return result;
    }
    
}

