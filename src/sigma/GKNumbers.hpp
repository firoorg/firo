//
//  GKNumbers.hpp
//  sigma
//
//  Created by David Gray on 16/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef GKNumbers_hpp
#define GKNumbers_hpp

#include <stdio.h>
#include <iostream>
#include <gmp.h>

#ifdef GK_FIXED_SIZE
#define GKInit(v) mpz_init2(v,576)
#else
#define GKInit(v) mpz_init(v)
#endif



namespace GK {

    size_t numberOfBits(size_t x);
    
    extern gmp_randstate_t randomState;
    extern mpz_t P;
    extern mpz_t Q;
    
    void printNumber(const mpz_t number);
    size_t rand(size_t max);
    
}


#endif /* GKNumbers_hpp */
