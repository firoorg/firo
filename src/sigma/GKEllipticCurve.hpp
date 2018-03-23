//
//  GKEllipticCurve.hpp
//  sigma
//
//  Created by David Gray on 07/02/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef GKEllipticCurve_hpp
#define GKEllipticCurve_hpp

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <cassert>
#include "crypto/common.h"
#include "crypto/sha256.h"
#include "gmp.h"

class ECScalar {
private:

    //secp256k1_scalar _value;
    unsigned char* _value;

#ifdef GK_COUNT_OPS
    static int64_t expmCount;
    static int64_t multCount;
    static int64_t invmCount;
#endif

public:
    friend class ECGroupElement;
    static const ECScalar N;

    ECScalar(); ;
    ECScalar(const ECScalar& value);;
    ECScalar(int64_t value);
    ECScalar(const char* str,int base = 10);
    ~ECScalar();

    ECScalar& set(const ECScalar& other);
    ECScalar& operator =(const ECScalar& other); ;
    ECScalar& mod();
    ECScalar& add(const ECScalar& other);
    ECScalar& sub(const ECScalar& other);
    ECScalar& mult(const ECScalar& other);
    ECScalar& expm(const ECScalar& exponent);
    ECScalar& expm(uint64_t exponent);
    ECScalar& invm();
    ECScalar& random();
    ECScalar& hash(const unsigned char* data,size_t len);

    std::string string(int base = 10) const;

    bool equal(const ECScalar& op) const;
    bool isMember() const;

    friend std::ostream& operator<< ( std::ostream& os, const ECScalar& c) {
        os << c.string();
        return os;
    }

    size_t writeMemoryRequired() const;
    unsigned char* encode(unsigned char* buffer) const;
    size_t readMemoryRequired(unsigned char* buffer) const;
    unsigned char* decode(unsigned char* buffer);

#ifdef GK_COUNT_OPS
    static void _displayCounts() {
        std::cerr << "ECScalar (e: " << expmCount << ",m: " << multCount << ",i: " << invmCount << ")" << std::endl;
    }

    static void _clearCount() {
        expmCount = 0;
        multCount = 0;
        invmCount = 0;
    }
#endif

private:

    void _setScalar(const char* str,int base);

};


class ECGroupElement {
private:

    //secp256k1_gej _value;
    void* _value;

#ifdef GK_COUNT_OPS
    static int64_t expmCount;
    static int64_t multCount;
    static int64_t invmCount;
#endif

public:

    static const ECGroupElement G;

    ECGroupElement();
    ECGroupElement(const ECGroupElement& value);
    ECGroupElement(const char* x,const char* y,int base = 10);
    ~ECGroupElement();

    ECGroupElement& set(const ECGroupElement& other);
    ECGroupElement& operator =(const ECGroupElement& other);
    ECGroupElement& mult(const ECGroupElement& other);
    ECGroupElement& expm(const ECScalar& exponent);
    ECGroupElement& invm();

    std::string string(int base = 10) const;
    bool equal(const ECGroupElement& op) const;
    bool isMember() const;

    size_t writeMemoryRequired() const;
    unsigned char* encode(unsigned char* buffer) const;
    size_t readMemoryRequired(unsigned char* buffer) const;
    unsigned char*  decode(unsigned char* buffer);
    friend std::ostream& operator<< ( std::ostream& os, const ECGroupElement& s ) {
        os << s.string() ;
        return os;
    }

#ifdef GK_COUNT_OPS
    static void _displayCounts() {
        std::cerr << "ECGroupElement (e: " << expmCount << ",m: " << multCount << ",i: " << invmCount << ")" << std::endl;
    }

    static void _clearCount() {
        expmCount = 0;
        multCount = 0;
        invmCount = 0;
    }
#endif
};


#endif /* GKEllipticCurve_hpp */
