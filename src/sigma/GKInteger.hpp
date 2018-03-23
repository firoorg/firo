//
// GKInteger.hpp
//  sigma
//
//  Created by David Gray on 29/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef ModuloInteger_hpp
#define ModuloInteger_hpp

#include <stdio.h>
#include <sstream>
#include <cassert>
#include "crypto/common.h"
#include "crypto/sha256.h"
#include <gmp.h>
#include "GKNumbers.hpp"
#include "GKDebug.hpp"

template <mpz_t M>
class ModuloInteger {
private:

    mpz_t _value;

#ifdef GK_COUNT_OPS
    static int64_t expmCount;
    static int64_t multCount;
    static int64_t invmCount;
#endif

public:

    template <mpz_t Q,mpz_t P>
    friend class IntegerGroupElement;

    ModuloInteger() {
        GKInit(_value);
    }

    ModuloInteger(const ModuloInteger& value) {
        GKInit(_value);
        mpz_set(_value,value._value);
    }

    ModuloInteger(int64_t value) {
        GKInit(_value);
        mpz_set_ui(_value,value);
    }

    ModuloInteger(const char* str,int base = 10) {
        GKInit(_value);
        mpz_set_str(_value,str,base);
    }

    ~ModuloInteger() {
       mpz_clear(_value);
    }

    ModuloInteger& set(const ModuloInteger& other) {
        mpz_set(_value,other._value);
        return *this;
    }

    ModuloInteger& operator =(const ModuloInteger& other) {
        mpz_set(_value,other._value);
        return *this;
    }

    ModuloInteger& mod() {
        mpz_mod(_value,_value,M);
        return *this;
    }

    ModuloInteger& add(const ModuloInteger& other) {
        mpz_add(_value,_value,other._value);
        mpz_mod(_value,_value,M);
        return *this;
    }

    ModuloInteger& sub(const ModuloInteger& other) {
        mpz_sub(_value,_value,other._value);
        mpz_mod(_value,_value,M);
        return *this;
    }

    ModuloInteger& mult(const ModuloInteger& other) {
#ifdef GK_COUNT_OPS
        multCount++;
#endif
        mpz_mul(_value,_value,other._value);
        mpz_mod(_value,_value,M);
        return *this;
    }

    ModuloInteger& expm(const ModuloInteger& exponent)  {
#ifdef GK_COUNT_OPS
        expmCount++;
#endif
        mpz_powm(_value,_value,exponent._value,M);  // See mpz_powm_sec()
        return *this;
    }

    ModuloInteger& expm(uint64_t exponent)  {
#ifdef GK_COUNT_OPS
        expmCount++;
#endif
        mpz_powm_ui(_value,_value,exponent,M);  // See mpz_powm_sec()
        return *this;
    }

    ModuloInteger& expm(const mpz_t exponent)  {
#ifdef GK_COUNT_OPS
        expmCount++;
#endif
        mpz_powm(_value,_value,exponent,M);  // See mpz_powm_sec()
        return *this;
    }

    ModuloInteger& invm()  {
#ifdef GK_COUNT_OPS
        invmCount++;
#endif
        mpz_invert(_value,_value,M);
        return *this;
    }

    ModuloInteger& random() {
        mpz_urandomm(_value,GK::randomState,M);
        mod();
        return *this;
    }

    ModuloInteger& hash(const unsigned char* data,size_t len)  {
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(data,len).Finalize(hash);

        mpz_import(_value,CSHA256::OUTPUT_SIZE,-1,1,-1,0,&hash);
        mpz_mod(_value,_value,M);

        return *this;
    }

    std::string string(int base = 10) const {
        char buffer[256];
        mpz_get_str(buffer,10,_value);
        return std::string(buffer);
    }

    bool equal(const ModuloInteger& op) {
        return mpz_cmp(_value,op._value) == 0;
    }

    bool isMember() const {
        return (mpz_sgn(_value) >= 0) && (mpz_cmp(_value,M) < 0);
    }

    friend std::ostream& operator<< ( std::ostream& os, const ModuloInteger& c) {
        os << c.string();
        return os;
    }

    size_t writeMemoryRequired() const  {
        return (mpz_sizeinbase(_value,2) >> 3) + 8;
    }

    unsigned char* encode(unsigned char* buffer) const {
        size_t count;
        mpz_export(buffer+4,&count,-1,1,0,0,_value);
        WriteLE32(buffer,(uint32_t)(count));
        return buffer + 4 + count;
    }

    size_t readMemoryRequired(unsigned char* buffer) const {
        size_t count = ReadLE32(buffer);
        return count + 4;
    }

    unsigned char* decode(unsigned char* buffer)  {
        size_t count = ReadLE32(buffer);
        mpz_import(_value,count,-1,1,1,0,buffer+4);
        return buffer + 4 + count;
    }

#ifdef GK_COUNT_OPS
    static void _displayCounts() {
        std::cerr << "ModuloInteger (e: " << expmCount << ",m: " << multCount << ",i: " << invmCount << ")" << std::endl;
    }

    static void _clearCount() {
        expmCount = 0;
        multCount = 0;
        invmCount = 0;
    }
#endif

};

template <mpz_t P,mpz_t Q>
class IntegerGroupElement {
private:
    ModuloInteger<P> _value;

#ifdef GK_COUNT_OPS
    static int64_t expmCount;
    static int64_t multCount;
    static int64_t invmCount;
#endif

public:

    IntegerGroupElement() :_value(1) {
    }

    IntegerGroupElement(const IntegerGroupElement& value) :_value(value._value)  {
    }

    IntegerGroupElement(const ModuloInteger<P>& value) :_value(value)  {
    }

    IntegerGroupElement(uint64_t value) :_value(value)  {
    }

    IntegerGroupElement(const char* str,int base = 10) :_value(str,base)  {
    }

    IntegerGroupElement& set(const IntegerGroupElement& other) {
        _value.set(other._value);
        return *this;
    }

    IntegerGroupElement& operator =(const IntegerGroupElement& other) {
        _value = other._value;
        return *this;
    }

    IntegerGroupElement& mult(const IntegerGroupElement& other) {
#ifdef GK_COUNT_OPS
        multCount++;
#endif
        _value.mult(other._value);
        return *this;
    }

    IntegerGroupElement& expm(const ModuloInteger<Q>& exponent) {
#ifdef GK_COUNT_OPS
        expmCount++;
#endif
        mpz_powm(_value._value,_value._value,exponent._value,P);  // See mpz_powm_sec()
        return *this;
    }

    IntegerGroupElement& invm() {
#ifdef GK_COUNT_OPS
        invmCount++;
#endif
        _value.invm();
        return *this;
    }

    size_t writeMemoryRequired() const  {
        return _value.writeMemoryRequired();
    }

    unsigned char* encode(unsigned char* buffer) const {
        return _value.encode(buffer);
    }

    size_t readMemoryRequired(unsigned char* buffer) const {
        return _value.readMemoryRequired(buffer);
    }

    unsigned char*  decode(unsigned char* buffer) {
        return _value.decode(buffer);
    }

    bool equal(const IntegerGroupElement& op) {
        return _value.equal(op._value);
    }

    bool isMember() const {
        mpz_t one;
        GKInit(one);
        mpz_powm(one,_value._value,Q,P);  // See mpz_powm_sec()
        bool isMember = mpz_cmp_ui(one,1) == 0;
        mpz_clear(one);
        return isMember;
    }

    friend std::ostream& operator<< ( std::ostream& os, const IntegerGroupElement& s ) {
        os << s._value ;
        return os;
    }

    void debug() const {
        _value.debug();
    }

#ifdef GK_COUNT_OPS
    static void _displayCounts() {
        std::cerr << "IntegerGroupElement (e: " << expmCount << ",m: " << multCount << ",i: " << invmCount << ")" << std::endl;
        std::cerr << "    " ;
        ModuloInteger<Q>::_displayCounts();
    }

    static void _clearCount() {
        expmCount = 0;
        multCount = 0;
        invmCount = 0;
        ModuloInteger<P>::_clearCount();
    }
#endif

};


#ifdef GK_COUNT_OPS

template <mpz_t M>
int64_t ModuloInteger<M>::expmCount = 0;

template <mpz_t M>
int64_t ModuloInteger<M>::multCount = 0;

template <mpz_t M>
int64_t ModuloInteger<M>::invmCount = 0;

template <mpz_t P,mpz_t Q>
int64_t IntegerGroupElement<P,Q>::expmCount = 0;

template <mpz_t P,mpz_t Q>
int64_t IntegerGroupElement<P,Q>::multCount = 0;

template <mpz_t P,mpz_t Q>
int64_t IntegerGroupElement<P,Q>::invmCount = 0;

#endif

#endif /* ModuloInteger_hpp */
