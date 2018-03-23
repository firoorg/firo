//
//  GKEllipticCurve.cpp
//  sigma
//
//  Created by David Gray on 07/02/2018.
//  Copyright © 2018 formal. All rights reserved.
//

//#undef USE_ASM_X86_64
//#undef USE_ENDOMORPHISM
#undef USE_FIELD_10X26
#undef USE_FIELD_5X52
#undef USE_FIELD_INV_BUILTIN
#undef USE_FIELD_INV_NUM
#undef USE_NUM_GMP
#undef USE_NUM_NONE
#undef USE_SCALAR_4X64
#undef USE_SCALAR_8X32
#undef USE_SCALAR_INV_BUILTIN
#undef USE_SCALAR_INV_NUM

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_FIELD_5X52 1
#define USE_SCALAR_4X64 1
#define USE_ASM_X86_64
#define USE_ENDOMORPHISM
#define SECP256K1_GNUC_PREREQ(_maj,_min) 0

//typedef __int128 uint128_t;
//#undef HAVE_CONFIG_H
//#define USE_NUM_GMP
#define SECP256K1_INLINE

#include "GKEllipticCurve.hpp"
//#include "sha256.h"
#include "gmp.h"
//#include "basic-config.h"
#include "util.h"
//#include "num_gmp.h"
//#include "num_gmp_impl.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "scratch_impl.h"
#include "GKNumbers.hpp"

void _convertToGmp(mpz_t result,secp256k1_scalar* value) {
    unsigned char buffer[64];
    secp256k1_scalar_get_b32(buffer,value);
    mpz_import(result,1,1,32,1,0,(void*)buffer);
}

void _convertFromGmp(secp256k1_scalar* result,mpz_t value) {
    unsigned char buffer[64];
    size_t count = 0;
    mpz_export((void*)buffer,&count,1,32,1,0,value);
    if (count != 1) {
        throw "ECScalar: invalid count";
    }
    int overflow = 0;
    secp256k1_scalar_set_b32(result,buffer,&overflow);
    if (overflow) {
        throw "ECScalar: overflow error";
    }
}

mpz_t _N;

// ECScalar
//

#ifdef GK_COUNT_OPS
int64_t ECScalar::expmCount = 0;
int64_t ECScalar::multCount = 0;
int64_t ECScalar::invmCount = 0;
#endif

ECScalar::ECScalar() {
    _value = (unsigned char*)malloc(sizeof(secp256k1_scalar));
    secp256k1_scalar_clear((secp256k1_scalar*)_value);
}

ECScalar::ECScalar(const ECScalar& value) {
    _value = (unsigned char*)malloc(sizeof(secp256k1_scalar));
    memcpy(_value,value._value,sizeof(secp256k1_scalar));
}

ECScalar::ECScalar(int64_t value) {
    _value = (unsigned char*)malloc(sizeof(secp256k1_scalar));
    secp256k1_scalar_set_int((secp256k1_scalar*)_value,(int)value);
}

ECScalar::ECScalar(const char* str,int base) {
    _value = (unsigned char*)malloc(sizeof(secp256k1_scalar));
    _setScalar(str,base);
}

ECScalar::~ECScalar() {
    free(_value);
}

ECScalar& ECScalar::set(const ECScalar& other) {
    memcpy(_value,other._value,sizeof(secp256k1_scalar));
    return *this;
}

ECScalar& ECScalar::operator =(const ECScalar& other) {
    memcpy(_value,other._value,sizeof(secp256k1_scalar));
    return *this;
}

ECScalar& ECScalar::mod() {
    secp256k1_scalar zero;
    secp256k1_scalar_clear(&zero);
    secp256k1_scalar_add((secp256k1_scalar*)_value,(secp256k1_scalar*)_value,&zero);
    return *this;
}

ECScalar& ECScalar::add(const ECScalar& other) {
    secp256k1_scalar_add((secp256k1_scalar*)_value,(secp256k1_scalar*)_value,(secp256k1_scalar*)other._value);
    return *this;
}

ECScalar& ECScalar::sub(const ECScalar& other) {
    secp256k1_scalar temp;
    secp256k1_scalar_negate(&temp,(secp256k1_scalar*)other._value);
    secp256k1_scalar_add((secp256k1_scalar*)_value,(secp256k1_scalar*)_value,&temp);
    return *this;
}

ECScalar& ECScalar::mult(const ECScalar& other) {
#ifdef GK_COUNT_OPS
   multCount++;
#endif
    secp256k1_scalar_mul((secp256k1_scalar*)_value, (secp256k1_scalar*)_value,(secp256k1_scalar*)other._value);
    return *this;
}

ECScalar& ECScalar::expm(const ECScalar& exponent) {
#ifdef GK_COUNT_OPS
    expmCount++;
#endif
    mpz_t x;
    GKInit(x);
    _convertToGmp(x,(secp256k1_scalar*)_value);
    mpz_t e;
    GKInit(e);
    _convertToGmp(e,(secp256k1_scalar*)exponent._value);
    mpz_powm(x,x,e,_N);
    _convertFromGmp((secp256k1_scalar*)_value, x);
    mpz_clear(x);
    mpz_clear(e);
    return *this;
}

ECScalar& ECScalar::expm(uint64_t exponent)  {
#ifdef GK_COUNT_OPS
    expmCount++;
#endif
    ECScalar e(exponent);
    return this -> expm(e);
}

ECScalar& ECScalar::invm()  {
#ifdef GK_COUNT_OPS
    invmCount++;
#endif
    mpz_t x;
    GKInit(x);
    _convertToGmp(x,(secp256k1_scalar*)_value);
     mpz_invert(x,x,_N);
    _convertFromGmp((secp256k1_scalar*)_value, x);
    mpz_clear(x);
    return *this;
}

ECScalar& ECScalar::random() {
    mpz_t x;
    GKInit(x);
    mpz_urandomm(x,GK::randomState,_N);
    _convertFromGmp((secp256k1_scalar*)_value, x);
    mpz_clear(x);
    return *this;
}

ECScalar& ECScalar::hash(const unsigned char* data,size_t len)  {
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data,len).Finalize(hash);

    int overflow = 0;
    secp256k1_scalar_set_b32((secp256k1_scalar*)_value,hash,&overflow);
    if (overflow) {
        throw "ECScalar: hashing overflowed";
    }
    this->mod();
    return *this;
}

std::string ECScalar::string(int base) const {
    unsigned char buffer[128];
    secp256k1_scalar_get_b32(buffer,(secp256k1_scalar*)_value);
    mpz_t value;
    GKInit(value);
    mpz_import(value,1,1,32,1,0,(void*)buffer);
    mpz_get_str((char*)buffer,base,value);
    mpz_clear(value);
    return std::string((char*)buffer);
}


bool ECScalar::equal(const ECScalar& op) const {
    return secp256k1_scalar_eq((secp256k1_scalar*)_value,(secp256k1_scalar*)op._value) == 0;
}

bool ECScalar::isMember() const {
    mpz_t x;
    GKInit(x);
    _convertToGmp(x,(secp256k1_scalar*)_value);
    int r = mpz_cmp(x,_N);
    mpz_clear(x);
    return r < 0;
}

size_t ECScalar::writeMemoryRequired() const  {
    return 32;
}

unsigned char* ECScalar::encode(unsigned char* buffer) const {
    secp256k1_scalar_get_b32(buffer,(secp256k1_scalar*)_value);
    return buffer + 32;
}

size_t ECScalar::readMemoryRequired(unsigned char* buffer) const{
    return 32;
}

unsigned char* ECScalar::decode(unsigned char* buffer)  {
    int overflow = 0;
    secp256k1_scalar_set_b32((secp256k1_scalar*)_value,buffer,&overflow);
    if (overflow) {
        throw "ECScalar: decoding overflowed";
    }
    return buffer + 32;
}

void ECScalar::_setScalar(const char* str,int base) {
    unsigned char buffer[128];
    mpz_t value;
    GKInit(value);
    mpz_set_str(value,str,base);
    size_t count = 0;
    mpz_export((void*)buffer,&count,1,32,1,0,value);
    mpz_clear(value);
    if (count != 1) {
        throw "setScalar: invalid count";
    }
    int overflow = 0;
    secp256k1_scalar_set_b32((secp256k1_scalar*)_value,buffer,&overflow);
}

//
// ECGroupElement
//

static secp256k1_ecmult_context _ctx;

#ifdef GK_COUNT_OPS
int64_t ECGroupElement::expmCount = 0;
int64_t ECGroupElement::multCount = 0;
int64_t ECGroupElement::invmCount = 0;
#endif

ECGroupElement::ECGroupElement() {
    _value = (unsigned char*)malloc(sizeof(secp256k1_gej));
    secp256k1_gej_set_infinity((secp256k1_gej*)_value);
}

ECGroupElement::ECGroupElement(const ECGroupElement& value)  {
    _value = (unsigned char*)malloc(sizeof(secp256k1_gej));
    memcpy(_value,value._value,sizeof(secp256k1_gej));
}

//ECGroupElement::ECGroupElement(const secp256k1_ge* value) {
//    secp256k1_gej_set_ge(&_value,value);
//}

//ECGroupElement::ECGroupElement(const secp256k1_gej* value) {
//    _value = *value;
//}

void _convertToFieldElement(secp256k1_fe *r,const char* str,int base) {
    unsigned char buffer[128];
    mpz_t value;
    GKInit(value);
    mpz_set_str(value,str,base);
    size_t count = 0;
    mpz_export((void*)buffer,&count,1,32,1,0,value);
    mpz_clear(value);
    if (count != 1) {
        throw "ECGroupElement::ECGroupElement: invalid count";
    }
    secp256k1_fe_set_b32(r,buffer);
}

ECGroupElement::ECGroupElement(const char* xStr,const char* yStr,int base) {
    secp256k1_ge element;
    _value = (unsigned char*)malloc(sizeof(secp256k1_gej));
    _convertToFieldElement(&element.x,xStr,base);
    _convertToFieldElement(&element.y,yStr,base);
    element.infinity = 0;
    secp256k1_gej_set_ge((secp256k1_gej*)_value,&element);
}

ECGroupElement::~ECGroupElement() {
    free(_value);
}

ECGroupElement& ECGroupElement::set(const ECGroupElement& other) {
    memcpy(_value,other._value,sizeof(secp256k1_gej));
    return *this;
}

ECGroupElement& ECGroupElement::operator =(const ECGroupElement& other) {
    memcpy(_value,other._value,sizeof(secp256k1_gej));
    return *this;
}

ECGroupElement& ECGroupElement::mult(const ECGroupElement& other) {
#ifdef GK_COUNT_OPS
    multCount++;
#endif
    secp256k1_gej_add_var((secp256k1_gej*)_value,(secp256k1_gej*)_value,(secp256k1_gej*)other._value,NULL);
     return *this;
}

ECGroupElement& ECGroupElement::expm(const ECScalar& exponent) {
#ifdef GK_COUNT_OPS
    expmCount++;
#endif
    secp256k1_scalar ng;
    secp256k1_scalar_set_int(&ng,0);

    secp256k1_ecmult(&_ctx,(secp256k1_gej*)_value,(secp256k1_gej*)_value,(secp256k1_scalar*)exponent._value,&ng);
    return *this;
}

ECGroupElement& ECGroupElement::invm() {
#ifdef GK_COUNT_OPS
    invmCount++;
#endif
    secp256k1_gej_neg((secp256k1_gej*)_value,(secp256k1_gej*)_value);
    return *this;
}

char* _convertToString(char* str,const unsigned char* buffer,int base) {
    mpz_t value;
    GKInit(value);
    mpz_import(value,1,1,32,1,0,(void*)buffer);
    mpz_get_str(str,base,value);
    mpz_clear(value);
    return str + strlen(str);
}

std::string ECGroupElement::string(int base) const {
    secp256k1_ge ge;
    secp256k1_ge_set_gej(&ge,(secp256k1_gej*)_value);
    if (ge.infinity) {
        return std::string("O");
    }
    char str[512];
    unsigned char buffer[32];
    char* ptr = str;

    *ptr++ = '(';
    secp256k1_fe_get_b32(buffer,&ge.x);
    ptr = _convertToString(ptr,buffer,base);
    *ptr++ = ',';
    secp256k1_fe_get_b32(buffer,&ge.y);
    ptr = _convertToString(ptr,buffer,base);
    *ptr++ = ')';
    *ptr++ = '\0';
    return std::string(str);
}

bool ECGroupElement::equal(const ECGroupElement& op) const {
    secp256k1_ge v1;
    secp256k1_ge v2;

    secp256k1_ge_set_gej(&v1,(secp256k1_gej*)_value);
    secp256k1_ge_set_gej(&v2,(secp256k1_gej*)op._value);

    if (v1.infinity != v2.infinity) {
        return false;
    }
    if (v1.infinity) {
        return true;
    }
    return (secp256k1_fe_equal_var(&v1.x,&v2.x)) && (secp256k1_fe_equal_var(&v1.y,&v2.y));
}

bool ECGroupElement::isMember() const {
    secp256k1_ge v1;
    secp256k1_ge_set_gej(&v1,(secp256k1_gej*)_value);
    if (secp256k1_ge_is_infinity(&v1)) {
        return true;
    }
    return secp256k1_ge_is_valid_var(&v1);
}

size_t ECGroupElement::writeMemoryRequired() const  {
    return sizeof(secp256k1_ge_storage);
}

unsigned char* ECGroupElement::encode(unsigned char* buffer) const {
    secp256k1_ge value;
    secp256k1_ge_storage storage;

    secp256k1_ge_set_gej(&value,(secp256k1_gej*)_value);
    secp256k1_ge_to_storage(&storage,&value);
    memcpy(buffer,&storage,sizeof(secp256k1_ge_storage));
    return buffer + sizeof(secp256k1_ge_storage);
}

size_t ECGroupElement::readMemoryRequired(unsigned char* buffer) const {
    return sizeof(secp256k1_ge_storage);
}

unsigned char*  ECGroupElement::decode(unsigned char* buffer) {
    secp256k1_ge value;
    secp256k1_ge_storage storage;
    memcpy(&storage,buffer,sizeof(secp256k1_ge_storage));
    secp256k1_ge_from_storage(&value,&storage);
    secp256k1_gej_set_ge((secp256k1_gej*)_value,&value);
    return buffer + sizeof(secp256k1_ge_storage);
}

static void my_illegal_callback_fn(const char* str, void* data) {
    //(void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}

//
//
//

bool initContext() {
    mpz_init_set_str(_N,"115792089237316195423570985008687907852837564279074904382605163141518161494337",10);
    secp256k1_ecmult_context_init(&_ctx);
    secp256k1_ecmult_context_build(&_ctx,(secp256k1_callback*)my_illegal_callback_fn);
    /// int ok = secp256k1_ecmult_context_is_built(&_ctx);
    return false;
}

const ECGroupElement ECGroupElement::G("55066263022277343669578718895168534326250603453777594175500187360389116729240",
                                       "32670510020758816978083085130507043184471273380659243275938904335757337482424",10);
const ECScalar ECScalar::N("115792089237316195423570985008687907852837564279074904382605163141518161494337");

bool start = initContext();
