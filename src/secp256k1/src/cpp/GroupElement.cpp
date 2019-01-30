#include "include/GroupElement.h"

#include "../field.h"
#include "../field_impl.h"
#include "../group.h"
#include "../group_impl.h"
#include "../hash.h"
#include "../hash_impl.h"
#include "../ecmult.h"
#include "../ecmult_impl.h"
#include "../scalar.h"
#include "../scalar_impl.h"

#include <gmp.h>
#include <openssl/rand.h>

#include <stdlib.h>

static secp256k1_ecmult_context ctx;

// Converts the value from secp256k1_gej to secp256k1_ge and returns.
static secp256k1_ge gej_to_ge(const secp256k1_gej &gej)
{
    secp256k1_ge ge;
    secp256k1_gej j(gej);
    secp256k1_ge_set_gej(&ge, &j);
    return ge;
}

namespace secp_primitives {

GroupElement::GroupElement()
        : g_(new secp256k1_gej())
{
    secp256k1_gej_clear(g_.get());
    g_->infinity = 1;
}

GroupElement::GroupElement(const GroupElement& other)
        : g_(new secp256k1_gej(*other.g_))
{
}

GroupElement::GroupElement(const secp256k1_gej *g)
        : g_(new secp256k1_gej(*g))
{
}

void _convertToFieldElement(secp256k1_fe *r,const char* str,int base) {
     unsigned char buffer[128];
    mpz_t value;
    mpz_init(value);
    mpz_set_str(value,str,base);
    size_t count = 0;
    mpz_export((void*)buffer,&count,1,32,1,0,value);
    mpz_clear(value);
    if (count != 1) {
         throw "GroupElement::GroupElement: invalid count";
        }
    secp256k1_fe_set_b32(r,buffer);
}

GroupElement::GroupElement(const char* x,const char* y, int base)
        : g_(new secp256k1_gej())
{
    secp256k1_gej_clear(g_.get());
    secp256k1_ge element;
    _convertToFieldElement(&element.x,x,base);
    _convertToFieldElement(&element.y,y,base);
    element.infinity = 0;
    secp256k1_gej_set_ge(g_.get(),&element);
}

GroupElement::~GroupElement()
{
}

GroupElement& GroupElement::operator=(const GroupElement &other)
{
    return set(other);
}

GroupElement& GroupElement::set(const GroupElement &other)
{
    g_.reset(new secp256k1_gej(*other.g_));
    return *this;
}

GroupElement GroupElement::operator*(const Scalar& multiplier) const
{
    secp256k1_gej result;
    secp256k1_scalar ng;
    secp256k1_scalar_set_int(&ng,0);
    secp256k1_ecmult(&ctx,&result,g_.get(), multiplier.get_value(),&ng);
    return &result;
}

GroupElement& GroupElement::operator*=(const Scalar& multiplier)
{
    secp256k1_scalar ng;
    secp256k1_scalar_set_int(&ng,0);
    secp256k1_ecmult(&ctx,g_.get(),g_.get(), multiplier.get_value(),&ng);
    return *this;
}

GroupElement GroupElement::operator+(const GroupElement &other) const
{
    secp256k1_gej result_gej;
    secp256k1_gej_add_var(&result_gej, g_.get(), other.g_.get(), NULL);
    return &result_gej;
}

GroupElement& GroupElement::operator+=(const GroupElement& other)
{
    secp256k1_gej_add_var(g_.get(), g_.get(), other.g_.get(), NULL);
    return *this;
}

GroupElement GroupElement::inverse() const
{
    secp256k1_gej result_gej;
    secp256k1_gej_neg(&result_gej,g_.get());
    return &result_gej;
}

void GroupElement::square()
{
    secp256k1_gej_double_var(g_.get(), g_.get(), NULL);
}

bool GroupElement::operator==(const  GroupElement& other) const
{
    if(g_->infinity && other.g_->infinity)
        return true;
    if(g_->infinity != other.g_->infinity)
        return false;
    secp256k1_ge this_ge = gej_to_ge(*g_);
    secp256k1_ge other_ge = gej_to_ge(*other.g_);
    if(!secp256k1_fe_equal(&this_ge.x, &other_ge.x))
        return false;
    if(!secp256k1_fe_equal(&this_ge.y, &other_ge.y))
        return false;

    return true;
}

bool GroupElement::operator!=(const  GroupElement& other) const
{
    return !(*this == other);
}

bool GroupElement::isMember() const
{
    secp256k1_ge v1 = gej_to_ge(*g_);
    if (secp256k1_ge_is_infinity(&v1)) {
        return true;
    }
    return secp256k1_ge_is_valid_var(&v1);
}

void GroupElement::randomize(){
    unsigned char temp[32] = { 0 };

    do {
        if (RAND_bytes(temp, 32) != 1) {
            throw "Unable to generate random GroupElement";
        }
        generate(temp);
    }while (!(this->isMember()));
}

GroupElement& GroupElement::generate(unsigned char* seed){
    unsigned char gen[33];
    static const unsigned char prefix1[16] = "1st generationn";
    static const unsigned char prefix2[16] = "2nd generationn";
    secp256k1_fe t = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 4);
    secp256k1_ge add;
    secp256k1_gej accum;
    int overflow;
    secp256k1_sha256_t sha256;
    unsigned char b32[32];
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, prefix1, 16);
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_finalize(&sha256, b32);
    secp256k1_fe_set_b32(&t, b32);
    indifferent_hash(&add, &t);
    secp256k1_gej_set_ge(&accum, &add);
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, prefix2, 16);
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_finalize(&sha256, b32);
    secp256k1_fe_set_b32(&t, b32);
    indifferent_hash(&add, &t);
    secp256k1_gej_add_ge(&accum, &accum, &add);
    secp256k1_ge_set_gej(&add, &accum);
    secp256k1_fe_normalize(&add.x);
    secp256k1_fe_get_b32(gen + 1, &add.x);
    gen[0] = 11 ^ secp256k1_fe_is_quad_var(&add.y);
    //load group element from gen;
    secp256k1_fe fe;
    secp256k1_fe_set_b32(&fe, gen + 1);
    secp256k1_ge ge;
    secp256k1_ge_set_xquad(&ge, &fe);
    if (gen[0] & 1) {
        secp256k1_ge_neg(&ge, &ge);
    }
    secp256k1_gej_set_ge(g_.get(), &ge);
    return *this;
}

void GroupElement::sha256(unsigned char* result) const{
    unsigned char buff[64];
    secp256k1_fe_get_b32(&buff[0], &g_->x);
    secp256k1_fe_get_b32(&buff[32], &g_->y);
    secp256k1_rfc6979_hmac_sha256_t sha256;
    secp256k1_rfc6979_hmac_sha256_initialize(&sha256, buff, 64);
    secp256k1_rfc6979_hmac_sha256_generate(&sha256,  result, 32);
}

char* _convertToString(char* str,const unsigned char* buffer,int base) {
    mpz_t value;
    mpz_init(value);
    mpz_import(value,1,1,32,1,0,(void*)buffer);
    mpz_get_str(str,base,value);
    mpz_clear(value);
return str + strlen(str);
}

std::string GroupElement::tostring() const {
    int base = 10;
    secp256k1_ge ge = gej_to_ge(*g_);

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

std::string GroupElement::GetHex() const {
    int base = 16;
    secp256k1_ge ge = gej_to_ge(*g_);

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

void GroupElement::indifferent_hash(secp256k1_ge* ge, const secp256k1_fe* t){
    static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df, 0x233770c2, 0xa797962c, 0xc61f6d15, 0xda14ecd4, 0x7d8d27ae, 0x1cd5f852);
    static const secp256k1_fe d = SECP256K1_FE_CONST(0x851695d4, 0x9a83f8ef, 0x919bb861, 0x53cbcb16, 0x630fb68a, 0xed0a766a, 0x3ec693d6, 0x8e6afa40);
    static const secp256k1_fe b = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);
    static const secp256k1_fe b_plus_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 8);

    secp256k1_fe wn, wd, x1n, x2n, x3n, x3d, jinv, tmp, x1, x2, x3, alphain, betain, gammain, y1, y2, y3;
    int alphaquad, betaquad;

    secp256k1_fe_mul(&wn, &c, t); /* mag 1 */
    secp256k1_fe_sqr(&wd, t); /* mag 1 */
    secp256k1_fe_add(&wd, &b_plus_one); /* mag 2 */
    secp256k1_fe_mul(&tmp, t, &wn); /* mag 1 */
    secp256k1_fe_negate(&tmp, &tmp, 1); /* mag 2 */
    secp256k1_fe_mul(&x1n, &d, &wd); /* mag 1 */
    secp256k1_fe_add(&x1n, &tmp); /* mag 3 */
    x2n = x1n; /* mag 3 */
    secp256k1_fe_add(&x2n, &wd); /* mag 5 */
    secp256k1_fe_negate(&x2n, &x2n, 5); /* mag 6 */
    secp256k1_fe_mul(&x3d, &c, t); /* mag 1 */
    secp256k1_fe_sqr(&x3d, &x3d); /* mag 1 */
    secp256k1_fe_sqr(&x3n, &wd); /* mag 1 */
    secp256k1_fe_add(&x3n, &x3d); /* mag 2 */
    secp256k1_fe_mul(&jinv, &x3d, &wd); /* mag 1 */
    secp256k1_fe_inv(&jinv, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x1, &x1n, &x3d); /* mag 1 */
    secp256k1_fe_mul(&x1, &x1, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x2, &x2n, &x3d); /* mag 1 */
    secp256k1_fe_mul(&x2, &x2, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x3, &x3n, &wd); /* mag 1 */
    secp256k1_fe_mul(&x3, &x3, &jinv); /* mag 1 */

    secp256k1_fe_sqr(&alphain, &x1); /* mag 1 */
    secp256k1_fe_mul(&alphain, &alphain, &x1); /* mag 1 */
    secp256k1_fe_add(&alphain, &b); /* mag 2 */
    secp256k1_fe_sqr(&betain, &x2); /* mag 1 */
    secp256k1_fe_mul(&betain, &betain, &x2); /* mag 1 */
    secp256k1_fe_add(&betain, &b); /* mag 2 */
    secp256k1_fe_sqr(&gammain, &x3); /* mag 1 */
    secp256k1_fe_mul(&gammain, &gammain, &x3); /* mag 1 */
    secp256k1_fe_add(&gammain, &b); /* mag 2 */

    alphaquad = secp256k1_fe_sqrt(&y1, &alphain);
    betaquad = secp256k1_fe_sqrt(&y2, &betain);
    secp256k1_fe_sqrt(&y3, &gammain);

    secp256k1_fe_cmov(&x1, &x2, (!alphaquad) & betaquad);
    secp256k1_fe_cmov(&y1, &y2, (!alphaquad) & betaquad);
    secp256k1_fe_cmov(&x1, &x3, (!alphaquad) & !betaquad);
    secp256k1_fe_cmov(&y1, &y3, (!alphaquad) & !betaquad);

    secp256k1_ge_set_xy(ge, &x1, &y1);

    /* The linked algorithm from the paper uses the Jacobi symbol of t to
     * determine the Jacobi symbol of the produced y coordinate. Since the
     * rest of the algorithm only uses t^2, we can safely use another criterion
     * as long as negation of t results in negation of the y coordinate. Here
     * we choose to use t's oddness, as it is faster to determine. */
    secp256k1_fe_negate(&tmp, &ge->y, 1);
    secp256k1_fe_cmov(&ge->y, &tmp, secp256k1_fe_is_odd(t));
}

size_t GroupElement::memoryRequired() const  {
    return 34;
}


unsigned char* GroupElement::serialize() const {
    unsigned char* data = new unsigned char[ 2 * sizeof(secp256k1_fe)];
    memcpy(&data[0], &g_->x.n[0], sizeof(secp256k1_fe));
    memcpy(&data[0] + sizeof(secp256k1_fe), &g_->y.n[0], sizeof(secp256k1_fe));
    return data;
}

unsigned char* GroupElement::serialize(unsigned char* buffer) const {
    secp256k1_ge value = gej_to_ge(*g_);
    secp256k1_fe x = value.x;
    secp256k1_fe y = value.y;
    secp256k1_fe_normalize(&x);
    secp256k1_fe_normalize(&y);
    unsigned char oddness = secp256k1_fe_is_odd(&y);
    unsigned char infinity = value.infinity;
    secp256k1_fe_get_b32(buffer, &x);
    buffer[32] = oddness;
    buffer[33] = infinity;
    return buffer + memoryRequired();
}

unsigned char* GroupElement::deserialize(unsigned char* buffer) {
    secp256k1_fe x;
    secp256k1_fe_set_b32(&x, buffer);
    unsigned char oddness = buffer[32];
    unsigned char infinity = buffer[33];
    secp256k1_ge result;
    secp256k1_ge_set_xo_var(&result, &x, (int)oddness);
    result.infinity = (int)infinity;
    secp256k1_gej_set_ge(g_.get(), &result);
    return buffer + memoryRequired();
}

std::vector<unsigned char> GroupElement::getvch() const {
    unsigned char buffer[memoryRequired()];
    serialize(buffer);
    std::vector<unsigned char> result;
    result.insert(result.begin(), buffer, buffer + memoryRequired());
    return result;
}

} // namespace secp_primitives
