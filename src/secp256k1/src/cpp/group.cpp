#include "group.hpp"

#include "num.hpp"
#include "scalar.hpp"
#include "secp256k1.hpp"

#include "../group_impl.h"
#include "../ecmult_impl.h"
#include "../field_impl.h"
#include "../hash_impl.h"
#include "../num_impl.h"
#include "../scalar_impl.h"

#include <array>
#include <memory>
#include <sstream>
#include <string>

#include <string.h>

namespace {

secp256k1_ge jacobian_to_affine(secp256k1_gej j) { // secp256k1_ge_set_gej need to write on j so need to pass by value
    secp256k1_ge a;
    secp256k1_ge_set_gej(&a, &j);
    return a;
}

// Implements the algorithm from:
//
// Indifferentiable Hashing to Barreto-Naehrig Curves
// Pierre-Alain Fouque and Mehdi Tibouchi
// Latincrypt 2012
void indifferent_hash(secp256k1_ge *ge, const secp256k1_fe *t) {
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

} // unnamed namespace

namespace secp_primitives {

GroupElement::Data::Data() noexcept {
    secp256k1_gej_clear(&value);
    value.infinity = 1;
}

GroupElement::GroupElement() : data(new Data()) {
}

GroupElement::GroupElement(const char *x, const char *y, unsigned base) : GroupElement() {
    secp256k1_ge v;

    secp256k1_fe_set_b32(&v.x, secp256k1::parse_int(x, x + strlen(x), base).data());
    secp256k1_fe_set_b32(&v.y, secp256k1::parse_int(y, y + strlen(y), base).data());
    v.infinity = 0;

    secp256k1_gej_set_ge(&data->value, &v);
}

GroupElement::GroupElement(const Data& d) : data(new Data(d)) {
}

GroupElement::GroupElement(const GroupElement& other) : data(new Data(*other.data)) {
}

GroupElement::~GroupElement() {
    // don't remove this destructor otherwise it will inlined on the outside and cause linking error due to
    // GroupElement::Data is incomplete type
}

GroupElement& GroupElement::operator=(const GroupElement &other) {
    *data = *other.data;
    return *this;
}

GroupElement GroupElement::operator*(const Scalar& scalar) const {
    secp256k1_scalar ng;
    Data r;

    secp256k1_scalar_set_int(&ng, 0);
    secp256k1_ecmult(&secp256k1::default_context->ecmult_ctx, &r.value, &data->value, &scalar.get_data().value, &ng);

    return r;
}

GroupElement& GroupElement::operator*=(const Scalar& scalar) {
    secp256k1_scalar ng;
    secp256k1_gej r;

    secp256k1_scalar_set_int(&ng, 0);
    secp256k1_ecmult(&secp256k1::default_context->ecmult_ctx, &r, &data->value, &scalar.get_data().value, &ng);

    data->value = r;

    return *this;
}

GroupElement GroupElement::operator+(const GroupElement& other) const {
    Data r;
    secp256k1_gej_add_var(&r.value, &data->value, &other.data->value, nullptr);
    return r;
}

GroupElement& GroupElement::operator+=(const GroupElement& other) {
    secp256k1_gej r;

    secp256k1_gej_add_var(&r, &data->value, &other.data->value, nullptr);
    data->value = r;

    return *this;
}

bool GroupElement::operator==(const  GroupElement& other) const {
    if (data->value.infinity && other.data->value.infinity) {
        return true;
    }

    if (data->value.infinity != other.data->value.infinity) {
        return false;
    }

    auto a = jacobian_to_affine(data->value);
    auto b = jacobian_to_affine(other.data->value);

    if (!secp256k1_fe_equal(&a.x, &b.x) || !secp256k1_fe_equal(&a.y, &b.y)) {
        return false;
    }

    return true;
}

bool GroupElement::operator!=(const GroupElement& other) const {
    return !(*this == other);
}

size_t GroupElement::hash() const {
    auto v = jacobian_to_affine(data->value);
    std::array<unsigned char, 32 * 2> coord;

    if (v.infinity) {
        coord.fill(0);
    } else {
        secp256k1_fe_get_b32(&coord[0], &v.x);
        secp256k1_fe_get_b32(&coord[32], &v.y);
    }

    return std::hash<std::string>()(std::string(coord.begin(), coord.end()));
}

std::vector<unsigned char> GroupElement::getvch() const {
    std::vector<unsigned char> result(memoryRequired(), 0);
    serialize(result.data());
    return result;
}

void GroupElement::sha256(unsigned char *result) const {
    unsigned char buf[64];
    secp256k1_rfc6979_hmac_sha256 sha256;

    secp256k1_fe_get_b32(&buf[0], &data->value.x);
    secp256k1_fe_get_b32(&buf[32], &data->value.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&sha256, buf, sizeof(buf));
    secp256k1_rfc6979_hmac_sha256_generate(&sha256, result, 32);
}

bool GroupElement::isMember() const {
    auto v = jacobian_to_affine(data->value);

    if (secp256k1_ge_is_infinity(&v)) {
        return true;
    }

    return secp256k1_ge_is_valid_var(&v);
}

bool GroupElement::isInfinity() const
{
    return secp256k1_gej_is_infinity(&data->value);
}

GroupElement GroupElement::inverse() const {
    Data r;
    secp256k1_gej_neg(&r.value, &data->value);
    return r;
}

void GroupElement::square() {
    secp256k1_gej r;
    secp256k1_gej_double_var(&r, &data->value, nullptr);
    data->value = r;
}

GroupElement& GroupElement::set_base_g() {
    secp256k1_gej_set_ge(&data->value, &secp256k1_ge_const_g);
    return *this;
}

GroupElement& GroupElement::generate(const unsigned char *seed) {
    static const unsigned char prefix1[16] = "1st generationn";
    static const unsigned char prefix2[16] = "2nd generationn";

    secp256k1_sha256 sha256;
    unsigned char hash[32];
    secp256k1_fe t = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 4);
    secp256k1_ge add;
    secp256k1_gej accum, tmp;
    unsigned char gen[33];

    int overflow;

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, prefix1, sizeof(prefix1));
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_finalize(&sha256, hash);

    secp256k1_fe_set_b32(&t, hash);
    indifferent_hash(&add, &t);
    secp256k1_gej_set_ge(&accum, &add);

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, prefix2, sizeof(prefix2));
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_finalize(&sha256, hash);

    secp256k1_fe_set_b32(&t, hash);
    indifferent_hash(&add, &t);
    secp256k1_gej_add_ge(&tmp, &accum, &add);
    accum = tmp;

    secp256k1_ge_set_gej(&add, &accum);
    secp256k1_fe_normalize(&add.x);

    secp256k1_fe_get_b32(gen + 1, &add.x);
    gen[0] = 11 ^ secp256k1_fe_is_quad_var(&add.y);

    // load group element from gen
    secp256k1_fe fe;
    secp256k1_ge ge;

    secp256k1_fe_set_b32(&fe, gen + 1);
    secp256k1_ge_set_xquad(&ge, &fe);

    if (gen[0] & 1) {
        secp256k1_ge v;
        secp256k1_ge_neg(&v, &ge);
        ge = v;
    }

    secp256k1_gej_set_ge(&data->value, &ge);

    return *this;
}

void GroupElement::randomize() {
    unsigned char seed[32];

    do {
        secp256k1::random_bytes(seed, sizeof(seed));
        generate(seed);
    } while (!isMember());
}

std::string GroupElement::GetHex() const {
    return tostring(16);
}

std::string GroupElement::tostring(unsigned base) const {
    auto v = jacobian_to_affine(data->value);

    if (v.infinity) {
        return "O";
    }

    std::stringstream s;
    std::array<unsigned char, 32> x, y;

    secp256k1_fe_get_b32(x.data(), &v.x);
    secp256k1_fe_get_b32(y.data(), &v.y);

    s << '(';
    s << secp256k1::int_to_string(x.begin(), x.end(), base);
    s << ',';
    s << secp256k1::int_to_string(y.begin(), y.end(), base);
    s << ')';

    return s.str();
}

unsigned char * GroupElement::serialize() const {
    std::unique_ptr<unsigned char[]> buf(new unsigned char [sizeof(secp256k1_fe) * 2]);

    memcpy(&buf[0], data->value.x.n, sizeof(secp256k1_fe));
    memcpy(&buf[sizeof(secp256k1_fe)], data->value.y.n, sizeof(secp256k1_fe));

    return buf.release();
}

unsigned char * GroupElement::serialize(unsigned char *buffer) const {
    auto v = jacobian_to_affine(data->value);

    secp256k1_fe_normalize(&v.x);
    secp256k1_fe_normalize(&v.y);

    secp256k1_fe_get_b32(buffer, &v.x);
    buffer[32] = secp256k1_fe_is_odd(&v.y);
    buffer[33] = v.infinity;

    return buffer + memoryRequired();
}

unsigned const char * GroupElement::deserialize(unsigned const char *buffer) {
    secp256k1_fe x;
    secp256k1_ge ge;

    secp256k1_fe_set_b32(&x, buffer);
    secp256k1_ge_set_xo_var(&ge, &x, buffer[32]);
    ge.infinity = buffer[33];

    secp256k1_gej_set_ge(&data->value, &ge);

    return buffer + memoryRequired();
}

} // namespace secp_primitives
