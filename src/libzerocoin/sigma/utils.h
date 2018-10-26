#ifndef ZCOIN_UTILS_H
#define ZCOIN_UTILS_H
#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <algorithm>

namespace sigma {

template<class Exponent, class GroupElement>
void commit(const GroupElement& g,
       const zcoin_common::GeneratorVector<Exponent, GroupElement> h,
       const std::vector<Exponent>& exp,
       const Exponent& r,
       GroupElement& result_out)  {

    result_out += g * r;
    h.get_vector_multiple(exp, result_out);
}

template<class Exponent>
void convert_to_delta(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out){
    int rem, nalNumber = 0;
    int j = 0;

    while (num != 0)
    {
        rem = num % n;
        num /= n;
        for(int i = 0; i < n; ++i){
            if(i == rem)
                out.push_back(Exponent(uint64_t(1)));
            else
                out.push_back(Exponent(uint64_t(0)));
        }
        j++;
    }

    for(int k = j; k < m; ++k){
        out.push_back(Exponent(uint64_t(1)));
        for(int i = 1; i < n; ++i){
                out.push_back(Exponent(uint64_t(0)));
        }
    }
}

std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m){
    std::vector<uint64_t> result;
    uint64_t rem, nalNumber = 0;
    uint64_t j = 0;
    while (num != 0)
    {
        rem = num % n;
        num /= n;
        result.push_back(rem);
        j++;
    }

    for(uint64_t k = j; k <= m; ++k){
        result.push_back(0);
    }
    return result;
}

template<class Exponent, class GroupElement>
void get_x(const GroupElement& A, const GroupElement& C, const GroupElement D, Exponent& result_out) {
    secp256k1_sha256_t hash;
    secp256k1_sha256_initialize(&hash);
    unsigned char data[6 * sizeof(secp256k1_fe)];
    unsigned char *A_serial = A.serialize();
    unsigned char *C_serial = C.serialize();
    unsigned char *D_serial = D.serialize();
    memcpy(&data[0], &A_serial[0], 2 * sizeof(secp256k1_fe));
    memcpy(&data[0] + 2 * sizeof(secp256k1_fe), &C_serial[0], 2 * sizeof(secp256k1_fe));
    memcpy(&data[0] + 4 * sizeof(secp256k1_fe), &D_serial[0], 2 * sizeof(secp256k1_fe));
    secp256k1_sha256_write(&hash, &data[0], 6 * sizeof(secp256k1_fe));
    unsigned char result_data[32];
    secp256k1_sha256_finalize(&hash, result_data);
    delete [] A_serial;
    delete [] C_serial;
    delete [] D_serial;
    result_out = result_data;
}

template<class Exponent, class GroupElement>
GroupElement commit(const GroupElement& g, const Exponent m, const GroupElement h, const Exponent r){
    return g * m + h * r;
}

template<class Exponent>
void newFactor(Exponent x, Exponent a, std::vector<Exponent>& coefficients) {
//    Exponent t((uint64_t)0);
//    for (int i = 0; i < coefficients.size(); i++) {
//        Exponent c(coefficients[i]);
//        coefficients[i] = t + c * a;
//        t = c * x;
//    }
//    coefficients.push_back(t);
    std::vector<Exponent> temp;
    std::vector<Exponent> t;
    t.push_back(x);
    t.push_back(a);

    for(int i = 0; i< coefficients.size() + 1; i++)
        temp.push_back(uint64_t(0));
    for(int i = 0; i< 2; i++){
        for(int j = 0; j < coefficients.size(); j++){
            temp[i+j] += t[i]*coefficients[j];
        }
    }
    coefficients.resize(temp.size());
    for(int i = 0; i < temp.size(); i++)
        coefficients[i] = temp[i];
}

}// namespace sigma
#endif //ZCOIN_UTILS_H
//
//
//
//#ifndef ZCOIN_UTILS_H
//#define ZCOIN_UTILS_H
//#include <vector>
//#include <secp256k1/include/Scalar.h>
//#include <secp256k1/include/GroupElement.h>
//
//namespace sigma {
//
//template<class Exponent, class GroupElement>
//void commit(const GroupElement& g,
//       const zcoin_common::GeneratorVector<Exponent, GroupElement> h,
//       const std::vector<Exponent>& exp,
//       const Exponent& r,
//       GroupElement& result_out)  {
//
//    result_out += g * r;
//    h.get_vector_multiple(exp, result_out);
//}
//
//template<class Exponent>
//void convert_to_delta(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out){
//    int rem, nalNumber = 0;
//    for(int k = 0; k < m; ++k){
//        if(num == 0){
//            out.push_back(Exponent(uint64_t(1)));
//            for(int i = 1; i < n; ++i){
//                out.push_back(Exponent(uint64_t(0)));
//            }
//        }
//        else {
//            rem = num % n;
//            num /= n;
//            for (int i = 0; i < n; ++i) {
//                if (i == rem)
//                    out.push_back(Exponent(uint64_t(1)));
//                else
//                    out.push_back(Exponent(uint64_t(0)));
//            }
//        }
//    }
//}
//
//std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m){
//    std::vector<uint64_t> result;
//    int rem, nalNumber = 0;
//    for(int k = 0; k <= m; ++k)
//    {
//        if(num == 0)
//            result.push_back(0);
//        else {
//            rem = num % n;
//            num /= n;
//            result.push_back(rem);
//        }
//    }
//    return result;
//}
//
//template<class Exponent, class GroupElement>
//void get_x(const GroupElement& A, const GroupElement& C, const GroupElement D, Exponent& result_out) {
//    secp256k1_sha256_t hash;
//    secp256k1_sha256_initialize(&hash);
//    unsigned char data[6 * sizeof(secp256k1_fe)];
//    unsigned char *A_serial = A.serialize();
//    unsigned char *C_serial = C.serialize();
//    unsigned char *D_serial = D.serialize();
//    memcpy(&data[0], &A_serial[0], 2 * sizeof(secp256k1_fe));
//    memcpy(&data[0] + 2 * sizeof(secp256k1_fe), &C_serial[0], 2 * sizeof(secp256k1_fe));
//    memcpy(&data[0] + 4 * sizeof(secp256k1_fe), &D_serial[0], 2 * sizeof(secp256k1_fe));
//    secp256k1_sha256_write(&hash, &data[0], 6 * sizeof(secp256k1_fe));
//    unsigned char result_data[32];
//    secp256k1_sha256_finalize(&hash, result_data);
//    delete [] A_serial;
//    delete [] C_serial;
//    delete [] D_serial;
//    result_out = result_data;
//}
//
//template<class Exponent, class GroupElement>
//GroupElement commit(const GroupElement& g, const Exponent m, const GroupElement h, const Exponent r){
//    return g * m + h * r;
//}
//
//template<class Exponent>
//void newFactor(Exponent x, Exponent a, std::vector<Exponent>& coefficients) {
//    Exponent t((uint64_t)0);
//    for (int i = 0; i < coefficients.size(); i++) {
//        Exponent c(coefficients[i]);
//        coefficients[i] = t + c * a;
//        t = c * x;
//    }
//    coefficients.push_back(t);
//}
//
//}// namespace sigma
//#endif //ZCOIN_UTILS_H
