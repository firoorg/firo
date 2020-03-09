#ifndef ZCOIN_LIBLELANTUS_LELANTUSPRIMITIVES_H
#define ZCOIN_LIBLELANTUS_LELANTUSPRIMITIVES_H
#include <vector>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <secp256k1/include/MultiExponent.h>
#include "sigmaplus_proof.h"
#include "lelantus_proof.h"
#include "schnorr_proof.h"
#include "innerproduct_proof.h"
#include "range_proof.h"
#include <algorithm>

namespace lelantus {

template<class Exponent, class GroupElement>
class LelantusPrimitives {

public:
////common functions
    static void generate_challenge(
            const std::vector<GroupElement>& group_elements,
            Exponent& result_out);

    static GroupElement commit(
            const GroupElement& g,
            const Exponent& m,
            const GroupElement& h,
            const Exponent& r);

    static GroupElement double_commit(
            const GroupElement& g,
            const Exponent& m,
            const GroupElement& hV,
            const Exponent& v,
            const GroupElement& hR,
            const Exponent& r);
////functions for sigma
    static void commit(
            const GroupElement& g,
            const std::vector<GroupElement>& h,
            const std::vector<Exponent>& exp,
            const Exponent& r,
            GroupElement& result_out);

    static void convert_to_sigma(uint64_t num, uint64_t n, uint64_t m, std::vector<Exponent>& out);

    static std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m);

    static void generate_Lelantus_challange(const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs, Exponent& result_out);

    static void new_factor(const Exponent& x, const Exponent& a, std::vector<Exponent>& coefficients);
//// functions for bulletproofs
    static void commit(
            const GroupElement& h,
            const Exponent& h_exp,
            const std::vector<GroupElement>& g_,
            const std::vector<Exponent>& L,
            const std::vector<GroupElement>& h_,
            const std::vector<Exponent>& R,
            GroupElement& result_out);

    // computes dot product of two Scalar vectors
    static Exponent scalar_dot_product(
            typename std::vector<Exponent>::const_iterator a_start,
            typename std::vector<Exponent>::const_iterator a_end,
            typename std::vector<Exponent>::const_iterator b_start,
            typename std::vector<Exponent>::const_iterator b_end);

    static void g_prime(
            const std::vector<GroupElement>& g_,
            const Exponent& x,
            std::vector<GroupElement>& result);

    static void h_prime(
            const std::vector<GroupElement>& h_,
            const Exponent& x,
            std::vector<GroupElement>& result);

    static GroupElement p_prime(
            const GroupElement& P_,
            const GroupElement& L,
            const GroupElement& R,
            const Exponent& x);

    static Exponent delta(const Exponent& y, const Exponent& z, uint64_t n, uint64_t m);

};

}// namespace lelantus

#include "lelantus_primitives.hpp"

#endif //ZCOIN_LIBLELANTUS_LELANTUSPRIMITIVES_H
