#include <boost/test/unit_test.hpp>

#include "test/test_bitcoin.h"

#include <libzerocoin/sigma/R1Proof.h>
#include <libzerocoin/sigma/R1ProofGenerator.h>
#include <libzerocoin/sigma/SigmaPrimitives.h>

using  namespace secp_primitives;
using  namespace sigma;

namespace {

struct sigma_unit_tests_fixture {
    // struct sigma_unit_tests_fixture : public TestingSetup {
    // sigma_unit_tests_fixture() = default;
    int N;
    int n;
    int m;
    int index;
    GroupElement g;
    std::unique_ptr<zcoin_common::GeneratorVector <Scalar, GroupElement>> h_;
    Scalar rB;
    std::vector <Scalar> sigma;
    std::unique_ptr<R1ProofGenerator<Scalar, GroupElement>> r1prover;
    R1Proof<Scalar, GroupElement> r1proof;
    Scalar x;
    std::vector <std::vector<Scalar>> P_i_k;
    std::vector<Scalar> f_;
    std::vector<Scalar> a;
    std::vector <Scalar> Pk;
    secp_primitives::Scalar r;
    std::vector<secp_primitives::GroupElement> commits;

    sigma_unit_tests_fixture() {
        // sigma_unit_tests_fixture() : TestingSetup(CBaseChainParams::REGTEST) {
        N = 16;
        n = 4;
        index = 13;
        m = (int)(log(N) / log(n));
        g.randomize();
        std::vector<GroupElement> h_gens;
        for(int i = 0; i < n * m; ++i ){
            h_gens.push_back(secp_primitives::GroupElement());
            h_gens[i].randomize();
        }

        h_.reset(new zcoin_common::GeneratorVector <Scalar, GroupElement>(h_gens));
        rB.randomize();
        SigmaPrimitives<Scalar,GroupElement>::convert_to_sigma(index, n, m, sigma);
        r1prover.reset(new R1ProofGenerator<Scalar, GroupElement>(g, *h_, sigma, rB, n, m));

        Pk.resize(m);
        for (int k = 0; k < m; ++k) {
            Pk[k].randomize();
        }
        r.randomize();
        for(int i = 0; i < N; ++i){
            if(i == (index)){
                secp_primitives::GroupElement c;
                secp_primitives::Scalar zero(uint64_t(0));
                c = sigma::SigmaPrimitives<Scalar,GroupElement>::commit(g, zero, h_gens[0], r);
                commits.push_back(c);
            }
            else{
                commits.push_back(secp_primitives::GroupElement());
                commits[i].randomize();
            }
        }
        (*r1prover).proof(a, r1proof);
        x = (*r1prover).x_;
        P_i_k.resize(N);
        for (int i = 0; i < N; ++i) {
            std::vector <Scalar>& coefficients = P_i_k[i];
            std::vector<uint64_t> I = SigmaPrimitives<Scalar,GroupElement>::convert_to_nal(i, n, m);
            coefficients.push_back(sigma[I[0]]);
            coefficients.push_back(a[I[0]]);
            for (int j = 1; j < m; ++j) {
                SigmaPrimitives<Scalar,GroupElement>::new_factor(sigma[j * n + I[j]], a[j * n + I[j]], coefficients);
            }
            std::reverse(coefficients.begin(), coefficients.end());
        }
        f_ = r1proof.f_;
        std::vector<Scalar> f;
        for(int j = 0; j < m; ++j){
            f.push_back(sigma[j * n] * x + a[j * n]);
            int k = n - 1;
            for(int i = 0; i < k; ++i){
                f.push_back(r1proof.f_[j * k + i]);
            }
        }
        f_= f;
    }

    ~sigma_unit_tests_fixture(){}
};

BOOST_FIXTURE_TEST_SUITE(sigma_unit_tests,sigma_unit_tests_fixture)

BOOST_AUTO_TEST_CASE(unit_f_and_p_x)
{
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = SigmaPrimitives<Scalar,GroupElement>::convert_to_nal(i, n, m);
        Scalar f_i(uint64_t(1));
        Scalar p_i_x(uint64_t(0));
        for(int j = 0; j < m; ++j){
            f_i *= f_[j*n + I[j]];
            p_i_x += (P_i_k[i][j]*x.exponent(j));
        }
        if(i==index)
            p_i_x += (P_i_k[i][m]*x.exponent(m));
        BOOST_CHECK(f_i==p_i_x);
    }
}

BOOST_AUTO_TEST_CASE(unit_commits)
{
    Scalar z;
    z = r * x.exponent(uint64_t(m));
    Scalar sum;
    Scalar x_k(uint64_t(1));
    for (int k = 0; k < m; ++k) {
        sum += (Pk[k] * x_k);
        x_k *= x;
    }
    z -= sum;
    GroupElement coommit = SigmaPrimitives<Scalar,GroupElement>::commit(g, Scalar(uint64_t(0)), (*h_).get_g(0), z);
    GroupElement commits_;
    for(int k = 0; k< m; ++k){
        commits_ += (SigmaPrimitives<Scalar,GroupElement>::commit(
                g, Scalar(uint64_t(0)), (*h_).get_g(0), Pk[k])) * (x.exponent(k)).negate();
    }
    commits_ += (commits[index] * x.exponent(m));

    BOOST_CHECK(coommit == commits_);
}

BOOST_AUTO_TEST_CASE(unit_G_k_prime)
{
    std::vector<Scalar> f_i_;
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = SigmaPrimitives<Scalar,GroupElement>::convert_to_nal(i, n, m);
        Scalar f_i(uint64_t(1));
        for(int j = 0; j < m; ++j){
            f_i *= f_[j*n + I[j]];
        }
        f_i_.push_back(f_i);
    }
    zcoin_common::GeneratorVector<Scalar, GroupElement> cc_(commits);
    GroupElement C;
    cc_.get_vector_multiple(f_i_, C);
    GroupElement G;
    for(int k = 0; k < m; ++k){
        GroupElement Gk_prime;
        for(int i = 0; i < N; ++i)
            Gk_prime += commits[i] * P_i_k[i][k];
            G += (Gk_prime)* ((x.exponent(k)).negate());
    }
    BOOST_CHECK((C + G) == (commits[index] * (x.exponent(m))));
}


BOOST_AUTO_TEST_SUITE_END()
}
