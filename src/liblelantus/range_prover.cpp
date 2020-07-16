#include "range_prover.h"

namespace lelantus {
    
RangeProver::RangeProver(
        const GroupElement& g,
        const GroupElement& h1,
        const GroupElement& h2,
        const std::vector<GroupElement>& g_vector,
        const std::vector<GroupElement>& h_vector,
        uint64_t n)
        : g (g)
        , h1 (h1)
        , h2 (h2)
        , g_(g_vector)
        , h_(h_vector)
        , n (n)
{}

void RangeProver::batch_proof(
        const std::vector<Scalar>& v,
        const std::vector<Scalar>& serialNumbers,
        const std::vector<Scalar>& randomness,
        RangeProof& proof_out) {
    std::size_t m = v.size();
    std::vector<std::vector<bool>> bits;
    bits.resize(m);
    for (std::size_t i = 0; i < v.size(); i++)
        v[i].get_bits(bits[i]);

    std::vector<Scalar> aL, aR;
    aL.reserve(n * m);
    aR.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 1; i <= n; ++i)
        {
            aL.emplace_back(uint64_t(bits[j][bits[j].size() - i]));
            aR.emplace_back(Scalar(uint64_t(bits[j][bits[j].size() - i])) - Scalar(uint64_t(1)));
        }
    }

    Scalar alpha;
    alpha.randomize();
    LelantusPrimitives::commit(h1, alpha, g_, aL, h_, aR, proof_out.A);

    std::vector<Scalar> sL, sR;
    sL.resize(n * m);
    sR.resize(n * m);
    for (std::size_t i = 0; i < n * m; ++i)
    {
        sL[i].randomize();
        sR[i].randomize();
    }

    Scalar ro;
    ro.randomize();
    LelantusPrimitives::commit(h1, ro, g_, sL, h_, sR, proof_out.S);

    Scalar y, z;
    std::vector<GroupElement> group_elements = {proof_out.A,proof_out.S};
    std::vector<GroupElement> group_elements2 = {proof_out.S,proof_out.A};
    LelantusPrimitives::generate_challenge(group_elements, y);
    LelantusPrimitives::generate_challenge(group_elements2, z);

    //compute l(x) and r(x) polynomials
    std::vector<std::vector<Scalar>> l_x, r_x;
    l_x.resize(n * m);
    r_x.resize(n * m);
    NthPower y_nm(y);
    NthPower z_j(z, z.square());
    Scalar z_sum1(uint64_t(0));
    Scalar z_sum2(uint64_t(0));

    NthPower two_n_(uint64_t(2));
    std::vector<Scalar> two_n;
    two_n.reserve(n);
    for (uint64_t k = 0; k < n; ++k)
    {
        two_n.emplace_back(two_n_.pow);
        two_n_.go_next();
    }

    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            int index = j * n + i;
            l_x[index].emplace_back(aL[index] - z);
            l_x[index].emplace_back(sL[index]);

            r_x[index].emplace_back(y_nm.pow * (aR[index] + z) + z_j.pow * two_n[i]);
            r_x[index].emplace_back(y_nm.pow * sR[index]);
            //
            y_nm.go_next();
        }
        z_sum1 += z_j.pow * randomness[j];
        z_sum2 += z_j.pow * serialNumbers[j];
        z_j.go_next();
    }

    //compute t1 and t2 coefficients
    Scalar t0, t1, t2;
    for (std::size_t i = 0; i < n * m; ++i)
    {
        t0 += l_x[i][0] * r_x[i][0];
        t1 += l_x[i][0] * r_x[i][1] + l_x[i][1] * r_x[i][0];
        t2 += l_x[i][1] * r_x[i][1];
    }

    //computing T11 T12 T21 T22;
    Scalar T_11, T_12, T_21, T_22;
    T_11.randomize();
    T_12.randomize();
    T_21.randomize();
    T_22.randomize();
    proof_out.T1 = LelantusPrimitives::double_commit(g, t1, h1, T_11, h2, T_21);
    proof_out.T2 = LelantusPrimitives::double_commit(g, t2, h1, T_12, h2, T_22);

    Scalar x;
    group_elements.emplace_back(proof_out.T1);
    group_elements.emplace_back(proof_out.T2);
    LelantusPrimitives::generate_challenge(group_elements, x);

    //computing l and r
    std::vector<Scalar> l;
    std::vector<Scalar> r;
    l.reserve(n * m);
    r.reserve(n * m);
    for (std::size_t i = 0; i < n * m; i++)
    {
        l.emplace_back(l_x[i][0] + l_x[i][1] * x);
        r.emplace_back(r_x[i][0] + r_x[i][1] * x);
    }

    proof_out.T_x1 = T_12 * x.square() + T_11 * x + z_sum1;
    proof_out.T_x2 = T_22 * x.square() + T_21 * x + z_sum2;
    proof_out.u = alpha + ro * x;

    //compute h'
    std::vector<GroupElement> h_prime;
    h_prime.reserve(h_.size());
    NthPower y_i_inv(y.inverse());
    for (std::size_t i = 0; i < h_.size(); ++i)
    {
        h_prime.emplace_back(h_[i] * y_i_inv.pow);
        y_i_inv.go_next();
    }

    InnerProductProofGenerator InnerProductProofGenerator(g_, h_prime, g);
    //t^ is calculated inside inner product proof generation with name c
    Scalar x_u;
    group_elements2.emplace_back(proof_out.T1);
    group_elements2.emplace_back(proof_out.T2);
    LelantusPrimitives::generate_challenge(group_elements2, x_u);

    InnerProductProofGenerator.generate_proof(l, r, x_u, proof_out.innerProductProof);

}

}//namespace lelantus