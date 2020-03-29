namespace lelantus {

template<class Exponent, class GroupElement>
RangeProver<Exponent, GroupElement>::RangeProver(
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

template<class Exponent, class GroupElement>
void RangeProver<Exponent, GroupElement>::batch_proof(
        const std::vector<Exponent>& v,
        const std::vector<Exponent>& serialNumbers,
        const std::vector<Exponent>& randomness,
        RangeProof<Exponent, GroupElement>& proof_out) {
    std::size_t m = v.size();
    std::vector<std::vector<bool>> bits;
    bits.resize(m);
    for (std::size_t i = 0; i < v.size(); i++)
        v[i].get_bits(bits[i]);

    std::vector<Exponent> aL, aR;
    aL.reserve(n * m);
    aR.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 1; i <= n; ++i)
        {
            aL.emplace_back(uint64_t(bits[j][bits[j].size() - i]));
            aR.emplace_back(Exponent(uint64_t(bits[j][bits[j].size() - i])) - Exponent(uint64_t(1)));
        }
    }

    Exponent alpha;
    alpha.randomize();
    LelantusPrimitives<Exponent, GroupElement>::commit(h1, alpha, g_, aL, h_, aR, proof_out.A);

    std::vector<Exponent> sL, sR;
    sL.resize(n * m);
    sR.resize(n * m);
    for (std::size_t i = 0; i < n * m; ++i)
    {
        sL[i].randomize();
        sR[i].randomize();
    }

    Exponent ro;
    ro.randomize();
    LelantusPrimitives<Exponent, GroupElement>::commit(h1, ro, g_, sL, h_, sR, proof_out.S);

    Exponent y, z;
    std::vector<GroupElement> group_elements = {proof_out.A,proof_out.S};
    std::vector<GroupElement> group_elements2 = {proof_out.S,proof_out.A};
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, y);
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements2, z);

    //compute l(x) and r(x) polynomials
    std::vector<std::vector<Exponent>> l_x, r_x;
    l_x.resize(n * m);
    r_x.resize(n * m);
    Exponent y_nm(uint64_t(1));

    Exponent z_j = z.square();
    Exponent z_sum1(uint64_t(0));
    Exponent z_sum2(uint64_t(0));
    Exponent two(uint64_t(2));
    for (std::size_t j = 0; j < m; ++j)
    {
        Exponent two_n(uint64_t(1));
        for (std::size_t i = 0; i < n; ++i)
        {
            int index = j * n + i;
            l_x[index].emplace_back(aL[index] - z);
            l_x[index].emplace_back(sL[index]);

            r_x[index].emplace_back(y_nm * (aR[index] + z) + z_j * two_n);
            r_x[index].emplace_back(y_nm * sR[index]);
            //
            y_nm *= y;
            two_n *= two;
        }
        z_sum1 += z_j * randomness[j];
        z_sum2 += z_j * serialNumbers[j];
        z_j *= z;
    }

    //compute t1 and t2 coefficients
    Exponent t0, t1, t2;
    for (std::size_t i = 0; i < n * m; ++i)
    {
        t0 += l_x[i][0] * r_x[i][0];
        t1 += l_x[i][0] * r_x[i][1] + l_x[i][1] * r_x[i][0];
        t2 += l_x[i][1] * r_x[i][1];
    }

    //computing T11 T12 T21 T22;
    Exponent T_11, T_12, T_21, T_22;
    T_11.randomize();
    T_12.randomize();
    T_21.randomize();
    T_22.randomize();
    proof_out.T1 = LelantusPrimitives<Exponent, GroupElement>::double_commit(g, t1, h1, T_11, h2, T_21);
    proof_out.T2 = LelantusPrimitives<Exponent, GroupElement>::double_commit(g, t2, h1, T_12, h2, T_22);

    Exponent x;
    group_elements.emplace_back(proof_out.T1);
    group_elements.emplace_back(proof_out.T2);
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);

    //computing l and r
    std::vector<Exponent> l;
    std::vector<Exponent> r;
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
    Exponent y_i_inv(uint64_t(1));
    Exponent y_inv = y.inverse();
    for (std::size_t i = 0; i < h_.size(); ++i)
    {
        h_prime.emplace_back(h_[i] * y_i_inv);
        y_i_inv *= y_inv;
    }

    InnerProductProofGenerator<Exponent, GroupElement> InnerProductProofGenerator(g_, h_prime, g);
    //t^ is calculated inside inner product proof generation with name c
    Exponent x_u;
    group_elements2.emplace_back(proof_out.T1);
    group_elements2.emplace_back(proof_out.T2);
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements2, x_u);

    InnerProductProofGenerator.generate_proof(l, r, x_u, proof_out.innerProductProof);

}

}//namespace lelantus