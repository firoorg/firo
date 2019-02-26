namespace nextgen{
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
        RangeProof<Exponent, GroupElement>& proof_out){
    uint64_t m = v.size();
    std::vector<std::vector<bool>> bits;
    bits.resize(m);
    for(int i = 0; i < v.size(); i++)
        v[i].get_bits(bits[i]);

    std::vector<Exponent> aL, aR;
    aL.reserve(n * m);
    aR.reserve(n * m);
    for(int j = 0; j < m; ++j) {
        for (int i = 1; i <= n; ++i) {
            aL.push_back(uint64_t(bits[j][bits[j].size() - i]));
            aR.push_back(Exponent(uint64_t(bits[j][bits[j].size() - i])) - Exponent(uint64_t(1)));
        }
    }

    Exponent alpha;
    alpha.randomize();
    NextGenPrimitives<Exponent, GroupElement>::commit(h1, alpha, g_, aL, h_, aR, proof_out.A);

    std::vector<Exponent> sL, sR;
    sL.resize(n * m);
    sR.resize(n * m);
    for(int i = 0; i < n * m; ++i) {
        sL[i].randomize();
        sR[i].randomize();
    }

    Exponent ro;
    ro.randomize();
    NextGenPrimitives<Exponent, GroupElement>::commit(h1, ro, g_, sL, h_, sR, proof_out.S);

    Exponent y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.A, proof_out.S, y);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.S, proof_out.A, z);

    //compute l(x) and r(x) polynomials
    std::vector<std::vector<Exponent>> l_x, r_x;
    l_x.resize(n * m);
    r_x.resize(n * m);
    Exponent y_nm(uint64_t(1));

    Exponent z_j = z.square();
    Exponent z_sum1(uint64_t(0));
    Exponent z_sum2(uint64_t(0));
    for(int j = 0; j < m; ++j) {
        Exponent two_n(uint64_t(1));
        for(int i = 0; i < n; ++i) {
            int index = j * n + i;
            l_x[index].push_back(aL[index] - z);
            l_x[index].push_back(sL[index]);

            r_x[index].push_back(y_nm * (aR[index] + z) + z_j * two_n);
            r_x[index].push_back(y_nm * sR[index]);
            //
            y_nm *= y;
            two_n *= Exponent(uint64_t(2));
        }
        z_sum1 += z_j * randomness[j];
        z_sum2 += z_j * serialNumbers[j];
        z_j *= z;
    }
    //compute t1 and t2 coefficients
    Exponent t0, t1, t2;
    for(int i = 0; i < n * m; ++i){
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
    proof_out.T1 = NextGenPrimitives<Exponent, GroupElement>::double_commit(g, t1, h1, T_11, h2, T_21);
    proof_out.T2 = NextGenPrimitives<Exponent, GroupElement>::double_commit(g, t2, h1, T_12, h2, T_22);

    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.T1, proof_out.T2, x);
    //computing l and r
    std::vector<Exponent> l;
    std::vector<Exponent> r;
    l.reserve(n * m);
    r.reserve(n * m);
    for(int i = 0; i < n * m; i++){
        l.push_back(l_x[i][0] + l_x[i][1] * x);
        r.push_back(r_x[i][0] + r_x[i][1] * x);
    }

    proof_out.T_x1 = T_12 * x.square() + T_11 * x + z_sum1;
    proof_out.T_x2 = T_22 * x.square() + T_21 * x + z_sum2;
    proof_out.u = alpha + ro * x;

    //compute h'
    std::vector<GroupElement> h_prime;
    h_prime.reserve(h_.size());
    Exponent y_i(uint64_t(1));
    for(int i = 0; i < h_.size(); ++i) {
        h_prime.push_back(h_.get_g(i) * y_i.inverse());
        y_i *= y;
    }
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_prime_(h_prime);
    InnerProductProoveGenerator<Exponent, GroupElement> innerProductProoveGenerator(g_, h_prime_, g);
    //   t^ is calculated inside inner product proof generation with name c
    Exponent x_u;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.A, x_u);
    innerProductProoveGenerator.generate_proof(l, r, x_u, proof_out.innerProductProof);

}

}//namespace nextgen