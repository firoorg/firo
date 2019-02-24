namespace nextgen{
template<class Exponent, class GroupElement>
RangeProver<Exponent, GroupElement>::RangeProver(
        const GroupElement& g,
        const GroupElement& h,
        const std::vector<GroupElement>& g_vector,
        const std::vector<GroupElement>& h_vector,
        uint64_t n)
    : g (g)
    , h (h)
    , g_(g_vector)
    , h_(h_vector)
    , n (n)
{}

template<class Exponent, class GroupElement>
void RangeProver<Exponent, GroupElement>::proof(
        const Exponent& v,
        const Exponent& randomness,
        RangeProof<Exponent, GroupElement>& proof_out){
    std::vector<bool> bits;
    v.get_bits(bits);

    std::vector<Exponent> aL, aR;
    aL.reserve(n);
    aR.reserve(n);
    for(int i = 1; i <= n; ++i) {
        aL.push_back(uint64_t(bits[bits.size() - i]));
        aR.push_back(Exponent(uint64_t(bits[bits.size() - i])) - Exponent(uint64_t(1)));
    }

    Exponent alpha;
    alpha.randomize();
    NextGenPrimitives<Exponent, GroupElement>::commit(h, alpha, g_, aL, h_, aR, proof_out.A);

    std::vector<Exponent> sL, sR;
    sL.resize(n);
    sR.resize(n);
    for(int i = 0; i < n; ++i) {
        sL[i].randomize();
        sR[i].randomize();
    }

    Exponent ro;
    ro.randomize();
    NextGenPrimitives<Exponent, GroupElement>::commit(h, ro, g_, sL, h_, sR, proof_out.S);

    Exponent y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.A, proof_out.S, y);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.S, proof_out.A, z);

    //compute l(x) and r(x) polynomials
    std::vector<std::vector<Exponent>> l_x, r_x;
    l_x.resize(n);
    r_x.resize(n);
    Exponent y_n(uint64_t(1));
    Exponent two_n(uint64_t(1));
    Exponent z_square = z.square();
    for(int i = 0; i < n; ++i){
        l_x[i].push_back(aL[i] - z);
        l_x[i].push_back(sL[i]);
        r_x[i].push_back(y_n * (aR[i] + z) + z_square * two_n);
        r_x[i].push_back(y_n * sR[i]);
        //
        y_n *= y;
        two_n *= Exponent(uint64_t(2));
    }
    //compute t1 and t2 coefficients
    Exponent t0, t1, t2;
    for(int i = 0; i < n; ++i){
        t0 += l_x[i][0] * r_x[i][0];
        t1 += l_x[i][0] * r_x[i][1] + l_x[i][1] * r_x[i][0];
        t2 += l_x[i][1] * r_x[i][1];
    }
    //computing T1 T2;
    Exponent T_1, T_2;
    T_1.randomize();
    T_2.randomize();
    proof_out.T1 = NextGenPrimitives<Exponent, GroupElement>::commit(g, t1, h, T_1);
    proof_out.T2 = NextGenPrimitives<Exponent, GroupElement>::commit(g, t2, h, T_2);

    Exponent x;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.T1, proof_out.T2, x);
    //computing l and r
    std::vector<Exponent> l;
    std::vector<Exponent> r;
    l.reserve(n);
    r.reserve(n);
    for(int i = 0; i < n; i++){
        l.push_back(l_x[i][0] + l_x[i][1] * x);
        r.push_back(r_x[i][0] + r_x[i][1] * x);
    }

    proof_out.T_x = T_2 * x.square() + T_1 * x + z_square * randomness;
    proof_out.u = alpha + ro * x;
    /////for linear size proof
//    proof_out.l = l;
//    proof_out.r = r;
//    proof_out.t_ = NextGenPrimitives<Exponent, GroupElement>::scalar_dot_product(l.begin(), l.end(), r.begin(), r.end());

////// for inner product proof
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

template<class Exponent, class GroupElement>
void RangeProver<Exponent, GroupElement>::batch_proof(
        const std::vector<Exponent>& v,
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
    NextGenPrimitives<Exponent, GroupElement>::commit(h, alpha, g_, aL, h_, aR, proof_out.A);

    std::vector<Exponent> sL, sR;
    sL.resize(n * m);
    sR.resize(n * m);
    for(int i = 0; i < n * m; ++i) {
        sL[i].randomize();
        sR[i].randomize();
    }

    Exponent ro;
    ro.randomize();
    NextGenPrimitives<Exponent, GroupElement>::commit(h, ro, g_, sL, h_, sR, proof_out.S);

    Exponent y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.A, proof_out.S, y);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof_out.S, proof_out.A, z);

    //compute l(x) and r(x) polynomials
    std::vector<std::vector<Exponent>> l_x, r_x;
    l_x.resize(n * m);
    r_x.resize(n * m);
    Exponent y_nm(uint64_t(1));

    Exponent z_j = z.square();
    Exponent z_j_sum = z_j;
    Exponent z_sum(uint64_t(0));
    for(int j = 0; j < m; ++j) {
        Exponent two_n(uint64_t(1));
        for(int i = 0; i < n; ++i) {
            int index = j * n + i;
            l_x[index].push_back(aL[index] - z);
            l_x[index].push_back(sL[index]);

            r_x[index].push_back(y_nm * (aR[index] + z) + z_j_sum * two_n);
            r_x[index].push_back(y_nm * sR[index]);
            //
            y_nm *= y;
            two_n *= Exponent(uint64_t(2));
        }
        z_sum += z_j * randomness[j];
        z_j *= z;
        z_j_sum += z_j;
    }
    //compute t1 and t2 coefficients
    Exponent t0, t1, t2;
    for(int i = 0; i < n * m; ++i){
        t0 += l_x[i][0] * r_x[i][0];
        t1 += l_x[i][0] * r_x[i][1] + l_x[i][1] * r_x[i][0];
        t2 += l_x[i][1] * r_x[i][1];
    }
    //computing T1 T2;
    Exponent T_1, T_2;
    T_1.randomize();
    T_2.randomize();
    proof_out.T1 = NextGenPrimitives<Exponent, GroupElement>::commit(g, t1, h, T_1);
    proof_out.T2 = NextGenPrimitives<Exponent, GroupElement>::commit(g, t2, h, T_2);

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

    proof_out.T_x = T_2 * x.square() + T_1 * x + z_sum;
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