namespace lelantus {

template<class Exponent, class GroupElement>
RangeVerifier<Exponent, GroupElement>::RangeVerifier(
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
bool RangeVerifier<Exponent, GroupElement>::verify_batch(const std::vector<GroupElement>& V, const RangeProof<Exponent, GroupElement>& proof) {
    if(!membership_checks(proof))
        return false;
    uint64_t m = V.size();
    //computing challenges
    Exponent x, x_u, y, z;

    std::vector<GroupElement> group_elements = {proof.A,proof.S};
    std::vector<GroupElement> group_elements2 = {proof.S,proof.A};
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, y);
    Exponent y_inv =  y.inverse();

    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements2, z);

    group_elements.emplace_back(proof.T1);
    group_elements.emplace_back(proof.T2);
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
    Exponent x_neg = x.negate();

    group_elements2.emplace_back(proof.T1);
    group_elements2.emplace_back(proof.T2);
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements2, x_u);

    uint64_t log_n = (int)(log(n * m) / log(2));
    const InnerProductProof<Exponent, GroupElement>& innerProductProof = proof.innerProductProof;
    std::vector<Exponent> x_j, x_j_inv;
    x_j.resize(log_n);
    x_j_inv.reserve(log_n);
    for (int i = 0; i < log_n; ++i)
    {
        std::vector<GroupElement> group_elements_i = {innerProductProof.L_[i], innerProductProof.R_[i]};
        LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements_i, x_j[i]);
        x_j_inv.push_back((x_j[i].inverse()));
    }

    Exponent z_square_neg = (z.square()).negate();
    Exponent delta = LelantusPrimitives<Exponent, GroupElement>::delta(y, z, n, m);
    //check line 97
    GroupElement V_z;
    Exponent z_m(uint64_t(1));
    for (int j = 0; j < m; ++j)
    {
        V_z += V[j] * (z_square_neg * z_m);
        z_m *= z;
    }

    std::vector<Exponent> l, r;
    l.resize(n * m);
    r.resize(n * m);
    Exponent y_n_(uint64_t(1));
    Exponent two(uint64_t(2));
    Exponent z_j = z.square();
    for (uint64_t j = 0; j < m ; ++j)
    {
        Exponent two_n_(uint64_t(1));
        for (uint64_t k = 0; k < n; ++k)
        {
            uint64_t i = j * n + k;
            Exponent x_il(uint64_t(1));
            Exponent x_ir(uint64_t(1));
            for (int j = 0; j < log_n; ++j)
            {
                if ((i >> j) & 1) {
                    x_il *= x_j[log_n - j - 1];
                    x_ir *= x_j_inv[log_n - j - 1];
                } else {
                    x_il *= x_j_inv[log_n - j - 1];
                    x_ir *= x_j[log_n - j - 1];
                }

            }
            l[i] = x_il * innerProductProof.a_ + z;
            r[i] = y_n_ * (x_ir * innerProductProof.b_ - (z_j * two_n_)) - z;
            y_n_ *= y_inv;
            two_n_ *= two;
        }
        z_j *= z;
    }
    //check line 105
    GroupElement left_;
    Exponent c;
    c.randomize();
    left_ += LelantusPrimitives<Exponent, GroupElement>::double_commit(g, (innerProductProof.c_ - delta) * c, h1, proof.T_x1 * c, h2, proof.T_x2 * c);
    left_ += V_z * c + proof.T1 * x_neg * c + proof.T2 * ((x.square()).negate() * c);

    secp_primitives::MultiExponent g_mult(g_, l);
    secp_primitives::MultiExponent h_mult(h_, r);
    left_ += g_mult.get_multiple() + h_mult.get_multiple();;

    left_ += g * (x_u *  (innerProductProof.a_ * innerProductProof.b_ - innerProductProof.c_))
             + h1 * proof.u
             + proof.A.inverse()
             + proof.S * x_neg;

    std::vector<Exponent> x_j_sq_neg, x_j_sq_inv_neg;
    for (int j = 0; j < log_n; ++j)
    {
        x_j_sq_neg.push_back(x_j[j].square().negate());
        x_j_sq_inv_neg.push_back(x_j_inv[j].square().negate());
    }
    secp_primitives::MultiExponent L(innerProductProof.L_, x_j_sq_neg);
    secp_primitives::MultiExponent R(innerProductProof.R_, x_j_sq_inv_neg);
    left_ += L.get_multiple() + R.get_multiple();

    if(!left_.isInfinity())
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool RangeVerifier<Exponent, GroupElement>::membership_checks(const RangeProof<Exponent, GroupElement>& proof) {
    if(!(proof.A.isMember()
         && proof.S.isMember()
         && proof.T1.isMember()
         && proof.T1.isMember()
         && proof.T_x1.isMember()
         && proof.T_x2.isMember()
         && proof.u.isMember()
         && proof.innerProductProof.a_.isMember()
         && proof.innerProductProof.b_.isMember())
       && proof.innerProductProof.c_.isMember())
        return false;

    for (int i = 0; i < proof.innerProductProof.L_.size(); ++i)
    {
        if (!(proof.innerProductProof.L_[i].isMember() && proof.innerProductProof.R_[i].isMember()))
            return false;
    }
    return true;
}


}//namespace lelantus