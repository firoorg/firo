namespace nextgen {

template<class Exponent, class GroupElement>
RangeVerifier<Exponent, GroupElement>::RangeVerifier(
        const GroupElement& g,
        const GroupElement& h,
        const std::vector<GroupElement>& g_vector,
        const std::vector<GroupElement>& h_vector,
        uint64_t n)
        : g (g)
        , h (h)
        , g_(g_vector, 16)
        , h_(h_vector, 16)
        , n (n)
{}

template<class Exponent, class GroupElement>
bool RangeVerifier<Exponent, GroupElement>::verify(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof){
    Exponent x, y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, proof.S, y);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.S, proof.A, z);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.T1, proof.T2, x);
    //compute h'
    std::vector<GroupElement> h_prime;
    h_prime.reserve(h_.size());
    Exponent y_i(uint64_t(1));
    for(int i = 0; i < h_.size(); ++i) {
        h_prime.push_back(h_.get_g(i) * y_i.inverse());
        y_i *= y;
    }
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_prime_(h_prime);
    //check line 65
    //t^ is the same as c form inner product proof
    GroupElement left = NextGenPrimitives<Exponent, GroupElement>::commit(g, proof.innerProductProof.c_, h, proof.T_x);
    GroupElement right = V * z.square()
                         + g *  NextGenPrimitives<Exponent, GroupElement>::delta(y, z, n)
                         + proof.T1 * x
                         + proof.T2 * x.square();
    if(left != right)
        return false;
    //check line 67
    std::vector<Exponent> z_neg;
    z_neg.reserve(n);
    Exponent _z = z.negate();
    for(int i = 0; i < n; ++i)
        z_neg.push_back(_z);

    std::vector<Exponent> h_exp;
    h_exp.reserve(n);
    y_i = (uint64_t(1));
    Exponent two_n(uint64_t(1));
    Exponent z_square = z.square();
    for(int i = 0; i < n; ++i) {
        h_exp.push_back(z * y_i + z_square * two_n);
        y_i *= y;
        two_n *= uint64_t(2);
    }
    GroupElement P;
    NextGenPrimitives<Exponent, GroupElement>::commit(proof.S, x, g_, z_neg, h_prime_, h_exp, P);
    P += proof.A;
////  this is for linear size proof
//    GroupElement right_;
//    NextGenPrimitives<Exponent, GroupElement>::commit(h, proof.u, g_, proof.l, h_prime_, proof.r, right_);
//    if(P != right_)
//        return false;
    //  check line 68
//    if(proof.t_ != NextGenPrimitives<Exponent, GroupElement>::scalar_dot_product(proof.l.begin(), proof.l.end(), proof.r.begin(), proof.r.end()))
//        return false;
//// for inner product
    P += (h * (proof.u).negate());
    InnerProductProofVerifier<Exponent, GroupElement> innerProductProofVerifier(g_, h_prime_, g, P );
    Exponent x_u;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, x_u);
    if(!innerProductProofVerifier.verify(x_u, proof.innerProductProof))
        return false;
    return true;
}


template<class Exponent, class GroupElement>
bool RangeVerifier<Exponent, GroupElement>::verify_fast(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof){
    Exponent x, y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, proof.S, y);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.S, proof.A, z);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.T1, proof.T2, x);
    //compute h'
    std::vector<GroupElement> h_prime;
    h_prime.reserve(h_.size());
    Exponent y_i(uint64_t(1));
    for(int i = 0; i < h_.size(); ++i) {
        h_prime.push_back(h_.get_g(i) * y_i.inverse());
        y_i *= y;
    }
    zcoin_common::GeneratorVector<Exponent, GroupElement> h_prime_(h_prime);
    //check line 65
    //t^ is the same as c form inner product proof
    GroupElement left = NextGenPrimitives<Exponent, GroupElement>::commit(g, proof.innerProductProof.c_, h, proof.T_x);
    GroupElement right = V * z.square()
                         + g *  NextGenPrimitives<Exponent, GroupElement>::delta(y, z, n)
                         + proof.T1 * x
                         + proof.T2 * x.square();
    if(left != right)
        return false;
    //check line 67
    std::vector<Exponent> z_neg;
    z_neg.reserve(n);
    Exponent _z = z.negate();
    for(int i = 0; i < n; ++i)
        z_neg.push_back(_z);

    std::vector<Exponent> h_exp;
    h_exp.reserve(n);
    y_i = (uint64_t(1));
    Exponent two_n(uint64_t(1));
    Exponent z_square = z.square();
    for(int i = 0; i < n; ++i) {
        h_exp.push_back(z * y_i + z_square * two_n);
        y_i *= y;
        two_n *= uint64_t(2);
    }
    GroupElement P;
    NextGenPrimitives<Exponent, GroupElement>::commit(proof.S, x, g_, z_neg, h_prime_, h_exp, P);
    P += proof.A;
    P += (h * (proof.u).negate());
    InnerProductProofVerifier<Exponent, GroupElement> innerProductProofVerifier(g_, h_prime_, g, P );
    Exponent x_u;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, x_u);
    if(!innerProductProofVerifier.verify_fast(n, x_u, proof.innerProductProof))
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool RangeVerifier<Exponent, GroupElement>::verify_optimised(const GroupElement& V, const RangeProof<Exponent, GroupElement>& proof){
    //computing challenges
    Exponent x, x_u, y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, proof.S, y);
    Exponent y_inv =  y.inverse();
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.S, proof.A, z);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.T1, proof.T2, x);
    Exponent x_neg = x.negate();
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, x_u);
    uint64_t log_n = (int)(log(n) / log(2));
    const InnerProductProof<Exponent, GroupElement>& innerProductProof = proof.innerProductProof;
    std::vector<Exponent> x_j, x_j_inv;
    x_j.resize(log_n);
    x_j_inv.reserve(log_n);
    for(int i = 0; i < log_n; ++i) {
        NextGenPrimitives<Exponent, GroupElement>::get_x(innerProductProof.L_[i], innerProductProof.R_[i], x_j[i]);
        x_j_inv.push_back((x_j[i].inverse()));
    }

    Exponent z_square_neg = (z.square()).negate();
    Exponent delta = NextGenPrimitives<Exponent, GroupElement>::delta(y, z, n);
    //check line 97
    GroupElement left = NextGenPrimitives<Exponent, GroupElement>::commit(g, (innerProductProof.c_ - delta), h, proof.T_x);
    left += V * (z_square_neg);
    left += proof.T1 * x_neg;
    left += proof.T2 * ((x.square()).negate());
    if(!left.isOne())
        return false;

    std::vector<Exponent> l, r;
    l.resize(n);
    r.resize(n);
    Exponent y_n_(uint64_t(1));
    Exponent two_n_(uint64_t(1));
    Exponent two(uint64_t(2));
    for(uint64_t i = 0; i < n; ++i){
        Exponent x_il(uint64_t(1));
        Exponent x_ir(uint64_t(1));
        for(int j = 0; j < log_n; ++j) {
            if((i >> j) & 1) {
                x_il *= x_j[log_n - j - 1];
                x_ir *= x_j_inv[log_n - j - 1];
            } else{
                x_il *= x_j_inv[log_n - j - 1];
                x_ir *= x_j[log_n - j - 1];
            }

        }
        l[i] = x_il * innerProductProof.a_ + z;
        r[i] = y_n_ * (x_ir * innerProductProof.b_ + (z_square_neg * two_n_)) - z;
        y_n_ *= y_inv;
        two_n_ *= two;
    }
//
//    Exponent y_n_ = y;
//    Exponent two_n_(uint64_t(2));
//    std::vector<Exponent> x_i;
//    x_i.resize(n);
//    x_i[0] = Exponent(uint64_t(1));
//    for(int j = 0; j < log_n; ++j)
//        x_i[0] *= x_j_inv[j];
//
//    l[0] = x_i[0] * innerProductProof.a_ + z;
//    r[0] = x_i[0].inverse() * innerProductProof.b_ + z_square_neg - z;
//
//    int pow_2 = 0;
//    int k = -1;
//
//    for(int i = 1; i < n; ++i) {
//
//        if (!(i & (i - 1))) {
//            pow_2 = i;
//            k += 1;
//        }
//        x_i[i] = x_i[i - pow_2] * x_j[log_n - k - 1].square();
//        l[i] = x_i[i] * innerProductProof.a_ + z;
//        r[i] = y_n_.inverse() * (x_i[i].inverse() * innerProductProof.b_ + (z_square_neg * two_n_)) - z;
//        y_n_ *= y;
//        two_n_ *= Exponent(uint64_t(2));
//    }

    //check line 105
    GroupElement left_;
//    //////
//    Exponent c;
//    c.randomize();
//    left_ += NextGenPrimitives<Exponent, GroupElement>::commit(g, (innerProductProof.c_ - delta) * c, h, proof.T_x * c);
//    left_ += V * (z_square_neg * c);
//    left_ += proof.T1 * (x.negate() * c);
//    left_ += proof.T2 * ((x.square()).negate() * c);
    ////
    g_.get_vector_multiple(l, left_);
    h_.get_vector_multiple(r, left_);
    left_ += g * (x_u *  (innerProductProof.a_ * innerProductProof.b_ - innerProductProof.c_));
    left_ += h * proof.u;
    left_ += proof.A.inverse();
    left_ += proof.S * x_neg;
    /////
    zcoin_common::GeneratorVector<Exponent, GroupElement> L(innerProductProof.L_);
    zcoin_common::GeneratorVector<Exponent, GroupElement> R(innerProductProof.R_);
    std::vector<Exponent> x_j_sq_neg, x_j_sq_inv_neg;
    for(int j = 0; j < log_n; ++j){
        x_j_sq_neg.push_back(x_j[j].square().negate());
        x_j_sq_inv_neg.push_back(x_j_inv[j].square().negate());
        /////
//        left_ += innerProductProof.L_[j] * (x_j[j].square().negate()) + innerProductProof.R_[j] * (x_j_inv[j].square().negate());
    }
    L.get_vector_multiple(x_j_sq_neg, left_);
    R.get_vector_multiple(x_j_sq_inv_neg, left_);
    if(!left_.isOne())
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool RangeVerifier<Exponent, GroupElement>::verify_batch(const std::vector<GroupElement>& V, const RangeProof<Exponent, GroupElement>& proof){
    uint64_t m = V.size();
    //computing challenges
    Exponent x, x_u, y, z;
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, proof.S, y);
    Exponent y_inv =  y.inverse();
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.S, proof.A, z);
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.T1, proof.T2, x);
    Exponent x_neg = x.negate();
    NextGenPrimitives<Exponent, GroupElement>::get_x(proof.A, x_u);
    uint64_t log_n = (int)(log(n * m) / log(2));
    const InnerProductProof<Exponent, GroupElement>& innerProductProof = proof.innerProductProof;
    std::vector<Exponent> x_j, x_j_inv;
    x_j.resize(log_n);
    x_j_inv.reserve(log_n);
    for(int i = 0; i < log_n; ++i) {
        NextGenPrimitives<Exponent, GroupElement>::get_x(innerProductProof.L_[i], innerProductProof.R_[i], x_j[i]);
        x_j_inv.push_back((x_j[i].inverse()));
    }

    Exponent z_square_neg = (z.square()).negate();
    Exponent delta = NextGenPrimitives<Exponent, GroupElement>::delta(y, z, n, m);
    //check line 97
    GroupElement left = NextGenPrimitives<Exponent, GroupElement>::commit(g, (innerProductProof.c_ - delta), h, proof.T_x);
    GroupElement V_z;
    Exponent z_m(uint64_t(1));
    for(int j = 0; j < m; ++j){
        V_z += V[j] * (z_square_neg * z_m);
        z_m *= z;
    }
    left += V_z;
    left += proof.T1 * x_neg;
    left += proof.T2 * ((x.square()).negate());
    if(!left.isOne())
        return false;

    std::vector<Exponent> l, r;
    l.resize(n * m);
    r.resize(n * m);
    Exponent y_n_(uint64_t(1));
    Exponent two(uint64_t(2));
    Exponent z_j = z.square();
    Exponent z_j_sum = z_j;
    for (uint64_t j = 0; j < m ; ++j) {
        Exponent two_n_(uint64_t(1));
        for (uint64_t k = 0; k < n; ++k) {
            uint64_t i = j * n + k;
            Exponent x_il(uint64_t(1));
            Exponent x_ir(uint64_t(1));
            for (int j = 0; j < log_n; ++j) {
                if ((i >> j) & 1) {
                    x_il *= x_j[log_n - j - 1];
                    x_ir *= x_j_inv[log_n - j - 1];
                } else {
                    x_il *= x_j_inv[log_n - j - 1];
                    x_ir *= x_j[log_n - j - 1];
                }

            }
            l[i] = x_il * innerProductProof.a_ + z;
            r[i] = y_n_ * (x_ir * innerProductProof.b_ - (z_j_sum * two_n_)) - z;
            y_n_ *= y_inv;
            two_n_ *= two;
        }
        z_j *= z;
        z_j_sum += z_j;
    }
    //check line 105
    GroupElement left_;
    g_.get_vector_multiple(l, left_);
    h_.get_vector_multiple(r, left_);
    left_ += g * (x_u *  (innerProductProof.a_ * innerProductProof.b_ - innerProductProof.c_));
    left_ += h * proof.u;
    left_ += proof.A.inverse();
    left_ += proof.S * x_neg;

    zcoin_common::GeneratorVector<Exponent, GroupElement> L(innerProductProof.L_);
    zcoin_common::GeneratorVector<Exponent, GroupElement> R(innerProductProof.R_);
    std::vector<Exponent> x_j_sq_neg, x_j_sq_inv_neg;
    for(int j = 0; j < log_n; ++j){
        x_j_sq_neg.push_back(x_j[j].square().negate());
        x_j_sq_inv_neg.push_back(x_j_inv[j].square().negate());
    }
    L.get_vector_multiple(x_j_sq_neg, left_);
    R.get_vector_multiple(x_j_sq_inv_neg, left_);

    if(!left_.isOne())
        return false;
    return true;
}


}//namespace nextgen