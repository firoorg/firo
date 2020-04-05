namespace lelantus {

template<class Exponent, class GroupElement>
SigmaPlusProver<Exponent, GroupElement>::SigmaPlusProver(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        uint64_t n,
        uint64_t m)
        : g_(g)
        , h_(h_gens)
        , n_(n)
        , m_(m) {
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::proof(
        const std::vector<GroupElement>& commits,
        int l,
        const Exponent& v,
        const Exponent& r,
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    Exponent rA, rB, rC, rD;
    rA.randomize();
    rB.randomize();
    rC.randomize();
    rD.randomize();
    std::vector <Exponent> sigma;
    std::vector <Exponent> Tk, Pk, Yk;
    Tk.resize(m_);
    Pk.resize(m_);
    Yk.resize(m_);
    std::vector<Exponent> a;
    a.resize(n_ * m_);
    sigma_commit(commits, l, rA, rB, rC, rD, a, Tk, Pk, Yk, sigma, proof_out);
    Exponent x;
    std::vector<GroupElement> group_elements = {proof_out.A_, proof_out.B_, proof_out.C_, proof_out.D_};
    group_elements.insert(group_elements.end(), proof_out.Gk_.begin(), proof_out.Gk_.end());
    group_elements.insert(group_elements.end(), proof_out.Qk.begin(), proof_out.Qk.end());
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
    sigma_response(sigma, a, rA, rB, rC, rD, v, r, Tk, Pk, x, proof_out);
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::sigma_commit(
        const std::vector<GroupElement>& commits,
        int l,
        const Exponent& rA,
        const Exponent& rB,
        const Exponent& rC,
        const Exponent& rD,
        std::vector <Exponent>& a,
        std::vector <Exponent>& Tk,
        std::vector <Exponent>& Pk,
        std::vector <Exponent>& Yk,
        std::vector <Exponent>& sigma,
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    std::size_t setSize = commits.size();
    assert(setSize > 0);
    LelantusPrimitives<Exponent, GroupElement>::convert_to_sigma(l, n_, m_, sigma);
    for (std::size_t k = 0; k < m_; ++k)
    {
        Tk[k].randomize();
        Pk[k].randomize();
        Yk[k].randomize();
    }

    //compute B
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, sigma, rB, proof_out.B_);

    //compute A
    for (std::size_t j = 0; j < m_; ++j)
    {
        for (std::size_t i = 1; i < n_; ++i)
        {
            a[j * n_ + i].randomize();
            a[j * n_] -= a[j * n_ + i];
        }
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, a, rA, proof_out.A_);

    //compute C
    std::vector<Exponent> c;
    c.resize(n_ * m_);
    Exponent one(uint64_t(1));
    Exponent two(uint64_t(2));
    for (std::size_t i = 0; i < n_ * m_; ++i)
    {
        c[i] = a[i] * (one - two * sigma[i]);
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_,h_, c, rC, proof_out.C_);

    //compute D
    std::vector<Exponent> d;
    d.resize(n_ * m_);
    for (std::size_t i = 0; i < n_ * m_; i++)
    {
        d[i] = a[i].square().negate();
    }
    LelantusPrimitives<Exponent, GroupElement>::commit(g_,h_, d, rD, proof_out.D_);

    std::size_t N = setSize;
    std::vector <std::vector<Exponent>> P_i_k;
    P_i_k.resize(N);
    for (std::size_t i = 0; i < N - 1; ++i)
    {
        std::vector <Exponent>& coefficients = P_i_k[i];
        std::vector<uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(i, n_, m_);
        coefficients.push_back(a[I[0]]);
        coefficients.push_back(sigma[I[0]]);
        for (std::size_t j = 1; j < m_; ++j) {
            LelantusPrimitives<Exponent, GroupElement>::new_factor(sigma[j * n_ + I[j]], a[j * n_ + I[j]], coefficients);
        }
    }

    /*
     * To optimize calculation of sum of all polynomials indices 's' = setSize-1 through 'n^m-1' we use the
     * fact that sum of all of elements in each row of 'a' array is zero. Computation is done by going
     * through n-ary representation of 's' and increasing "digit" at each position to 'n-1' one by one.
     * During every step digits at higher positions are fixed and digits at lower positions go through all
     * possible combinations with a total corresponding polynomial sum of 'x^j'.
     *
     * The math behind optimization (TeX notation):
     *
     * \sum_{i=s+1}^{N-1}p_i(x) =
     *   \sum_{j=0}^{m-1}
     *     \left[
     *       \left( \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i}) \right)
     *       \left( \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k}) \right)
     *       x^j
     *     \right]
     */

    std::vector<uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(N-1, n_, m_);
    std::vector<uint64_t> lj = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(l, n_, m_);

    std::vector<Exponent> p_i_sum;
    p_i_sum.emplace_back(one);
    std::vector<std::vector<Exponent>> partial_p_s;

    // Pre-calculate product parts and calculate p_s(x) at the same time, put the latter into p_i_sum
    for (int j = m_ - 1; j >= 0; j--) {
        partial_p_s.push_back(p_i_sum);
        LelantusPrimitives<Exponent, GroupElement>::new_factor(sigma[j * n_ + I[j]], a[j * n_ + I[j]], p_i_sum);
    }

    for (std::size_t j = 0; j < m_; j++) {
        // \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i})
        Exponent a_sum(uint64_t(0));
        for (std::size_t i = I[j] + 1; i < n_; i++)
            a_sum += a[j * n_ + i];
        Exponent x_sum(uint64_t(lj[j] >= I[j]+1 ? 1 : 0));

        // Multiply by \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k})
        std::vector<Exponent> &polynomial = partial_p_s[m_ - j - 1];
        LelantusPrimitives<Exponent, GroupElement>::new_factor(x_sum, a_sum, polynomial);

        // Multiply by x^j and add to the result
        for (std::size_t k = 0; k < m_ - j; k++)
            p_i_sum[j + k] += polynomial[k];
    }

    P_i_k[N-1] = p_i_sum;

    proof_out.Gk_.reserve(m_);
    proof_out.Qk.reserve(m_);
    for (std::size_t k = 0; k < m_; ++k)
    {
        std::vector <Exponent> P_i;
        P_i.reserve(N);
        for (std::size_t i = 0; i < N; ++i){
            P_i.emplace_back(P_i_k[i][k]);
        }
        secp_primitives::MultiExponent mult(commits, P_i);
        GroupElement c_k = mult.get_multiple();
        proof_out.Gk_.emplace_back(c_k + h_[1] * Yk[k].negate());
        proof_out.Qk.emplace_back(LelantusPrimitives<Exponent, GroupElement>::double_commit(g_, Exponent(uint64_t(0)), h_[0], Pk[k], h_[1], Tk[k]) + h_[1] * Yk[k]);

    }
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::sigma_response(
        const std::vector <Exponent>& sigma,
        const std::vector<Exponent>& a,
        const Exponent& rA,
        const Exponent& rB,
        const Exponent& rC,
        const Exponent& rD,
        const Exponent& v,
        const Exponent& r,
        const std::vector <Exponent>& Tk,
        const std::vector <Exponent>& Pk,
        const Exponent& x,
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {

    //f
    proof_out.f_.reserve(m_ * (n_ - 1));
    for (std::size_t j = 0; j < m_; j++)
    {
        for (std::size_t i = 1; i < n_; i++)
            proof_out.f_.emplace_back(sigma[(j * n_) + i] * x + a[(j * n_) + i]);
    }
    //zA, zC
    proof_out.ZA_ =  rB * x + rA;
    proof_out.ZC_ = rC * x + rD;

    //computing z
    proof_out.zV_ = v * x.exponent(uint64_t(m_));
    proof_out.zR_ = r * x.exponent(uint64_t(m_));
    Exponent sumV, sumR;

    NthPower<Exponent> x_k(x);
    for (std::size_t k = 0; k < m_; ++k) {
        sumV += (Pk[k] * x_k.pow);
        sumR += (Tk[k] * x_k.pow);
        x_k.go_next();
    }
    proof_out.zV_ -= sumV;
    proof_out.zR_ -= sumR;
}

}//namespace lelantus