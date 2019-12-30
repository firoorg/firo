namespace lelantus {

template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        uint64_t n,
        uint64_t m)
        : g_(g)
        , h_(h_gens)
        , n(n)
        , m(m){
}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    Exponent x;
    std::vector<GroupElement> group_elements = {proof.A_, proof.B_, proof.C_, proof.D_};
    group_elements.insert(group_elements.end(), proof.Gk_.begin(), proof.Gk_.end());
    group_elements.insert(group_elements.end(), proof.Qk.begin(), proof.Qk.end());
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
    return verify(commits, x, proof);
}

template<class Exponent, class GroupElement>
bool  SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const Exponent& x,
        const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    if(!membership_checks(proof))
        return false;

    std::vector<Exponent> f_;
    compute_fs(proof, x, f_);

    if(!abcd_checks(proof, x, f_))
        return false;

    int N = commits.size();
    std::vector<Exponent> f_i_;
    f_i_.reserve(N);
    for (int i = 0; i < N; ++i)
    {
        std::vector<uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
        Exponent f_i(uint64_t(1));
        for (int j = 0; j < m; ++j)
        {
            f_i *= f_[j*n + I[j]];
        }
        f_i_.emplace_back(f_i);
    }

    secp_primitives::MultiExponent mult(commits, f_i_);
    GroupElement t1 = mult.get_multiple();

    const std::vector <GroupElement>& Gk = proof.Gk_;
    const std::vector <GroupElement>& Qk = proof.Qk;
    GroupElement t2;
    Exponent x_k(uint64_t(1));
    for (int k = 0; k < m; ++k)
    {
        t2 += ((Gk[k] + Qk[k] )* (x_k.negate()));
        x_k *= x;
    }

    GroupElement left(t1 + t2);
    if(left != LelantusPrimitives<Exponent, GroupElement>::double_commit(g_, Exponent(uint64_t(0)), h_[0], proof.zV_, h_[1], proof.zR_))
        return false;

    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::batchverify(
        const std::vector<GroupElement>& commits,
        const Exponent& x,
        const std::vector<Exponent>& serials,
        const vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const {
    int M = proofs.size();
    int N = commits.size();

    if (commits.empty())
        return false;

    for(int t = 0; t < M; ++t)
        if(!membership_checks(proofs[t]))
            return false;
    std::vector<std::vector<Exponent>> f_;
    f_.resize(M);
    for (int t = 0; t < M; ++t)
    {
        if(!compute_fs(proofs[t], x, f_[t]) || !abcd_checks(proofs[t], x, f_[t]))
            return false;
    }

    std::vector<Exponent> y;
    y.resize(M);
    for (int t = 0; t < M; ++t)
        y[t].randomize();
    //TODO(levon) remove this matrix. we can only keep single row in each iteration. need some changes in logic.
    std::vector<std::vector<Exponent>> f_i_;
    f_i_.resize(M);
    std::vector<Exponent> f_i_t;
    f_i_t.reserve(N);
    for (int t = 0; t < M; ++t)
    {
        f_i_[t].reserve(N);
        for (int i = 0; i < N - 1; ++i)
        {
            std::vector <uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
            Exponent f_i(uint64_t(1));
            for (int j = 0; j < m; ++j)
            {
                f_i *= f_[t][j*n + I[j]];
            }
            f_i_[t].emplace_back(f_i);
        }

        /*
        * Optimization for getting power for last 'commits' array element is done similarly to the one used in creating
        * a proof. The fact that sum of any row in 'f' array is 'x' (challenge value) is used.
        *
        * Math (in TeX notation):
        *
        * \sum_{i=s+1}^{N-1} \prod_{j=0}^{m-1}f_{j,i_j} =
        *   \sum_{j=0}^{m-1}
        *     \left[
        *       \left( \sum_{i=s_j+1}^{n-1}f_{j,i} \right)
        *       \left( \prod_{k=j}^{m-1}f_{k,s_k} \right)
        *       x^j
        *     \right]
        */

        Exponent pow(uint64_t(1));
        std::vector<uint64_t> I = LelantusPrimitives<Exponent, GroupElement>::convert_to_nal(N - 1, n, m);
        vector<Exponent> f_part_product;    // partial product of f array elements for lastIndex
        for (int j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[t][j * n + I[j]];
        }

        Exponent xj(uint64_t(1));;    // x^j
        for (int j = 0; j < m; j++) {
            Exponent fi_sum(uint64_t(0));
            for (int i = I[j] + 1; i < n; i++)
                fi_sum += f_[t][j*n + i];
            pow += fi_sum * xj * f_part_product[m - j - 1];
            xj *= x;
        }
        f_i_[t].emplace_back(pow);
    }

    for (int i = 0; i < N; ++i)
    {
        Exponent f_i;
        for (int t = 0; t < M;++t)
            f_i += f_i_[t][i] * y[t];
        f_i_t.emplace_back(f_i);
    }

    secp_primitives::MultiExponent mult(commits, f_i_t);
    GroupElement t1 = mult.get_multiple();

    GroupElement t2;
    for (int t = 0; t < M; ++t)
    {
        const std::vector <GroupElement>& Gk = proofs[t].Gk_;
        const std::vector <GroupElement>& Qk = proofs[t].Qk;
        GroupElement term;
        Exponent x_k(uint64_t(1));
        for (int k = 0; k < m; ++k)
        {
            term += ((Gk[k] + Qk[k]) * (x_k.negate()));
            x_k *= x;
        }
        term *= y[t];
        t2 += term;
    }
    GroupElement left(t1 + t2);

    GroupElement right;
    Exponent exp;
    for (int t = 0; t < M; ++t)
    {
        right += (LelantusPrimitives<Exponent, GroupElement>::double_commit(g_, Exponent(uint64_t(0)), h_[0], proofs[t].zV_, h_[1], proofs[t].zR_)) * y[t];
        Exponent e;
        for(int i = 0; i < N; ++i)
            e += f_i_[t][i];
        e *= serials[t] * y[t];
        exp += e;
    }
    right += g_ * exp;
    if(left != right)
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    if(!(proof.A_.isMember() &&
         proof.B_.isMember() &&
         proof.C_.isMember() &&
         proof.D_.isMember()) ||
        (proof.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.C_.isInfinity() ||
         proof.D_.isInfinity()))
        return false;

    for (int i = 0; i < proof.f_.size(); i++)
    {
        if (!proof.f_[i].isMember() || proof.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& Gk = proof.Gk_;
    const std::vector <GroupElement>& Qk = proof.Qk;
    for (int k = 0; k < m; ++k)
    {
        if (!(Gk[k].isMember() && Qk[k].isMember()))
            return false;
    }
    if(!(proof.ZA_.isMember() &&
         proof.ZC_.isMember() &&
         proof.zV_.isMember() &&
         proof.zR_.isMember()) ||
        (proof.ZA_.isZero() ||
         proof.ZC_.isZero() ||
         proof.zV_.isZero() ||
         proof.zR_.isZero()))
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::compute_fs(
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        const Exponent& x,
        std::vector<Exponent>& f_) const {
    for(unsigned int j = 0; j < proof.f_.size(); ++j) {
        if(proof.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (int j = 0; j < m; ++j)
    {
        f_.push_back(Exponent(uint64_t(0)));
        Exponent temp;
        int k = n - 1;
        for (int i = 0; i < k; ++i)
        {
            temp += proof.f_[j * k + i];
            f_.emplace_back(proof.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::abcd_checks(
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        const Exponent& x,
        const std::vector<Exponent>& f_) const {
    GroupElement one;
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, f_, proof.ZA_, one);
    if((proof.B_ * x + proof.A_) != one)
        return false;

    std::vector<Exponent> f_prime;
    f_prime.reserve(f_.size());
    for(int i = 0; i < f_.size(); i++)
        f_prime.emplace_back(f_[i] * (x - f_[i]));
    GroupElement two;
    LelantusPrimitives<Exponent, GroupElement>::commit(g_, h_, f_prime, proof.ZC_, two);
    if((proof.C_ * x + proof.D_) != two)
        return false;
    return true;
}

} //namespace lelantus