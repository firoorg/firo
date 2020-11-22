
#include <math.h>
namespace sigma{

template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        int n,
        int m)
    : g_(g)
    , h_(h_gens)
    , n(n)
    , m(m){
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        bool fPadding) const {

    R1ProofVerifier<Exponent, GroupElement> r1ProofVerifier(g_, h_, proof.B_, n, m);
    std::vector<Exponent> f;
    const R1Proof<Exponent, GroupElement>& r1Proof = proof.r1Proof_;
    if (!r1ProofVerifier.verify(r1Proof, f, true /* Skip verification of final response */)) {
        LogPrintf("Sigma spend failed due to r1 proof incorrect.");
        return false;
    }

    if (!proof.B_.isMember() || proof.B_.isInfinity()) {
        LogPrintf("Sigma spend failed due to value of B outside of group.");
        return false;
    }

    const std::vector <GroupElement>& Gk = proof.Gk_;
    for (int k = 0; k < m; ++k) {
        if (!Gk[k].isMember() || Gk[k].isInfinity()) {
            LogPrintf("Sigma spend failed due to value of GK[i] outside of group.");
            return false;
        }
    }

    // Compute value of challenge X, then continue R1 proof and sigma final response proof.
    std::vector<GroupElement> group_elements = {
        r1Proof.A_, proof.B_, r1Proof.C_, r1Proof.D_};

    group_elements.insert(group_elements.end(), Gk.begin(), Gk.end());
    Exponent challenge_x;
    SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, challenge_x);

    // Now verify the final response of r1 proof. Values of "f" are finalized only after this call.
    if (!r1ProofVerifier.verify_final_response(r1Proof, challenge_x, f)) {
        LogPrintf("Sigma spend failed due to incorrect final response.");
        return false;
    }

    if(!proof.z_.isMember() || proof.z_.isZero()) {
        LogPrintf("Sigma spend failed due to value of Z outside of group.");
        return false;
    }

    if (commits.empty()) {
        LogPrintf("No mints in the anonymity set");
        return false;
    }

    std::size_t N = commits.size();
    std::vector<Exponent> f_i_;
    f_i_.resize(N);

    ptr = f_i_.data();
    end_ptr = ptr + N;
    Scalar f_i(uint64_t(1));
    compute_fis(f_i, m, f);

    if (fPadding) {
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
        std::vector<uint64_t> I = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(N - 1, n, m);
        vector<Exponent> f_part_product;    // partial product of f array elements for lastIndex
        for (int j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f[j * n + I[j]];
        }

        Exponent xj(uint64_t(1));;    // x^j
        for (int j = 0; j < m; j++) {
            Exponent fi_sum(uint64_t(0));
            for (int i = I[j] + 1; i < n; i++)
                fi_sum += f[j*n + i];
            f_i_[N - 1] += fi_sum * xj * f_part_product[m - j - 1];
            xj *= challenge_x;
        }
    }

    secp_primitives::MultiExponent mult(commits, f_i_);
    GroupElement t1 = mult.get_multiple();

    GroupElement t2;
    Exponent x_k(uint64_t(1));
    for(int k = 0; k < m; ++k){
        t2 += (Gk[k] * (x_k.negate()));
        x_k *= challenge_x;
    }

    GroupElement left(t1 + t2);
    if (left != SigmaPrimitives<Exponent, GroupElement>::commit(g_, Exponent(uint64_t(0)), h_[0], proof.z_)) {
        LogPrintf("Sigma spend failed due to final proof verification failure.");
        return false;
    }

    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::batch_verify(
        const std::vector<GroupElement>& commits,
        const std::vector<Exponent>& serials,
        const vector<bool>& fPadding,
        const std::vector<size_t>& setSizes,
        const vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const {

    int M = proofs.size();
    int N = commits.size();

    if (commits.empty())
        return false;

    for(int t = 0; t < M; ++t) {
        if (!membership_checks(proofs[t])) {
            LogPrintf("Sigma spend failed due to membership check failed.");
            return false;
        }
    }
    std::vector<Exponent> challenges;
    challenges.resize(M);

    std::vector<std::vector<Exponent>> f_;
    f_.resize(M);
    for (int t = 0; t < M; ++t)
    {
        std::vector<GroupElement> group_elements = {
                proofs[t].r1Proof_.A_, proofs[t].B_, proofs[t].r1Proof_.C_, proofs[t].r1Proof_.D_};

        group_elements.insert(group_elements.end(), proofs[t].Gk_.begin(), proofs[t].Gk_.end());
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, challenges[t]);

        if(!compute_fs(proofs[t], challenges[t], f_[t]) || !abcd_checks(proofs[t], challenges[t], f_[t])) {
            LogPrintf("Sigma spend failed due to compute_fs or abcd_checks failed.");
            return false;
        }
    }

    std::vector<Scalar> y;
    y.resize(M);
    for (int t = 0; t < M; ++t)
        y[t].randomize();

    std::vector<Scalar> f_i_t;
    f_i_t.resize(N);
    GroupElement right;
    Scalar exp;

    std::vector <std::vector<uint64_t>> I_;
    I_.resize(N);
    for (int i = 0; i < N ; ++i)
        I_[i] = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);

    for (int t = 0; t < M; ++t)
    {
        right += (SigmaPrimitives<Exponent, GroupElement>::commit(g_, Scalar(uint64_t(0)), h_[0], proofs[t].z_)) * y[t];
        Scalar e;
        size_t size = setSizes[t];
        size_t start = N - size;

        ptr = f_i_t.data() + start;
        start_ptr = ptr;
        end_ptr = ptr + size - 1;
        Scalar f_i(uint64_t(1));
        compute_batch_fis(f_i, m, f_[t], y[t], e);

        if(fPadding[t]) {
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

            Scalar pow(uint64_t(1));
            vector <Scalar> f_part_product;    // partial product of f array elements for lastIndex
            for (int j = m - 1; j >= 0; j--) {
                f_part_product.push_back(pow);
                pow *= f_[t][j * n + I_[size - 1][j]];
            }

            NthPower<Exponent> xj(challenges[t]);
            for (std::size_t j = 0; j < m; j++) {
                Scalar fi_sum(uint64_t(0));
                for (std::size_t i = I_[size - 1][j] + 1; i < n; i++)
                    fi_sum += f_[t][j * n + i];
                pow += fi_sum * xj.pow * f_part_product[m - j - 1];
                xj.go_next();
            }

            f_i_t[N - 1] += pow * y[t];
            e += pow;
        } else {
            Scalar f_i(uint64_t(1));
            for (std::size_t j = 0; j < m; ++j)
            {
                f_i *= f_[t][j*n + I_[size - 1][j]];
            }

            f_i_t[N - 1] += f_i * y[t];
            e += f_i;
        }

        e *= serials[t] * y[t];
        exp += e;
    }

    secp_primitives::MultiExponent mult(commits, f_i_t);
    GroupElement t1 = mult.get_multiple();

    std::vector<std::vector<Scalar>> x_t_k_neg;
    x_t_k_neg.resize(M);
    for (int t = 0; t < M; ++t) {
        x_t_k_neg[t].reserve(m);
        NthPower<Exponent> x_k(challenges[t]);
        for (uint64_t k = 0; k < m; ++k) {
            x_t_k_neg[t].emplace_back(x_k.pow.negate());
            x_k.go_next();
        }
    }

    GroupElement t2;
    for (int t = 0; t < M; ++t) {
        const std::vector <GroupElement>& Gk = proofs[t].Gk_;
        GroupElement term;
        for (std::size_t k = 0; k < m; ++k)
        {
            term += ((Gk[k]) * x_t_k_neg[t][k]);
        }
        term *= y[t];
        t2 += term;
    }
    GroupElement left(t1 + t2);

    right += g_ * exp;
    if(left != right)
        return false;

    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    if(!(proof.r1Proof_.A_.isMember() &&
         proof.B_.isMember() &&
         proof.r1Proof_.C_.isMember() &&
         proof.r1Proof_.D_.isMember()) ||
        (proof.r1Proof_.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.r1Proof_.C_.isInfinity() ||
         proof.r1Proof_.D_.isInfinity()))
        return false;

    for (std::size_t i = 0; i < proof.r1Proof_.f_.size(); i++)
    {
        if (!proof.r1Proof_.f_[i].isMember() || proof.r1Proof_.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& Gk = proof.Gk_;
    for (std::size_t k = 0; k < m; ++k)
    {
        if (!Gk[k].isMember() || Gk[k].isInfinity())
            return false;
    }
    if(!(proof.r1Proof_.ZA_.isMember() &&
         proof.r1Proof_.ZC_.isMember() &&
         proof.z_.isMember()) ||
        (proof.r1Proof_.ZA_.isZero() ||
         proof.r1Proof_.ZC_.isZero() ||
         proof.z_.isZero()))
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::compute_fs(
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        const Exponent& x,
        std::vector<Exponent>& f_) const {
    for(unsigned int j = 0; j < proof.r1Proof_.f_.size(); ++j) {
        if(proof.r1Proof_.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        int k = n - 1;
        for (int i = 0; i < k; ++i)
        {
            temp += proof.r1Proof_.f_[j * k + i];
            f_.emplace_back(proof.r1Proof_.f_[j * k + i]);
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
    Exponent c;
    c.randomize();

    // Aggregating two checks into one, B^x * A = Comm(..) and C^x * D = Comm(..)
    std::vector<Scalar> f_plus_f_prime;
    f_plus_f_prime.reserve(f_.size());
    for(std::size_t i = 0; i < f_.size(); i++)
        f_plus_f_prime.emplace_back(f_[i] * c + f_[i] * (x - f_[i]));

    GroupElement right;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, f_plus_f_prime, proof.r1Proof_.ZA_ * c + proof.r1Proof_.ZC_, right);
    if(((proof.B_ * x + proof.r1Proof_.A_) * c + proof.r1Proof_.C_ * x + proof.r1Proof_.D_) != right)
        return false;
    return true;
}

template<class Exponent, class GroupElement>
void SigmaPlusVerifier<Exponent, GroupElement>::compute_fis(const Exponent& f_i, int j, const std::vector<Exponent>& f) const {
    j--;
    if (j == -1)
    {
        if(ptr < end_ptr)
            *ptr++ += f_i;
        return;
    }

    Scalar t;

    for (int i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_fis(t, j, f);
    }
}

template<class Exponent, class GroupElement>
void SigmaPlusVerifier<Exponent, GroupElement>::compute_batch_fis(const Exponent& f_i, int j, const std::vector<Exponent>& f, const Exponent& y, Exponent& e) const {
    j--;
    if (j == -1)
    {
        if(ptr >= start_ptr && ptr < end_ptr){
            *ptr++ += f_i * y;
            e += f_i;
        }
        return;
    }

    Exponent t;

    for (int i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_batch_fis(t, j, f, y, e);
    }
}

} // namespace sigma