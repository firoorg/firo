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

    std::size_t N = commits.size();
    Exponent pow(uint64_t(1));
    if(fPadding) {
        // get power for lastIndex position
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
            pow += fi_sum * xj * f_part_product[m - j - 1];
            xj *= challenge_x;
        }
    }

    std::vector<Exponent> f_i_;
    f_i_.reserve(N);

    std::size_t N_ = N;
    if(fPadding) {
        N_ = N - 1;
    }

    for(std::size_t i = 0; i < N_; ++i) {
        std::vector<uint64_t> I = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
        Exponent f_i(uint64_t(1));
        for(int j = 0; j < m; ++j){
            f_i *= f[j*n + I[j]];
        }
        f_i_.emplace_back(f_i);
    }

    if(fPadding) {
        f_i_.emplace_back(pow);
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

} // namespace sigma
