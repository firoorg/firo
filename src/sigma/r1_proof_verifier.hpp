namespace sigma {

template<class Exponent, class GroupElement>
R1ProofVerifier<Exponent,GroupElement>::R1ProofVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        const GroupElement& B,
        int n ,
        int m)
    : g_(g)
    , h_(h_gens)
    , B_Commit(B)
    , n_(n)
    , m_(m){
}

template<class Exponent, class GroupElement>
bool R1ProofVerifier<Exponent,GroupElement>::verify(
        const R1Proof<Exponent, GroupElement>& proof,
        bool skip_final_response_verification) const {
    std::vector<Exponent> f;
    return verify(proof, f, skip_final_response_verification);
}

template<class Exponent, class GroupElement>
bool R1ProofVerifier<Exponent,GroupElement>::verify(
        const R1Proof<Exponent, GroupElement>& proof,
        std::vector<Exponent>& f_out, 
        bool skip_final_response_verification) const{

    if(!(proof.A_.isMember() &&
         B_Commit.isMember()  &&
         proof.C_.isMember() &&
         proof.D_.isMember()))
        return false;
    const std::vector<Exponent>& f = proof.f_;
    for (std::size_t i = 0; i < f.size(); i++) {
        if(!f[i].isMember())
            return false;
    }

    if(!(proof.ZA_.isMember() &&
         proof.ZC_.isMember()))
        return false;

    if (!skip_final_response_verification) {
        Exponent x;
        std::vector<GroupElement> group_elements = {proof.A_, B_Commit, proof.C_, proof.D_};
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
        return verify_final_response(proof, x, f_out);
    }
    return true;
}

template<class Exponent, class GroupElement>
bool R1ProofVerifier<Exponent,GroupElement>::verify_final_response(
            const R1Proof<Exponent, GroupElement>& proof,
            const Exponent& challenge_x,
            std::vector<Exponent>& f_out) const {
    const std::vector<Exponent>& f = proof.f_;
    f_out.clear();
    f_out.reserve(n_ * m_);
    for(int j = 0; j < m_; ++j) {
        f_out.push_back(Exponent(uint64_t(0)));
        Exponent temp;
        int k = n_ - 1;
        for(int i = 0; i < k; ++i) {
            temp += f[j * k + i];
            f_out.emplace_back(f[j * k + i]);
        }
        f_out[j * n_] = challenge_x - temp;
    }

    GroupElement one;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, f_out, proof.ZA_, one);
    if((B_Commit * challenge_x + proof.A_) != one)
        return false;

    std::vector<Exponent> f_outprime;
    f_outprime.reserve(f_out.size());
    for (std::size_t i = 0; i < f_out.size(); i++) {
        f_outprime.emplace_back(f_out[i] * (challenge_x - f_out[i]));
    }

    GroupElement two;
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, f_outprime, proof.ZC_, two);
    if ((proof.C_ * challenge_x + proof.D_) != two)
        return false;

    return true;
}
 
} // namespace sigma
