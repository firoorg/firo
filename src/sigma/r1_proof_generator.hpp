namespace sigma {

template<class Exponent, class GroupElement>
R1ProofGenerator<Exponent,GroupElement>::R1ProofGenerator(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        const std::vector<Exponent>& b,
        const Exponent& r,
        int n ,
        int m)
    : g_(g)
    , h_(h_gens)
    , b_(b)
    , r(r)
    , n_(n)
    , m_(m)
{
    SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, b_, r, B_Commit);
}

template<class Exponent, class GroupElement>
const GroupElement& R1ProofGenerator<Exponent,GroupElement>::get_B() const {
    return B_Commit;
}

template<class Exponent, class GroupElement>
void R1ProofGenerator<Exponent,GroupElement>::proof(
        R1Proof<Exponent, GroupElement>& proof_out, bool skip_final_response) {
    std::vector<Exponent> a;
    proof(a, proof_out, skip_final_response);
}

template<class Exponent, class GroupElement>
void R1ProofGenerator<Exponent,GroupElement>::proof(
        std::vector<Exponent>& a_out,
        R1Proof<Exponent, GroupElement>& proof_out,
        bool skip_final_response) {
    rC_.randomize();
    rD_.randomize();
    a_out.resize(n_ * m_);
    for(int j = 0; j < m_; ++j) {
        for(int i = 1; i < n_; ++i) {
            a_out[j * n_ + i].randomize();
            a_out[j * n_] -= a_out[j * n_ + i];
        }
    }

    // proof_out.B_ = B_Commit;

    //compute A
    GroupElement A;
    while(!A.isMember() || A.isInfinity()) {
        rA_.randomize();
        SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, a_out, rA_, A);
    }
    proof_out.A_ = A;

    //compute C
    std::vector<Exponent> c;
    c.resize(n_ * m_);
    for(int i = 0; i < n_ * m_; ++i) {
        c[i] = (a_out[i] * (Exponent(uint64_t(1)) - (Exponent(uint64_t(2)) * b_[i])));
    }
    GroupElement C;
    while(!C.isMember() || C.isInfinity()) {
        rC_.randomize();
        SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, c, rC_, C);
    }
    proof_out.C_ = C;

    //compute D
    std::vector<Exponent> d;
    d.resize(n_ * m_);
    for(int i = 0; i < n_ * m_; i++) {
        d[i] = ((a_out[i].square()).negate());
    }
    GroupElement D;
    while(!D.isMember() || D.isInfinity()) {
        rD_.randomize();
        SigmaPrimitives<Exponent, GroupElement>::commit(g_, h_, d, rD_, D);
    }
    proof_out.D_ = D;

    if (!skip_final_response) {
        Exponent x;
        std::vector<GroupElement> group_elements = {A, B_Commit, C, D};
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
        generate_final_response(a_out, x, proof_out);
    }
}

template<class Exponent, class GroupElement>
void R1ProofGenerator<Exponent,GroupElement>::generate_final_response(
        const std::vector<Exponent>& a,
        const Exponent& challenge_x,
        R1Proof<Exponent, GroupElement>& proof_out) {
    //f
    proof_out.f_.clear();
    proof_out.f_.reserve(m_ * (n_ - 1));
    for(int j = 0; j < m_; j++) {
        for(int i = 1; i < n_; i++)
        proof_out.f_.emplace_back(b_[(j * n_) + i] * challenge_x + a[(j * n_) + i]);
    }

    //zA
    proof_out.ZA_ = r * challenge_x + rA_;
    proof_out.ZC_ = rC_ * challenge_x + rD_;
}

} //namespace sigma
