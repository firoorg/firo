namespace sigma {

template<class Exponent, class GroupElement>
SigmaPlusProver<Exponent, GroupElement>::SigmaPlusProver(const GroupElement& g,
                                 const std::vector<GroupElement>& h_gens, int n, int m)
                                : g_(g), h_(h_gens), n_(n), m_(m) {
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::proof(const std::vector<GroupElement>& commits, int l, Exponent r, SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    int N = commits.size();
    Exponent rB;
    rB.randomize();
    std::vector <Exponent> delta;
    convert_to_delta(l, n_, m_, delta);
    std::cout<<delta.size();
    for(int j = 0; j < m_; ++j){
        for(int i = 0; i < n_; ++i){
            std::cout<< delta[j*n_ + i]<< " ";
        }
        std::cout<<std::endl;
    }
    std::vector <Exponent> Pk;
    for (int k = 0; k < m_; ++k) {
        Pk.push_back(Exponent());
        Pk[k].randomize();
    }

    proof_out.n_ = n_;
    proof_out.m_ = m_;
    R1ProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> r1prover(g_, h_, delta, rB, n_, m_);
    R1Proof<secp_primitives::Scalar, secp_primitives::GroupElement> r1proof;
    std::vector<Exponent> a;
    r1prover.proof(a, r1proof);
    proof_out.r1Proof_ = r1proof;
    proof_out.B_ = r1prover.get_B();
    Exponent x = r1prover.x_;
    std::vector <std::vector<Exponent>> P_i_k;
    P_i_k.resize(N);
    for (int i = 0; i < commits.size(); ++i) {
        std::vector <Exponent>& coefficients = P_i_k[i];
        coefficients.push_back(uint64_t(0));
        std::vector<uint64_t> I = convert_to_nal(i, n_, m_);
        coefficients.push_back(delta[I[0]]);
        coefficients.push_back(a[I[0]]);
        for (int j = 1; j < m_; ++j) {
                newFactor(delta[j * n_ + I[j]], a[j * n_ + I[j]], coefficients);
        }
                std::reverse(coefficients.begin(), coefficients.end());
//        if(i == l)
//            coefficients.erase(coefficients.end()-1);
//        else{
//            coefficients.erase(coefficients.end()-1);coefficients.erase(coefficients.end()-1);
//        }
//        std::reverse(coefficients.begin(), coefficients.end());
    }


    //computing G_k`s;
    std::vector <GroupElement> Gk;
    zcoin_common::GeneratorVector <Exponent, GroupElement> c_(commits);
    for (int k = 0; k < m_; ++k) {
        std::vector <Exponent> P_i;
        for (int i = 0; i < N; ++i){
            P_i.push_back(P_i_k[i][k]);
//            if(i!=l)
//            P_i.push_back(P_i_k[i][m_ - k]);
//            else
//                P_i.push_back(P_i_k[i][m_ - k-1]);

    }
        GroupElement c_k;
        c_.get_vector_multiple(P_i, c_k);
        c_k += commit(g_, Exponent(uint64_t(0)), h_.get_g(0), Pk[k]);
        Gk.push_back(c_k);
    }
    proof_out.Gk_ = Gk;
    //computing z
    Exponent z;
    z = r * x.exponent(uint64_t(m_));
    Exponent sum;
    for (int k = 0; k < m_; ++k) {
        sum += (Pk[k] * x.exponent(uint64_t(k)));
    }
    z -= sum;
    proof_out.z_ = z;

// for debug
////checking if P_i_k`s are correct
   const std::vector<Exponent>& f = r1proof.get_f();
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = convert_to_nal(i, n_, m_);
         Exponent f_i(uint64_t(1));
         Exponent p_i_x(uint64_t(0));
//         std::cout<< I.size() <<" is I size" <<std::endl;
//         std::cout<< m_ << " is m" << std::endl;
            std::cout<<"I is "<< i<<" --->>";
        for(int j = 0; j < m_; ++j){
            std::cout<<I[j] <<" ";
            f_i *= f[j*n_ + I[j]];
            p_i_x += (P_i_k[i][j]*x.exponent(j));
        }
        std::cout<<std::endl;
        if(i==l)
            p_i_x += (P_i_k[i][m_]*x.exponent(m_));
        if(f_i==p_i_x)
            std::cout<< "P_i(x)"<< i << " is correct"<< std::endl;
    }

    ////////
    std::vector <Exponent> exp;
    zcoin_common::GeneratorVector<Exponent, GroupElement> c(commits);
    GroupElement C_i;
    for(int i = 0; i < N; ++i){
        std::vector<uint64_t> I = convert_to_nal(i, n_, m_);
        Exponent f_i(uint64_t(1));
        for(int j = 0; j < m_; ++j)
            f_i *= f[(j)*n_ + I[j]];
        exp.push_back(f_i);
    }

    GroupElement t1;
    c.get_vector_multiple(exp, t1);
    GroupElement t2;
    for(int k = 0; k < m_; ++k){
        t2 += (Gk[k] * (x.exponent(uint64_t(k)))).inverse();
    }
    GroupElement left(t1 + t2);
    GroupElement cc = commits[l];
    /*for(int i = 0; i < N; ++i){
        if(i == l)
            cc += commits[i] * Exponent(uint64_t(1));
        else
            cc += commits[i] * Exponent(uint64_t(0));
    }*/

    Exponent x_m = x.exponent(m_);

    cc *= x_m;
    if(left==cc)
        std::cout<< "Sax chotki ancav"<< std::endl;


}

}//namespace sigma