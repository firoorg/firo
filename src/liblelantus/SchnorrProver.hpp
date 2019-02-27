namespace lelantus {

template<class Exponent, class GroupElement>
SchnorrProver<Exponent, GroupElement>::SchnorrProver(const GroupElement& g, const GroupElement& h):
    g_(g), h_(h) {
}

template<class Exponent, class GroupElement>
void SchnorrProver<Exponent, GroupElement>::proof(
        const Exponent& P,
        const Exponent& T,
        SchnorrProof<Exponent, GroupElement>& proof_out){
    Exponent P0;
    Exponent T0;
    P0.randomize();
    T0.randomize();
    GroupElement u = LelantusPrimitives<Exponent, GroupElement>::commit(g_,P0, h_, T0);
    proof_out.u = u;
    Exponent c;
    LelantusPrimitives<Exponent, GroupElement>::get_c(u, c);
    proof_out.P1 = P0 - c * P;
    proof_out.T1 = T0 - c * T;
}

}//namespace lelantus