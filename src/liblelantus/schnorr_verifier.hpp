namespace lelantus {

template<class Exponent, class GroupElement>
SchnorrVerifier<Exponent, GroupElement>::SchnorrVerifier(const GroupElement& g, const GroupElement& h):
        g_(g), h_(h) {
}

template<class Exponent, class GroupElement>
bool SchnorrVerifier<Exponent, GroupElement>::verify(
        const GroupElement& y,
        const SchnorrProof<Exponent, GroupElement>& proof){

    const GroupElement& u = proof.u;
    Exponent c;
    std::vector<GroupElement> group_elements = {u};
    LelantusPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, c);
    const Exponent P1 = proof.P1;
    const Exponent T1 = proof.T1;

    if(!(u.isMember()) || !(y.isMember()) || !(P1.isMember()) || !(T1.isMember()))
        return false;

    GroupElement right = y * c + g_ * P1 + h_ * T1;
    if(u == right) {
        return true;
    }

    return false;
}

}//namespace lelantus