#include "schnorr_verifier.h"
#include "challenge_generator_impl.h"

namespace lelantus {
    
SchnorrVerifier::SchnorrVerifier(const GroupElement& g, const GroupElement& h, bool withFixes_):
        g_(g), h_(h), withFixes(withFixes_) {
}

bool SchnorrVerifier::verify(
        const GroupElement& y,
        const GroupElement& a,
        const GroupElement& b,
        const SchnorrProof& proof,
        unique_ptr<ChallengeGenerator>& challengeGenerator){

    const GroupElement& u = proof.u;
    Scalar c;
    std::vector<GroupElement> group_elements = {u};

    std::string shts = "";
    if (withFixes) {
        shts = "SCHNORR_PROOF";
        std::vector<unsigned char> pre(shts.begin(), shts.end());
        group_elements = {u, y, a, b};
        challengeGenerator->add(pre);
    } else {
        challengeGenerator.reset(new ChallengeGeneratorImpl<CSHA256>());
    }
    challengeGenerator->add(group_elements);
    challengeGenerator->get_challenge(c);

    const Scalar P1 = proof.P1;
    const Scalar T1 = proof.T1;

    if (!(u.isMember() && y.isMember() && P1.isMember() && T1.isMember()) ||
        u.isInfinity() || y.isInfinity() || P1.isZero() || T1.isZero())
        return false;

    GroupElement right = y * c + g_ * P1 + h_ * T1;
    if (u == right) {
        return true;
    }

    return false;
}

bool SchnorrVerifier::verify(
        const GroupElement& y,
        const std::vector<GroupElement>& groupElements,
        const SchnorrProof& proof){

    const GroupElement& u = proof.u;
    Scalar c;

    ChallengeGeneratorImpl<CHash256> challengeGenerator;
    std::string shts = "SCHNORR_PROOF";
    std::vector<unsigned char> pre(shts.begin(), shts.end());
    challengeGenerator.add(pre);
    challengeGenerator.add(groupElements);
    challengeGenerator.add(u);

    challengeGenerator.get_challenge(c);

    const Scalar P1 = proof.P1;
    const Scalar T1 = proof.T1;

    if (!(u.isMember() && y.isMember() && P1.isMember() && T1.isMember()) ||
        u.isInfinity() || y.isInfinity() || P1.isZero() || T1.isZero())
        return false;

    GroupElement right = y * c + g_ * P1 + h_ * T1;
    if (u == right) {
        return true;
    }

    return false;
}

}//namespace lelantus