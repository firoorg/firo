#include "range_verifier.h"
#include "challenge_generator_sha256.h"
#include "challenge_generator_hash256.h"
#include "chainparams.h"

namespace lelantus {
    
RangeVerifier::RangeVerifier(
        const GroupElement& g,
        const GroupElement& h1,
        const GroupElement& h2,
        const std::vector<GroupElement>& g_vector,
        const std::vector<GroupElement>& h_vector,
        uint64_t n)
        : g (g)
        , h1 (h1)
        , h2 (h2)
        , g_(g_vector)
        , h_(h_vector)
        , n (n)
{}

bool RangeVerifier::verify_batch(const std::vector<GroupElement>& V, const std::vector<GroupElement>& commitments, const RangeProof& proof) {
    if(!membership_checks(proof))
        return false;
    uint64_t m = V.size();

    //computing challenges
    Scalar x, x_u, y, z;
    bool afterFixes = chainActive.Height() > ::Params().GetConsensus().nLelantusFixesStartBlock;
    unique_ptr<ChallengeGenerator> challengeGenerator;
    if (afterFixes) {
        challengeGenerator = std::make_unique<ChallengeGeneratorHash256>();
        std::string domain_separator = "RANGE_PROOF";
        std::vector<unsigned char> pre(domain_separator.begin(), domain_separator.end());
        challengeGenerator->add(pre);
        challengeGenerator->add(commitments);
    }  else {
        challengeGenerator = std::make_unique<ChallengeGeneratorSha256>();
    }
    challengeGenerator->add({proof.A, proof.S});
    challengeGenerator->get_challenge(y);
    challengeGenerator->get_challenge(z);

    challengeGenerator->add({proof.T1, proof.T2});
    challengeGenerator->get_challenge(x);
    Scalar x_neg = x.negate();

    challengeGenerator->add({proof.T_x1, proof.T_x2, proof.u});
    challengeGenerator->get_challenge(x_u);

    auto log_n = RangeProof::int_log2(n * m);
    const InnerProductProof& innerProductProof = proof.innerProductProof;
    std::vector<Scalar> x_j, x_j_inv;
    x_j.resize(log_n);
    x_j_inv.reserve(log_n);
    for (int i = 0; i < log_n; ++i)
    {
        std::vector<GroupElement> group_elements_i = {innerProductProof.L_[i], innerProductProof.R_[i]};

        if (afterFixes) {
            std::string domain_separator = "INNER_PRODUCT";
            std::vector<unsigned char> pre(domain_separator.begin(), domain_separator.end());
            challengeGenerator->add(pre);
        } else {
            challengeGenerator.reset();
        }

        challengeGenerator->add(group_elements_i);
        challengeGenerator->get_challenge(x_j[i]);
        x_j_inv.emplace_back((x_j[i].inverse()));
    }

    Scalar z_square_neg = (z.square()).negate();
    Scalar delta = LelantusPrimitives::delta(y, z, n, m);

    //check line 97
    GroupElement V_z;
    NthPower z_m(z);
    for (std::size_t j = 0; j < m; ++j)
    {
        V_z += V[j] * (z_square_neg * z_m.pow);
        z_m.go_next();
    }

    std::vector<Scalar> l_r;
    l_r.resize(n * m * 2);
    NthPower y_n_(y.inverse());
    NthPower z_j(z, z.square());

    NthPower two_n_(uint64_t(2));
    std::vector<Scalar> two_n;
    two_n.reserve(n);
    for (uint64_t k = 0; k < n; ++k)
    {
        two_n.emplace_back(two_n_.pow);
        two_n_.go_next();
    }

    for (uint64_t t = 0; t < m ; ++t)
    {
        for (uint64_t k = 0; k < n; ++k)
        {
            uint64_t i = t * n + k;
            Scalar x_il(uint64_t(1));
            Scalar x_ir(uint64_t(1));
            for (int j = 0; j < log_n; ++j)
            {
                if ((i >> j) & 1) {
                    x_il *= x_j[log_n - j - 1];
                    x_ir *= x_j_inv[log_n - j - 1];
                } else {
                    x_il *= x_j_inv[log_n - j - 1];
                    x_ir *= x_j[log_n - j - 1];
                }

            }
            l_r[i] = x_il * innerProductProof.a_ + z;
            l_r[n * m + i] = y_n_.pow * (x_ir * innerProductProof.b_ - (z_j.pow * two_n[k])) - z;
            y_n_.go_next();
        }
        z_j.go_next();
    }

    //check lines  98 and 105
    Scalar c;
    c.randomize();

    std::vector<GroupElement> points;
    points.insert(points.end(), g_.begin(), g_.end());
    points.insert(points.end(), h_.begin(), h_.end());
    std::vector<Scalar> exponents(l_r);

    points.emplace_back(g);
    exponents.emplace_back((innerProductProof.c_ - delta) * c + x_u *  (innerProductProof.a_ * innerProductProof.b_ - innerProductProof.c_));
    points.emplace_back(h1);
    exponents.emplace_back(proof.T_x1 * c + proof.u);
    points.emplace_back(h2);
    exponents.emplace_back(proof.T_x2 * c);
    points.emplace_back(proof.A);
    exponents.emplace_back(Scalar(uint64_t(1)).negate());
    points.emplace_back(V_z);
    exponents.emplace_back(c);
    points.emplace_back(proof.T1);
    exponents.emplace_back(x_neg * c);
    points.emplace_back(proof.T2);
    exponents.emplace_back((x.square()).negate() * c);
    points.emplace_back(proof.S);
    exponents.emplace_back(x_neg);

    std::vector<Scalar> x_j_sq_neg;
    x_j_sq_neg.resize(2 * log_n);
    for (int j = 0; j < log_n; ++j)
    {
        x_j_sq_neg[j] = x_j[j].square().negate();
        x_j_sq_neg[log_n + j] = x_j_inv[j].square().negate();
    }

    points.insert(points.end(), innerProductProof.L_.begin(), innerProductProof.L_.end());
    points.insert(points.end(), innerProductProof.R_.begin(), innerProductProof.R_.end());
    exponents.insert(exponents.end(), x_j_sq_neg.begin(), x_j_sq_neg.end());

    secp_primitives::MultiExponent mult(points, exponents);

    //checking whether the result is equal to 1 (in elliptic curve it is infinity)
    if(!mult.get_multiple().isInfinity())
        return false;
    return true;
}

bool RangeVerifier::membership_checks(const RangeProof& proof) {
    if(!(proof.A.isMember()
         && proof.S.isMember()
         && proof.T1.isMember()
         && proof.T2.isMember()
         && proof.T_x1.isMember()
         && proof.T_x2.isMember()
         && proof.u.isMember()
         && proof.innerProductProof.a_.isMember()
         && proof.innerProductProof.b_.isMember()
         && proof.innerProductProof.c_.isMember())
         || proof.A.isInfinity()
         || proof.S.isInfinity()
         || proof.T1.isInfinity()
         || proof.T2.isInfinity()
         || proof.T_x1.isZero()
         || proof.T_x2.isZero()
         || proof.u.isZero()
         || proof.innerProductProof.a_.isZero()
         || proof.innerProductProof.b_.isZero()
         || proof.innerProductProof.c_.isZero())
        return false;

    for (std::size_t i = 0; i < proof.innerProductProof.L_.size(); ++i)
    {
        if (!(proof.innerProductProof.L_[i].isMember() && proof.innerProductProof.R_[i].isMember())
           || proof.innerProductProof.L_[i].isInfinity() || proof.innerProductProof.R_[i].isInfinity())
            return false;
    }
    return true;
}


}//namespace lelantus