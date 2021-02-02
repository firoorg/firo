#ifndef FIRO_SIGMA_R1_PROOF_GENERATOR_H
#define FIRO_SIGMA_R1_PROOF_GENERATOR_H

#include "r1_proof.h"
#include "sigma_primitives.h"

namespace sigma {

template <class Exponent, class GroupElement>
class R1ProofGenerator{

public:
    R1ProofGenerator(const GroupElement& g,
                     const std::vector<GroupElement>& h_gens,
                     const std::vector<Exponent>& b,
                     const Exponent& r,
                     int n,
                     int m);

    // Returns commitment B.
    const GroupElement& get_B() const;

    /** \brief Generates r1 proof by randomly selecting the values of vector a. 
     *  \param[out] proof_out - R1 proof generated.
     *  \param[in] skip_final_response If set to true, will only generate the initial message of the proof.
     */
    void proof(R1Proof<Exponent, GroupElement>& proof_out, bool skip_final_response = false);

    /** \brief Generates R1 proof, which proves that the given matrix b of size n*m contains bits, and for each row exactly 1 bit is set to 1.
     *  \param[out] a_out - List of randomly generated scalars. These values are used in the rest of sigma proof.
     *  \param[out] proof_out - R1 proof generated.
     *  \param[in] skip_final_response If set to true, will only generate the initial message of the proof.
     */
    void proof(std::vector<Exponent>& a_out,
               R1Proof<Exponent, GroupElement>& proof_out,
               bool skip_final_response = false);

    /** \brief Finishes generation of R1 proof, the part after receiving the challenge x.
     *  \param[in] a - List of randomly generated scalars. These values are used in the rest of sigma proof.
     *  \param[in] challenge_x Value of challenge X.
     *  \param[out] proof_out - R1 proof generated.
     */
    void generate_final_response(const std::vector<Exponent>& a,
                                 const Exponent& challenge_x,
                                 R1Proof<Exponent, GroupElement>& proof_out);
private:

    Exponent rA_;
    Exponent rC_;
    Exponent rD_;

    // Generators for the commitment. Size of h_ must be n*m.
    const GroupElement& g_;
    const std::vector<GroupElement>& h_;

    // n*m values of a matrix describing index l of the coin being spent.
    // Each value in this vector is a bit, I.E. 0 or 1.
    std::vector<Exponent> b_;
    
    // Randomness of commitment B_Commit.
    Exponent r;
    
    // Main commitment B for the [nxm] matrix of b_.
    GroupElement B_Commit;

    // Size of the matrix for commitment. Number of coins N < n^m.
    int n_;
    int m_;

};

} // namespace sigma

#include "r1_proof_generator.hpp"

#endif // FIRO_SIGMA_R1_PROOF_GENERATOR_H
