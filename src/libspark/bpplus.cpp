#include "bpplus.h"
#include "transcript.h"

namespace spark {

// Useful scalar constants
const Scalar ZERO = Scalar((uint64_t) 0);
const Scalar ONE = Scalar((uint64_t) 1);
const Scalar TWO = Scalar((uint64_t) 2);
    
BPPlus::BPPlus(
        const GroupElement& G_,
        const GroupElement& H_,
        const std::vector<GroupElement>& Gi_,
        const std::vector<GroupElement>& Hi_,
        const std::size_t N_)
        : G (G_)
        , H (H_)
        , Gi (Gi_)
        , Hi (Hi_)
        , N (N_)
{
    if (Gi.size() != Hi.size()) {
        throw std::invalid_argument("Bad BPPlus generator sizes!");
    }

    // Bit length must be a nonzero power of two
    if (!is_nonzero_power_of_2(N)) {
        throw std::invalid_argument("Bad BPPlus bit length!");
    }

    // Compute 2**N-1 for optimized verification
    TWO_N_MINUS_ONE = TWO;
    for (int i = 0; i < log2(N); i++) {
        TWO_N_MINUS_ONE *= TWO_N_MINUS_ONE;
    }
    TWO_N_MINUS_ONE -= ONE;
}

// The floor function of log2
std::size_t log2(std::size_t n) {
    std::size_t l = 0;
    while ((n >>= 1) != 0) {
        l++;
    }
    
    return l;
}

// Is this value a nonzero power of 2?
bool is_nonzero_power_of_2(std::size_t n) {
    return n > 0 && (n & (n - 1)) == 0;
}

void BPPlus::prove(
        const std::vector<Scalar>& unpadded_v,
        const std::vector<Scalar>& unpadded_r,
        const std::vector<GroupElement>& unpadded_C,  
        BPPlusProof& proof) {
    // Bulletproofs+ are only defined when the input set size is a nonzero power of two
    // To get around this, we can trivially pad the input set with zero commitments
    // We make sure this is done canonically in a way that's transparent to the caller

    // Define the original and padded sizes
    std::size_t unpadded_M = unpadded_C.size();
    if (unpadded_M == 0) {
        throw std::invalid_argument("Bad BPPlus statement!1");
    }
    std::size_t M = unpadded_M;
    if (!is_nonzero_power_of_2(M)) {
        M = 1 << (log2(unpadded_M) + 1);
    }

    // Set up transcript, using the unpadded values
    // This is fine since the verifier canonically generates the same transcript
    Transcript transcript(LABEL_TRANSCRIPT_BPPLUS);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("Gi", Gi);
    transcript.add("Hi", Hi);
    transcript.add("N", Scalar(N));
    transcript.add("C", unpadded_C);

    // Now pad the input set to produce a valid statement
    std::vector<Scalar> v(unpadded_v);
    std::vector<Scalar> r(unpadded_r);
    std::vector<GroupElement> C(unpadded_C);
    for (std::size_t i = unpadded_M; i < M; i++) {
        v.emplace_back(); // zero scalar
        r.emplace_back(); // zero scalar
        C.emplace_back(); // identity group element, a valid commitment using the corresponding scalars
    }

    // Check statement validity
    if (C.size() != M) {
        throw std::invalid_argument("Bad BPPlus statement!2");
    }
    if (!is_nonzero_power_of_2(M)) {
        throw std::invalid_argument("Unexpected bad padding!3");
    }
    if (N*M > Gi.size()) {
        throw std::invalid_argument("Bad BPPlus statement!4");   
    }
    if (!(v.size() == M && r.size() == M)) {
        throw std::invalid_argument("Bad BPPlus statement!5");
    }
    for (std::size_t j = 0; j < M; j++) {
        if (!(G*v[j] + H*r[j] == C[j])) {
            throw std::invalid_argument("Bad BPPlus statement!6");
        }
    }

    // Decompose bits
    std::vector<std::vector<bool>> bits;
    bits.resize(M);
    for (std::size_t j = 0; j < M; j++) {
        v[j].get_bits(bits[j]);
    }

    // Compute aL, aR
    std::vector<Scalar> aL, aR;
    aL.reserve(N*M);
    aR.reserve(N*M);
    for (std::size_t j = 0; j < M; ++j)
    {
        for (std::size_t i = 1; i <= N; ++i)
        {
            aL.emplace_back(uint64_t(bits[j][bits[j].size() - i]));
            aR.emplace_back(Scalar(uint64_t(bits[j][bits[j].size() - i])) - ONE);
        }
    }

    // Compute A
    Scalar alpha;
    alpha.randomize();

    std::vector<GroupElement> A_points;
    std::vector<Scalar> A_scalars;
    A_points.reserve(2*N*M + 1);
    A_scalars.reserve(2*N*M + 1);

    A_points.emplace_back(H);
    A_scalars.emplace_back(alpha);
    for (std::size_t i = 0; i < N*M; i++) {
        A_points.emplace_back(Gi[i]);
        A_scalars.emplace_back(aL[i]);
        A_points.emplace_back(Hi[i]);
        A_scalars.emplace_back(aR[i]);
    }
    secp_primitives::MultiExponent A_multiexp(A_points, A_scalars);
    proof.A = A_multiexp.get_multiple();
    transcript.add("A", proof.A);

    // Challenges
    Scalar y = transcript.challenge("y");
    Scalar z = transcript.challenge("z");
    Scalar z_square = z.square();

    // Challenge powers
    std::vector<Scalar> y_powers;
    y_powers.resize(M*N + 2);
    y_powers[0] = ZERO;
    y_powers[1] = y;
    for (std::size_t i = 2; i < M*N + 2; i++) {
        y_powers[i] = y_powers[i-1]*y;
    }

    // Compute d
    std::vector<Scalar> d;
    d.resize(M*N);
    d[0] = z_square;
    for (std::size_t i = 1; i < N; i++) {
        d[i] = TWO*d[i-1];
    }
    for (std::size_t j = 1; j < M; j++) {
        for (std::size_t i = 0; i < N; i++) {
            d[j*N+i] = d[(j-1)*N+i]*z_square;
        }
    }

    // Compute aL1, aR1
    std::vector<Scalar> aL1, aR1;
    for (std::size_t i = 0; i < N*M; i++) {
        aL1.emplace_back(aL[i] - z);
        aR1.emplace_back(aR[i] + d[i]*y_powers[N*M - i] + z);
    }

    // Compute alpha1
    Scalar alpha1 = alpha;
    Scalar z_even_powers = 1;
    for (std::size_t j = 0; j < M; j++) {
        z_even_powers *= z_square;
        alpha1 += z_even_powers*r[j]*y_powers[N*M+1];
    }

    // Run the inner product rounds
    std::vector<GroupElement> Gi1(Gi);
    std::vector<GroupElement> Hi1(Hi);
    std::vector<Scalar> a1(aL1);
    std::vector<Scalar> b1(aR1);
    std::size_t N1 = N*M;

    while (N1 > 1) {
        N1 /= 2;

        Scalar dL, dR;
        dL.randomize();
        dR.randomize();

        // Compute cL, cR
        Scalar cL, cR;
        for (std::size_t i = 0; i < N1; i++) {
            cL += a1[i]*y_powers[i+1]*b1[i+N1];
            cR += a1[i+N1]*y_powers[N1]*y_powers[i+1]*b1[i];
        }

        // Compute L, R
        GroupElement L_, R_;
        std::vector<GroupElement> L_points, R_points;
        std::vector<Scalar> L_scalars, R_scalars;
        L_points.reserve(2*N1 + 2);
        R_points.reserve(2*N1 + 2);
        L_scalars.reserve(2*N1 + 2);
        R_scalars.reserve(2*N1 + 2);
        Scalar y_N1_inverse = y_powers[N1].inverse();
        for (std::size_t i = 0; i < N1; i++) {
            L_points.emplace_back(Gi1[i+N1]);
            L_scalars.emplace_back(a1[i]*y_N1_inverse);
            L_points.emplace_back(Hi1[i]);
            L_scalars.emplace_back(b1[i+N1]);

            R_points.emplace_back(Gi1[i]);
            R_scalars.emplace_back(a1[i+N1]*y_powers[N1]);
            R_points.emplace_back(Hi1[i+N1]);
            R_scalars.emplace_back(b1[i]);
        }
        L_points.emplace_back(G);
        L_scalars.emplace_back(cL);
        L_points.emplace_back(H);
        L_scalars.emplace_back(dL);
        R_points.emplace_back(G);
        R_scalars.emplace_back(cR);
        R_points.emplace_back(H);
        R_scalars.emplace_back(dR);

        secp_primitives::MultiExponent L_multiexp(L_points, L_scalars);
        secp_primitives::MultiExponent R_multiexp(R_points, R_scalars);
        L_ = L_multiexp.get_multiple();
        R_ = R_multiexp.get_multiple();
        proof.L.emplace_back(L_);
        proof.R.emplace_back(R_);

        transcript.add("L", L_);
        transcript.add("R", R_);
        Scalar e = transcript.challenge("e");
        Scalar e_inverse = e.inverse();

        // Compress round elements
        for (std::size_t i = 0; i < N1; i++) {
            Gi1[i] = Gi1[i]*e_inverse + Gi1[i+N1]*(e*y_N1_inverse);
            Hi1[i] = Hi1[i]*e + Hi1[i+N1]*e_inverse;
            a1[i] = a1[i]*e + a1[i+N1]*y_powers[N1]*e_inverse;
            b1[i] = b1[i]*e_inverse + b1[i+N1]*e;
        }
        Gi1.resize(N1);
        Hi1.resize(N1);
        a1.resize(N1);
        b1.resize(N1);

        // Update alpha1
        alpha1 = dL*e.square() + alpha1 + dR*e_inverse.square();
    }

    // Final proof elements
    Scalar r_, s_, d_, eta_;
    r_.randomize();
    s_.randomize();
    d_.randomize();
    eta_.randomize();

    proof.A1 = Gi1[0]*r_ + Hi1[0]*s_ + G*(r_*y*b1[0] + s_*y*a1[0]) + H*d_;
    proof.B = G*(r_*y*s_) + H*eta_;

    transcript.add("A1", proof.A1);
    transcript.add("B", proof.B);
    Scalar e1 = transcript.challenge("e1");

    proof.r1 = r_ + a1[0]*e1;
    proof.s1 = s_ + b1[0]*e1;
    proof.d1 = eta_ + d_*e1 + alpha1*e1.square();
}

bool BPPlus::verify(const std::vector<GroupElement>& unpadded_C, const BPPlusProof& proof) {
    std::vector<std::vector<GroupElement>> unpadded_C_batch = {unpadded_C};
    std::vector<BPPlusProof> proof_batch = {proof};

    return verify(unpadded_C_batch, proof_batch);
}

bool BPPlus::verify(const std::vector<std::vector<GroupElement>>& unpadded_C, const std::vector<BPPlusProof>& proofs) {
    // Preprocess all proofs
    if (!(unpadded_C.size() == proofs.size())) {
        return false;
    }
    std::size_t N_proofs = proofs.size();
    std::size_t max_M = 0; // maximum number of padded aggregated values across all proofs

    // Check aggregated input consistency
    for (std::size_t k = 0; k < N_proofs; k++) {
        std::size_t unpadded_M = unpadded_C[k].size();
        std::size_t M = unpadded_M;

        // Require a power of two
        if (M == 0) {
            return false;
        }
        if (!is_nonzero_power_of_2(M)) {
            M = 1 << log2(unpadded_M) + 1;
        }

        // Track the maximum value
        if (M > max_M) {
            max_M = M;
        }

        // Check inner product round consistency
        std::size_t rounds = proofs[k].L.size();
        if (proofs[k].R.size() != rounds) {
            return false;
        }
        if (log2(N*M) != rounds) {
            return false;
        }
    }

    // Check the bounds on the batch
    if (max_M*N > Gi.size() || max_M*N > Hi.size()) {
        return false;
    }

    // Set up final multiscalar multiplication and common scalars
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    Scalar G_scalar, H_scalar;

    // Interleave the Gi and Hi scalars
    for (std::size_t i = 0; i < max_M*N; i++) {
        points.emplace_back(Gi[i]);
        scalars.emplace_back(ZERO);
        points.emplace_back(Hi[i]);
        scalars.emplace_back(ZERO);
    }

    std::vector<std::vector<unsigned char>> serialized_Gi;
    serialized_Gi.resize(Gi.size());
    std::vector<std::vector<unsigned char>> serialized_Hi;
    serialized_Hi.resize(Hi.size());
    // Serialize and cash Gi and Hi vectors
    for (std::size_t i = 0; i < Gi.size(); i++) {
        serialized_Gi[i].resize(GroupElement::serialize_size);
        Gi[i].serialize(serialized_Gi[i].data());
        serialized_Hi[i].resize(GroupElement::serialize_size);
        Hi[i].serialize(serialized_Hi[i].data());
    }

    // Process each proof and add to the batch
    for (std::size_t k_proofs = 0; k_proofs < N_proofs; k_proofs++) {
        const BPPlusProof proof = proofs[k_proofs];
        const std::size_t unpadded_M = unpadded_C[k_proofs].size();
        const std::size_t rounds = proof.L.size();

        // Weight this proof in the batch
        Scalar w = ZERO;
        while (w == ZERO) {
            w.randomize();
        }

        // Set up transcript
        Transcript transcript(LABEL_TRANSCRIPT_BPPLUS);
        transcript.add("G", G);
        transcript.add("H", H);
        transcript.add("Gi", serialized_Gi);
        transcript.add("Hi", serialized_Hi);
        transcript.add("N", Scalar(N));
        transcript.add("C", unpadded_C[k_proofs]);
        transcript.add("A", proof.A);

        // Pad to a valid statement if needed
        std::size_t M = unpadded_M;
        if (!is_nonzero_power_of_2(M)) {
            M = 1 << (log2(unpadded_M) + 1);
        }
        std::vector<GroupElement> C(unpadded_C[k_proofs]);
        for (std::size_t i = unpadded_M; i < M; i++) {
            C.emplace_back();
        }

        // Get challenges
        Scalar y = transcript.challenge("y");
        if (y == ZERO) {
            return false;
        }
        Scalar y_inverse = y.inverse();
        Scalar y_NM = y;
        for (std::size_t i = 0; i < rounds; i++) {
            y_NM = y_NM.square();
        }
        Scalar y_NM_1 = y_NM*y;

        Scalar z = transcript.challenge("z");
        if (z == ZERO) {
            return false;
        }
        Scalar z_square = z.square();

        std::vector<Scalar> e;
        std::vector<Scalar> e_inverse;
        for (std::size_t j = 0; j < rounds; j++) {
            transcript.add("L", proof.L[j]);
            transcript.add("R", proof.R[j]);
            Scalar e_ = transcript.challenge("e");
            if (e_ == ZERO) {
                return false;
            }
            e.emplace_back(e_);
            e_inverse.emplace_back(e[j].inverse());
        }

        transcript.add("A1", proof.A1);
        transcript.add("B", proof.B);
        Scalar e1 = transcript.challenge("e1");
        if (e1 == ZERO) {
            return false;
        }
        Scalar e1_square = e1.square();

        // C_j: -e1**2 * z**(2*(j + 1)) * y**(N*M + 1) * w
        Scalar C_scalar = e1_square.negate()*z_square*y_NM_1*w;
        for (std::size_t j = 0; j < M; j++) {
            points.emplace_back(C[j]);
            scalars.emplace_back(C_scalar);

            C_scalar *= z.square();
        }

        // B: -w
        points.emplace_back(proof.B);
        scalars.emplace_back(w.negate());

        // A1: -w*e1
        points.emplace_back(proof.A1);
        scalars.emplace_back(w.negate()*e1);

        // A: -w*e1**2
        points.emplace_back(proof.A);
        scalars.emplace_back(w.negate()*e1_square);

        // H: w*d1
        H_scalar += w*proof.d1;

        // Compute d
        std::vector<Scalar> d;
        d.resize(N*M);
        d[0] = z_square;
        for (std::size_t i = 1; i < N; i++) {
            d[i] = d[i-1] + d[i-1];
        }
        for (std::size_t j = 1; j < M; j++) {
            for (std::size_t i = 0; i < N; i++) {
                d[j*N + i] = d[(j - 1)*N + i]*z_square;
            }
        }

        // Sum the elements of d
        Scalar sum_d = z_square;
        Scalar temp_z = sum_d;
        std::size_t temp_2M = 2*M;
        while (temp_2M > 2) {
            sum_d += sum_d*temp_z;
            temp_z = temp_z.square();
            temp_2M /= 2;
        }
        sum_d *= TWO_N_MINUS_ONE;

        // Sum the powers of y
        Scalar sum_y;
        Scalar track = y;
        for (std::size_t i = 0; i < N*M; i++) {
            sum_y += track;
            track *= y;
        }

        // G: w*(r1*y*s1 + e1**2*(y**(N*M + 1)*z*sum_d + (z**2-z)*sum_y))
        G_scalar += w*(proof.r1*y*proof.s1 + e1_square*(y_NM_1*z*sum_d + (z_square - z)*sum_y));

        // Track some iterated exponential terms
        Scalar iter_y_inv = ONE; // y.inverse()**i
        Scalar iter_y_NM = y_NM; // y**(N*M - i)

        // Gi, Hi
        for (std::size_t i = 0; i < N*M; i++) {
            Scalar g = proof.r1*e1*iter_y_inv;
            Scalar h = proof.s1*e1;
            for (std::size_t j = 0; j < rounds; j++) {
                if ((i >> j) & 1) {
                    g *= e[rounds-j-1];
                    h *= e_inverse[rounds-j-1];
                } else {
                    h *= e[rounds-j-1];
                    g *= e_inverse[rounds-j-1];
                }
            }

            // Gi
            scalars[2*i] += w*(g + e1_square*z);
            
            // Hi
            scalars[2*i+1] += w*(h - e1_square*(d[i]*iter_y_NM+z));

            // Update the iterated values
            iter_y_inv *= y_inverse;
            iter_y_NM *= y_inverse;
        }

        // L, R
        for (std::size_t j = 0; j < rounds; j++) {
            points.emplace_back(proof.L[j]);
            scalars.emplace_back(w*(e1_square.negate()*e[j].square()));
            points.emplace_back(proof.R[j]);
            scalars.emplace_back(w*(e1_square.negate()*e_inverse[j].square()));
        }
    }

    // Add the common generators
    points.emplace_back(G);
    scalars.emplace_back(G_scalar);
    points.emplace_back(H);
    scalars.emplace_back(H_scalar);

    // Test the batch
    secp_primitives::MultiExponent multiexp(points, scalars);
    return multiexp.get_multiple().isInfinity();
}

}