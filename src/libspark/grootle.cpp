#include "grootle.h"
#include "transcript.h"

namespace spark {

// Useful scalar constants
const Scalar ZERO = Scalar(uint64_t(0));
const Scalar ONE = Scalar(uint64_t(1));
const Scalar TWO = Scalar(uint64_t(2));

Grootle::Grootle(
        const GroupElement& H_,
        const std::vector<GroupElement>& Gi_,
        const std::vector<GroupElement>& Hi_,
        const std::size_t n_,
        const std::size_t m_)
        : H (H_)
        , Gi (Gi_)
        , Hi (Hi_)
        , n (n_)
        , m (m_)
{
    if (!(n > 1 && m > 1)) {
        throw std::invalid_argument("Bad Grootle size parameters!");
    }
    if (Gi.size() != n*m || Hi.size() != n*m) {
        throw std::invalid_argument("Bad Grootle generator size!");
    }
}

// Compute a delta function vector
static inline std::vector<Scalar> convert_to_sigma(std::size_t num, const std::size_t n, const std::size_t m) {
    std::vector<Scalar> result;
    result.reserve(n*m);

    for (std::size_t j = 0; j < m; j++) {
        for (std::size_t i = 0; i < n; i++) {
            if (i == (num % n)) {
                result.emplace_back(ONE);
            } else {
                result.emplace_back(ZERO);
            }
        }
        num /= n;
    }

    return result;
}

// Decompose an integer with arbitrary base and padded size
static inline std::vector<std::size_t> decompose(std::size_t num, const std::size_t n, const std::size_t m) {
    std::vector<std::size_t> result;
    result.reserve(m);

    while (num != 0) {
        result.emplace_back(num % n);
        num /= n;
    }
    result.resize(m);

    return result;
}

// Compute a double Pedersen vector commitment
static inline GroupElement vector_commit(const std::vector<GroupElement>& Gi, const std::vector<GroupElement>& Hi, const std::vector<Scalar>& a, const std::vector<Scalar>& b, const GroupElement& H, const Scalar& r) {
    if (Gi.size() != a.size() || Hi.size() != b.size()) {
        throw std::runtime_error("Vector commitment size mismatch!");
    }
    return secp_primitives::MultiExponent(Gi, a).get_multiple() + secp_primitives::MultiExponent(Hi, b).get_multiple() + H*r;
}

// Compute a convolution with a degree-one polynomial
static inline void convolve(const Scalar& x_1, const Scalar& x_0, std::vector<Scalar>& coefficients) {
    if (coefficients.empty()) {
        throw std::runtime_error("Empty convolution coefficient vector!");
    }

    std::size_t degree = coefficients.size() - 1;
    coefficients.emplace_back(x_1*coefficients[degree]);
    for (std::size_t i = degree; i >=1; i--) {
        coefficients[i] = x_0*coefficients[i] + x_1*coefficients[i-1];
    }
    coefficients[0] *= x_0;
}

static bool compute_fs(
        const GrootleProof& proof,
        const Scalar& x,
        std::vector<Scalar>& f_,
        const std::size_t n,
        const std::size_t m) {
    for (std::size_t j = 0; j < proof.f.size(); ++j) {
        if(proof.f[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        std::size_t k = n - 1;
        for (std::size_t i = 0; i < k; ++i)
        {
            temp += proof.f[j * k + i];
            f_.emplace_back(proof.f[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

static void compute_batch_fis(
        Scalar& f_sum,
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        const Scalar& y,
        std::vector<Scalar>::iterator& ptr,
        std::vector<Scalar>::iterator start_ptr,
        std::vector<Scalar>::iterator end_ptr,
        const std::size_t n) {
    j--;
    if (j == -1)
    {
        if(ptr >= start_ptr && ptr < end_ptr){
            *ptr++ += f_i * y;
            f_sum += f_i;
        }
        return;
    }

    Scalar t;

    for (std::size_t i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_batch_fis(f_sum, t, j, f, y, ptr, start_ptr, end_ptr, n);
    }
}

void Grootle::prove(
        const std::size_t l,
        const Scalar& s,
        const std::vector<GroupElement>& S,
        const GroupElement& S1,
        const Scalar& v,
        const std::vector<GroupElement>& V,
        const GroupElement& V1,
        const std::vector<unsigned char>& root,
        GrootleProof& proof) {
    // Check statement validity
    std::size_t N = (std::size_t) pow(n, m); // padded input size
    std::size_t size = S.size(); // actual input size
    if (l >= size) {
        throw std::invalid_argument("Bad Grootle secret index!");
    }
    if (V.size() != S.size()) {
        throw std::invalid_argument("Bad Grootle input vector sizes!");
    }
    if (size > N || size == 0) {
        throw std::invalid_argument("Bad Grootle size parameter!");
    }
    if (S[l] + S1.inverse() != H*s) {
        throw std::invalid_argument("Bad Grootle proof statement!");
    }
    if (V[l] + V1.inverse() != H*v) {
        throw std::invalid_argument("Bad Grootle proof statement!");
    }

    // Set up transcript
    Transcript transcript(LABEL_TRANSCRIPT_GROOTLE);
    transcript.add("H", H);
    transcript.add("Gi", Gi);
    transcript.add("Hi", Hi);
    transcript.add("n", Scalar(n));
    transcript.add("m", Scalar(m));
    transcript.add("root", root);
    transcript.add("S1", S1);
    transcript.add("V1", V1);

    // Compute A
    std::vector<Scalar> a;
    a.resize(n*m);
    for (std::size_t j = 0; j < m; j++) {
        for (std::size_t i = 1; i < n; i++) {
            a[j*n + i].randomize();
            a[j*n] -= a[j*n + i];
        }
    }
    std::vector<Scalar> d;
    d.resize(n*m);
    for (std::size_t i = 0; i < n*m; i++) {
        d[i] = a[i].square().negate();
    }
    Scalar rA;
    rA.randomize();
    proof.A = vector_commit(Gi, Hi, a, d, H, rA);

    // Compute B
    std::vector<Scalar> sigma = convert_to_sigma(l, n, m);
    std::vector<Scalar> c;
    c.resize(n*m);
    for (std::size_t i = 0; i < n*m; i++) {
        c[i] = a[i]*(ONE - TWO*sigma[i]);
    }
    Scalar rB;
    rB.randomize();
    proof.B = vector_commit(Gi, Hi, sigma, c, H, rB);

    // Compute convolution terms
    std::vector<std::vector<Scalar>> P_i_j;
    P_i_j.resize(size);
    for (std::size_t i = 0; i < size - 1; ++i)
    {
        std::vector<Scalar>& coefficients = P_i_j[i];
        std::vector<std::size_t> I = decompose(i, n, m);
        coefficients.push_back(a[I[0]]);
        coefficients.push_back(sigma[I[0]]);
        for (std::size_t j = 1; j < m; ++j) {
            convolve(sigma[j*n + I[j]], a[j*n + I[j]], coefficients);
        }
    }

    /*
     * To optimize calculation of sum of all polynomials indices 's' = size-1 through 'n^m-1' we use the
     * fact that sum of all of elements in each row of 'a' array is zero. Computation is done by going
     * through n-ary representation of 's' and increasing "digit" at each position to 'n-1' one by one.
     * During every step digits at higher positions are fixed and digits at lower positions go through all
     * possible combinations with a total corresponding polynomial sum of 'x^j'.
     *
     * The math behind optimization (TeX notation):
     *
     * \sum_{i=s+1}^{N-1}p_i(x) =
     *   \sum_{j=0}^{m-1}
     *     \left[
     *       \left( \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i}) \right)
     *       \left( \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k}) \right)
     *       x^j
     *     \right]
     */

    std::vector<std::size_t> I = decompose(size - 1, n, m);
    std::vector<std::size_t> lj = decompose(l, n, m);

    std::vector<Scalar> p_i_sum;
    p_i_sum.emplace_back(ONE);
    std::vector<std::vector<Scalar>> partial_p_s;

    // Pre-calculate product parts and calculate p_s(x) at the same time, put the latter into p_i_sum
    for (std::ptrdiff_t j = m - 1; j >= 0; j--) {
        partial_p_s.push_back(p_i_sum);
        convolve(sigma[j*n + I[j]], a[j*n + I[j]], p_i_sum);
    }

    for (std::size_t j = 0; j < m; j++) {
        // \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i})
        Scalar a_sum(uint64_t(0));
        for (std::size_t i = I[j] + 1; i < n; i++)
            a_sum += a[j * n + i];
        Scalar x_sum(uint64_t(lj[j] >= I[j]+1 ? 1 : 0));

        // Multiply by \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k})
        std::vector<Scalar> &polynomial = partial_p_s[m - j - 1];
        convolve(x_sum, a_sum, polynomial);

        // Multiply by x^j and add to the result
        for (std::size_t k = 0; k < m - j; k++)
            p_i_sum[j + k] += polynomial[k];
    }

    P_i_j[size - 1] = p_i_sum;

    // Perform the commitment offsets
    std::vector<GroupElement> S_offset(S);
    std::vector<GroupElement> V_offset(V);
    GroupElement S1_inverse = S1.inverse();
    GroupElement V1_inverse = V1.inverse();
    for (std::size_t k = 0; k < S_offset.size(); k++) {
        S_offset[k] += S1_inverse;
        V_offset[k] += V1_inverse;

        // Neither should be zero
        if (S_offset[k].isInfinity() || V_offset[k].isInfinity()) {
            throw std::invalid_argument("Commitment offset should not be zero");
        }
    }

    // Generate masks
    std::vector<Scalar> rho_S, rho_V;
    rho_S.resize(m);
    rho_V.resize(m);
    for (std::size_t j = 0; j < m; j++) {
        rho_S[j].randomize();
        rho_V[j].randomize();
    }

    proof.X.reserve(m);
    proof.X1.reserve(m);
    for (std::size_t j = 0; j < m; ++j)
    {
        std::vector<Scalar> P_i;
        P_i.reserve(size);
        for (std::size_t i = 0; i < size; ++i){
            P_i.emplace_back(P_i_j[i][j]);
        }
        
        // S
        secp_primitives::MultiExponent mult_S(S_offset, P_i);
        proof.X.emplace_back(mult_S.get_multiple() + H*rho_S[j]);
        
        // V
        secp_primitives::MultiExponent mult_V(V_offset, P_i);
        proof.X1.emplace_back(mult_V.get_multiple() + H*rho_V[j]);
    }

    // Challenge
    transcript.add("A", proof.A);
    transcript.add("B", proof.B);
    transcript.add("X", proof.X);
    transcript.add("X1", proof.X1);
    Scalar x = transcript.challenge("x");

    // Compute f
    proof.f.reserve(m*(n - 1));
    for (std::size_t j = 0; j < m; j++)
    {
        for (std::size_t i = 1; i < n; i++) {
            proof.f.emplace_back(sigma[(j * n) + i] * x + a[(j * n) + i]);
        }
    }

    // Compute zA, zC
    proof.z = rB * x + rA;

    // Compute zS, zV
    proof.zS = s * x.exponent(uint64_t(m));
    proof.zV = v * x.exponent(uint64_t(m));
    Scalar sumS, sumV;

    Scalar x_powers(uint64_t(1));
    for (std::size_t j = 0; j < m; ++j) {
        if (x_powers.isZero()) {
            throw std::runtime_error("Challenge power is zero");
        }
        sumS += (rho_S[j] * x_powers);
        sumV += (rho_V[j] * x_powers);
        x_powers *= x;
    }
    proof.zS -= sumS;
    proof.zV -= sumV;
}

// Verify a single proof
bool Grootle::verify(
        const std::vector<GroupElement>& S,
        const GroupElement& S1,
        const std::vector<GroupElement>& V,
        const GroupElement& V1,
        const std::vector<unsigned char>& root,
        const std::size_t size,
        const GrootleProof& proof) {
    std::vector<GroupElement> S1_batch = {S1};
    std::vector<GroupElement> V1_batch = {V1};
    std::vector<std::size_t> size_batch = {size};
    std::vector<std::vector<unsigned char>> root_batch = {root};
    std::vector<GrootleProof> proof_batch = {proof};

    return verify(S, S1_batch, V, V1_batch, root_batch, size_batch, proof_batch);
}

// Verify a batch of proofs
bool Grootle::verify(
        const std::vector<GroupElement>& S,
        const std::vector<GroupElement>& S1,
        const std::vector<GroupElement>& V,
        const std::vector<GroupElement>& V1,
        const std::vector<std::vector<unsigned char>>& roots,
        const std::vector<std::size_t>& sizes,
        const std::vector<GrootleProof>& proofs) {
    // Sanity checks
    if (n < 2 || m < 2) {
        LogPrintf("Verifier parameters are invalid");
        return false;
    }
    std::size_t M = proofs.size();
    std::size_t N = (std::size_t)pow(n, m);

    if (S.size() == 0) {
        LogPrintf("Cannot have empty commitment set");
        return false;
    }
    if (S.size() > N) {
        LogPrintf("Commitment set is too large");
        return false;
    }
    if (S.size() != V.size()) {
        LogPrintf("Commitment set sizes do not match");
        return false;
    }
    if (S1.size() != M || V1.size() != M) {
        LogPrintf("Invalid number of offsets provided");
        return false;
    }
    if (sizes.size() != M) {
        LogPrintf("Invalid set size vector size");
        return false;
    }
    if (roots.size() != M) {
        LogPrintf("Invalid root vector size");
        return false;
    }

    // Check for zero inputs
    for (std::size_t t = 0; t < S1.size(); t++) {
        for (std::size_t i = 0; i < S.size(); i++) {
            if (S[i] == S1[t] || V[i] == V1[t]) {
                LogPrintf("Invalid offset commitment");
                return false;
            }
        }
    }

    // Check proof semantics
    for (std::size_t t = 0; t < M; t++) {
        GrootleProof proof = proofs[t];
        if (proof.X.size() != m || proof.X1.size() != m) {
            LogPrintf("Bad proof vector size!");
            return false;
        }
        if (proof.f.size() != m*(n-1)) {
            LogPrintf("Bad proof vector size!");
            return false;
        }
    }

    // Commitment binding weight; intentionally restricted range for efficiency, but must be nonzero
    // NOTE: this may initialize with a PRNG, which should be sufficient for this use
    std::random_device generator;
    std::uniform_int_distribution<uint16_t> distribution;
    Scalar bind_weight(ZERO);
    while (bind_weight == ZERO) {
        bind_weight = Scalar(distribution(generator));
    }

    // Bind the commitment lists
    std::vector<GroupElement> commits;
    commits.reserve(S.size());
    for (std::size_t i = 0; i < S.size(); i++) {
        commits.emplace_back(S[i] + V[i]*bind_weight);
    }

    // Final batch multiscalar multiplication
    Scalar H_scalar;
    std::vector<Scalar> Gi_scalars;
    std::vector<Scalar> Hi_scalars;
    std::vector<Scalar> commit_scalars;
    Gi_scalars.resize(n*m);
    Hi_scalars.resize(n*m);
    commit_scalars.resize(commits.size());

    // Set up the final batch elements
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    std::size_t final_size = 1 + 2*m*n + commits.size(); // F, (Gi), (Hi), (commits)
    for (std::size_t t = 0; t < M; t++) {
        final_size += 2 + proofs[t].X.size() + proofs[t].X1.size(); // A, B, (Gs), (Gv)
    }
    points.reserve(final_size);
    scalars.reserve(final_size);

    // Index decomposition, which is common among all proofs
    std::vector<std::vector<std::size_t> > I_;
    I_.reserve(commits.size());
    I_.resize(commits.size());
    for (std::size_t i = 0; i < commits.size(); i++) {
        I_[i] = decompose(i, n, m);
    }

    // Process all proofs
    for (std::size_t t = 0; t < M; t++) {
        GrootleProof proof = proofs[t];

        // Reconstruct the challenge
        Transcript transcript(LABEL_TRANSCRIPT_GROOTLE);
        transcript.add("H", H);
        transcript.add("Gi", Gi);
        transcript.add("Hi", Hi);
        transcript.add("n", Scalar(n));
        transcript.add("m", Scalar(m));
        transcript.add("root", roots[t]);
        transcript.add("S1", S1[t]);
        transcript.add("V1", V1[t]);
        transcript.add("A", proof.A);
        transcript.add("B", proof.B);
        transcript.add("X", proof.X);
        transcript.add("X1", proof.X1);
        Scalar x = transcript.challenge("x");

        // Generate nonzero random verifier weights (the randomization already asserts nonzero)
        Scalar w1, w2;
        w1.randomize();
        w2.randomize();

        // Reconstruct f-matrix
        std::vector<Scalar> f_;
        if (!compute_fs(proof, x, f_, n, m)) {
            LogPrintf("Invalid matrix reconstruction");
            return false;
        }

        // Effective set size
        const std::size_t size = sizes[t];

        // A, B (and associated commitments)
        points.emplace_back(proof.A);
        scalars.emplace_back(w1.negate());
        points.emplace_back(proof.B);
        scalars.emplace_back(x.negate() * w1);

        H_scalar += proof.z * w1;
        for (std::size_t i = 0; i < m * n; i++) {
            Gi_scalars[i] += f_[i] * w1;
            Hi_scalars[i] += f_[i]*(x - f_[i]) * w1;
        }

        // Input sets
        H_scalar += (proof.zS + bind_weight * proof.zV) * w2.negate();

        Scalar f_sum;
        Scalar f_i(uint64_t(1));
        std::vector<Scalar>::iterator ptr = commit_scalars.begin() + commits.size() - size;
        compute_batch_fis(f_sum, f_i, m, f_, w2, ptr, ptr, ptr + size - 1, n);

        Scalar pow(uint64_t(1));
        std::vector<Scalar> f_part_product;
        for (std::ptrdiff_t j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[j*n + I_[size - 1][j]];
        }

        Scalar x_powers(uint64_t(1));
        for (std::size_t j = 0; j < m; j++) {
            Scalar fi_sum(uint64_t(0));
            for (std::size_t i = I_[size - 1][j] + 1; i < n; i++)
                fi_sum += f_[j*n + i];
            pow += fi_sum * x_powers * f_part_product[m - j - 1];
            x_powers *= x;
        }

        f_sum += pow;
        commit_scalars[commits.size() - 1] += pow * w2;

        // S1, V1
        points.emplace_back(S1[t] + V1[t] * bind_weight);
        scalars.emplace_back(f_sum * w2.negate());

        // (X), (X1)
        x_powers = Scalar(uint64_t(1));
        for (std::size_t j = 0; j < m; j++) {
            if (x_powers.isZero()) {
                LogPrintf("Challenge power is zero");
                return false;
            }
            points.emplace_back(proof.X[j] + proof.X1[j] * bind_weight);
            scalars.emplace_back(x_powers.negate() * w2);
            x_powers *= x;
        }
    }

    // Add common generators
    points.emplace_back(H);
    scalars.emplace_back(H_scalar);
    for (std::size_t i = 0; i < m * n; i++) {
        points.emplace_back(Gi[i]);
        scalars.emplace_back(Gi_scalars[i]);
        points.emplace_back(Hi[i]);
        scalars.emplace_back(Hi_scalars[i]);
    }
    for (std::size_t i = 0; i < commits.size(); i++) {
        points.emplace_back(commits[i]);
        scalars.emplace_back(commit_scalars[i]);
    }

    // Verify the batch
    secp_primitives::MultiExponent result(points, scalars);
    if (result.get_multiple().isInfinity()) {
        return true;
    }
    return false;
}

}