#include "type.h"
#include "transcript.h"

namespace spats
{

TypeEquality::TypeEquality(const GroupElement& E_, const GroupElement& F_, const GroupElement& G_, const GroupElement& H_) : E(E_), F(F_), G(G_), H(H_)
{
}
Scalar TypeEquality::challenge(
    const std::vector<GroupElement>& C,
    const GroupElement& A,
    const GroupElement& B)
{
    Transcript transcript(LABEL_TRANSCRIPT_TYPE);
    transcript.add("E", E);
    transcript.add("F", F);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("C", C);
    transcript.add("A", A);
    transcript.add("B", B);

    return transcript.challenge("c");
}

void TypeEquality::prove(const GroupElement& C, const Scalar& w, const Scalar& x, const Scalar& y, const Scalar& z, TypeProof& proof)
{
    const std::vector<Scalar> y_vector = {y};
    const std::vector<Scalar> z_vector = {z};
    const std::vector<GroupElement> C_vector = {C};
    prove(C_vector, w, x, y_vector, z_vector, proof);
}

void TypeEquality::prove(const std::vector<GroupElement>& C, const Scalar& w, const Scalar& x, const std::vector<Scalar>& y, const std::vector<Scalar>& z, TypeProof& proof)
{
    const std::size_t n = y.size();

    // Check statement validity
    if (y.size() != z.size()) {
        throw std::invalid_argument("Bad Type statement!1");
    }


    for (std::size_t i = 0; i < n; i++) {
               if (E * w + F * x + G * y[i] + H * z[i] != C[i]) {
            throw std::invalid_argument("Bad Type statement!2");
        }
    }
    Scalar rw;
    Scalar rx;
    Scalar ry;
    Scalar rz;
    Scalar sy;
    Scalar sz;
    Scalar tempUy;
    Scalar tempUz;

    rw.randomize();
    rx.randomize();
    ry.randomize();
    rz.randomize();
    sy.randomize();
    sz.randomize();

    proof.A = E * rw + F * rx + G * ry + H * rz;
    proof.B = G * sy + H * sz;

    const Scalar c = challenge(C, proof.A, proof.B);
    Scalar c_power(c);

    // c_power must be nonzero
    if (c_power.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }

    proof.tw = rw + c * w;
    proof.tx = rx + c * x;
    proof.ty = ry + c * y[0];
    proof.tz = rz + c * z[0];
    for (std::size_t i = 1; i < n; i++) {
        tempUy += c_power * (y[i] - y[0]);
        tempUz += c_power * (z[i] - z[0]);
        c_power *= c;
    }
    proof.uy = sy + tempUy;
    proof.uz = sz + tempUz;
}

bool TypeEquality::verify(const GroupElement& C, const TypeProof& proof)
{
    const std::vector<GroupElement> C_vector = {C};
    return verify(C_vector, proof);
}

bool TypeEquality::verify(const std::vector<GroupElement>& C, const TypeProof& proof)
{
    // GroupElement tempC2;
    const std::size_t n = C.size();
    
    // std::vector<GroupElement> points;
    // points.reserve(n + 2);
    // std::vector<Scalar> scalars;
    // scalars.reserve(n + 2);

    const Scalar c = challenge(C, proof.A, proof.B);
    // c must be nonzero
    if (c.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }
    // Scalar c_power(c);
    const GroupElement check1 = (proof.A + C[0] * c) + (E * proof.tw + F * proof.tx + G * proof.ty + H * proof.tz).inverse();
    // for (std::size_t i = 1; i < n; i++) {
    //     // c_power must be nonzero
    //     if (c_power.isZero()) {
    //         throw std::invalid_argument("Unexpected challenge!");
    //     }
    //     tempC2 += (C[i] + C[0].inverse()) * c_power;
    //     c_power *= c;
    // }
    // const GroupElement check2 = (proof.B + tempC2) + (G * proof.uy + H * proof.uz).inverse();

    // equation 1
    // tw * E + tx * F + ty * G + tz * H = A + c * C0
    std::vector<Scalar> scalars_eq_1;
    scalars_eq_1.reserve(6);
    std::vector<GroupElement> points_eq_1;
    points_eq_1.reserve(6);

    scalars_eq_1.emplace_back(Scalar(uint64_t(1)));
    scalars_eq_1.emplace_back(c);
    scalars_eq_1.emplace_back(proof.tw);
    scalars_eq_1.emplace_back(proof.tx);
    scalars_eq_1.emplace_back(proof.ty);
    scalars_eq_1.emplace_back(proof.tz);
    
    points_eq_1.emplace_back(proof.A);
    points_eq_1.emplace_back(C[0]);
    points_eq_1.emplace_back(E.inverse());
    points_eq_1.emplace_back(F.inverse());
    points_eq_1.emplace_back(G.inverse());
    points_eq_1.emplace_back(H.inverse());

    // equation 2
    // uy * G + uz * H = B + \sum_{i=1}^{n-1}{ c^i * (C_i - C_0) }
    std::vector<Scalar> scalars_eq_2;
    scalars_eq_2.reserve(n + 2);
    std::vector<GroupElement> points_eq_2;
    points_eq_2.reserve(n + 2);

    Scalar c_power(c);
    for (std::size_t i = 1; i < n; i++) {
        // c_power must be nonzero
        if (c_power.isZero()) {
            throw std::invalid_argument("Unexpected challenge!");
        }
        scalars_eq_2.emplace_back(c_power);
        points_eq_2.emplace_back(C[i] + C[0].inverse());
        
        // tempC2 += (C[i] + C[0].inverse()) * c_power;
        c_power *= c;
    }

    scalars_eq_2.emplace_back(1);
    scalars_eq_2.emplace_back(proof.uy);
    scalars_eq_2.emplace_back(proof.uz);
    
    points_eq_2.emplace_back(proof.B);
    points_eq_2.emplace_back(G.inverse());
    points_eq_2.emplace_back(H.inverse());

    // const GroupElement check2 = (proof.B + tempC2) + (G * proof.uy + H * proof.uz).inverse();

    MultiExponent result_eq_1(points_eq_1, scalars_eq_1);
    MultiExponent result_eq_2(points_eq_2, scalars_eq_2);
    // return result.get_multiple().isInfinity();

    return result_eq_1.get_multiple().isInfinity() && result_eq_2.get_multiple().isInfinity();
    // return check1.isInfinity() && check2.isInfinity();
}


} // namespace spats