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
        throw std::invalid_argument("Bad Type statement!");
    }
    for (std::size_t i = 0; i < n; i++) {
        if (E * w + F * x + G * y[i] + H * z[i] != C[i]) {
            throw std::invalid_argument("Bad Type statement!");
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
    GroupElement tempC2;
    const std::size_t n = C.size();
    const Scalar c = challenge(C, proof.A, proof.B);
    Scalar c_power(c);
    const GroupElement check1 = (proof.A + C[0] * c) + (E * proof.tw + F * proof.tx + G * proof.ty + H * proof.tz).inverse();
    for (std::size_t i = 1; i < n; i++) {
        tempC2 += (C[i] + C[0].inverse()) * c_power;
        c_power *= c;
    }
    const GroupElement check2 = (proof.B + tempC2) + (G * proof.uy + H * proof.uz).inverse();

    return check1.isInfinity() && check2.isInfinity();
}


} // namespace spats