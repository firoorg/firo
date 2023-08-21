#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/grootle.h"
#include "../../libspark/grootle_proof.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    size_t n = fdp.ConsumeIntegral<size_t>();
    size_t m = fdp.ConsumeIntegral<size_t>();
    size_t N = (size_t) std::pow(n, m);

    GroupElement H;
    std::vector<GroupElement> Gi = fsp.GetGroupElements(n*m);
    std::vector<GroupElement> Hi = fsp.GetGroupElements(n*m);

    size_t commit_size = fdp.ConsumeIntegral<size_t>();
    std::vector<GroupElement> S = fsp.GetGroupElements(commit_size);
    std::vector<GroupElement> V = fsp.GetGroupElements(commit_size);

    std::vector<uint8_t> indexes = fdp.ConsumeBytes<uint8_t>(len);
    std::vector<size_t> sizes;
    sizes.resize(len);
    for(size_t i=0; i < len; i++) {
        sizes[i] = fdp.ConsumeIntegral<size_t>();
    }
    std::vector<GroupElement> S1, V1;
    std::vector<std::vector<unsigned char>> roots;
    std::vector<Scalar> s, v;
    for (std::size_t index : indexes) {
        Scalar s_, v_;
        s_ = fsp.GetScalar();
        v_ = fsp.GetScalar();
        s.emplace_back(s_);
        v.emplace_back(v_);

        S1.emplace_back(S[index]);
        V1.emplace_back(V[index]);

        S[index] += H*s_;
        V[index] += H*v_;

        Scalar temp;
        temp = fsp.GetScalar();
        std::vector<unsigned char> root;
        root.reserve(spark::SCALAR_ENCODING);
        temp.serialize(root.data());
        roots.emplace_back(root);
    }

    spark::Grootle grootle(H, Hi, Hi, n, m);
    std::vector<spark::GrootleProof> proofs;

    for (size_t i=0; i < indexes.size(); i++) {
        proofs.emplace_back();
        std::vector<GroupElement> S_(S.begin() + commit_size - sizes[i], S.end());
        std::vector<GroupElement> V_(V.begin() + commit_size - sizes[i], V.end());

        grootle.prove(
            indexes[i] - (commit_size - sizes[i]),
            s[i],
            S_,
            S1[i],
            v[i],
            V_,
            V1[i],
            roots[i],
            proofs.back()

        );

        assert(grootle.verify(S, S1[i], V, V1[i], roots[i], sizes[i], proofs.back()));
    }

    assert(grootle.verify(S, S1, V, V1, roots, sizes, proofs));

    // Add an invalid proof
    proofs.emplace_back(proofs.back());
    S1.emplace_back(S1.back());
    V1.emplace_back(V1.back());
    S1.back().randomize();
    sizes.emplace_back(sizes.back());
    assert(!grootle.verify(S, S1, V, V1, roots, sizes, proofs));

    return 0;

}