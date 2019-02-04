#include <chrono>
#include <ctime>
#include <nextgen/RangeProver.h>
#include <nextgen/RangeVerifier.h>

void test(uint64_t n, secp_primitives::Scalar& v){
    std::vector<secp_primitives::GroupElement> g_, h_;
    secp_primitives::GroupElement g_gen, h_gen;
    g_gen.randomize();
    h_gen.randomize();
    g_.resize(n);
    h_.resize(n);
    for(int i = 0; i < n; ++i){
        g_[i].randomize();
        h_[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();

    std::clock_t proof_start = std::clock();
    nextgen::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen, g_, h_, n);
    nextgen::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    rangeProver.proof(v, r, proof);

    std::cout << "n = " << n ;
    std::cout << " Proof size  " << proof.memoryRequired(n) ;

    auto duration_clock = ( std::clock() - proof_start );
    std::cout << " Proof time  " << duration_clock << " μs ";

    secp_primitives::GroupElement V = g_gen * v +  h_gen * r;

    std::clock_t verify_start = std::clock();
    nextgen::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen, g_, h_, n);
    rangeVerifier.verify(V, proof);
    duration_clock = ( std::clock() - verify_start );
    std::cout << " Verify time  " <<  duration_clock;

    verify_start = std::clock();
    rangeVerifier.verify_fast(V, proof);
    duration_clock = ( std::clock() - verify_start );
    std::cout << " Fast Verify time  " <<  duration_clock << " μs ";

    verify_start = std::clock();
    rangeVerifier.verify_optimised(V, proof);
    duration_clock = ( std::clock() - verify_start );
    std::cout << " Optimised Verify time  " <<  duration_clock << " μs \n";

}

int main(){
    {
        secp_primitives::Scalar v(uint64_t(17));
        uint64_t n = 32;
        test(n, v);
    }
    {
        secp_primitives::Scalar v(uint64_t(1777));
        uint64_t n = 64;
        test(n, v);
    }
    return 0;
}
