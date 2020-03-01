#include <chrono>
#include <ctime>
#include "../range_prover.h"
#include "../range_verifier.h"

void test(uint64_t n, uint64_t m, secp_primitives::Scalar& v){
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();
    //creating generators g, h vectors
    std::vector <secp_primitives::GroupElement> g_;
    std::vector <secp_primitives::GroupElement> h_;
    for (int i = 0; i < n * m; ++i) {
        secp_primitives::GroupElement g;
        secp_primitives::GroupElement h;
        g.randomize();
        g_.push_back(g);
        h.randomize();
        h_.push_back(h);
    }

    std::vector<secp_primitives::Scalar> v_s, serials, randoms;
    std::vector<secp_primitives::GroupElement> V;
    for(int j = 0; j < m; ++j){
        secp_primitives::Scalar v(uint64_t(701+j)), random, serial;
        random.randomize();
        serial.randomize();
        v_s.push_back(v);
        randoms.push_back(random);
        serials.push_back(serial);
        V.push_back(g_gen * v +  h_gen1 * random + h_gen2 * serial);
    }

    std::clock_t proof_start = std::clock();
    lelantus::RangeProver<secp_primitives::Scalar, secp_primitives::GroupElement> rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n);
    lelantus::RangeProof<secp_primitives::Scalar, secp_primitives::GroupElement> proof;
    rangeProver.batch_proof(v_s, serials, randoms, proof);
    std::cout << "n = " << n << "m = " << m;
    std::cout << " Proof size  " << proof.memoryRequired(n, m) ;

    auto duration_clock = ( std::clock() - proof_start );
    std::cout << " Proof time  " << duration_clock << " μs ";


    lelantus::RangeVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n);
    std::clock_t verify_start = std::clock();
    rangeVerifier.verify_batch(V, proof);
    duration_clock = ( std::clock() - verify_start );
    std::cout << " Fast Verify time  " <<  duration_clock << " μs " << std::endl;
}

int main(){
    {
        secp_primitives::Scalar v(uint64_t(17));
        uint64_t n = 32;
        uint64_t m = 2;
        test(n, m, v);
    }
    {
        secp_primitives::Scalar v(uint64_t(1777));
        uint64_t n = 64;
        uint64_t m = 4;
        test(n, m, v);
    }
    return 0;
}
