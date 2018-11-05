
#include <libzerocoin/sigma/SigmaPlusProver.h>
#include <libzerocoin/sigma/SigmaPlusVerifier.h>
#include <chrono>
#include <ctime>

void test( int N, int n, int index){
    int m = (int)(log(N) / log(n));;
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    std::random_device rd;
    std::mt19937 rand(rd());
    for(int i = 0; i < N; ++i){
        if(i == index){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);

        }
        else{
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize(rand);
        }
    }

    std::clock_t proof_start = std::clock();

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof;
    prover.proof(commits, index, r, proof);
    std::cout <<"N = " << N << " n = " << n << "m = " <<m;
    std::cout << " Proof size  " << proof.memoryRequired() ;

    auto duration_clock = ( std::clock() - proof_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Proof time  " << duration_clock << " ms ";



    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);
    std::clock_t verify_start = std::clock();
    verifier.verify(commits, proof);

    duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Verify time  " <<  duration_clock << " ms \n";
}

int main(){
    test(16384, 4, 0);
    test(32768, 8, 0);
    test(65536, 4, 0);
    test(65536, 16, 0);
    test(262144, 8, 0);
    test(262144, 64, 0);
	return 0;
}