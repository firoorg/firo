#include <libzerocoin/sigma/SigmaPlusProver.h>

int main(){
    int N = 30000;
    int n = 4;
    int index = 22300;

    int m = (int)(log(N) / log(n));

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    for(int i = 0; i < n * m; ++i ){
        h_gens.push_back(secp_primitives::GroupElement());
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    std::random_device rd;
    std::mt19937 rand(rd());
    for(int i = 0; i < N; ++i){
        if(i == (index)){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = g * zero + h_gens[0] * r;
            commits.push_back(c);

        }
        else{
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize(rand);
        }
    }

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof;

    prover.proof(commits, index, r, proof);

    std:: cout<<"Size of Proof is "<< proof.debug_size() << "   \n";
}