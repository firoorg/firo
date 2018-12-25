#include <nextgen/SigmaPlusProver.h>
#include <nextgen/SigmaPlusVerifier.h>
#include <chrono>
#include <ctime>

#include <fstream>

void generate_batch_proofs(
        const secp_primitives::GroupElement& g,
        const std::vector<secp_primitives::GroupElement>& h_gens,
        int N, int n, int m, int M,
        std::vector<secp_primitives::GroupElement>& commits,
        secp_primitives::Scalar& x,
        std::vector<secp_primitives::Scalar>& serials,
        std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>>& proofs){

    nextgen::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);
    int M_ = M;
    std::vector<secp_primitives::Scalar> v_;
    std::vector<secp_primitives::Scalar> r_;
    std::vector<int> indexes;
    for(int i = 0; i < N; ++i){
        if(M_){
            secp_primitives::Scalar s, r;
            s.randomize();
            serials.push_back(s);
            r.randomize();
            r_.push_back(r);
            secp_primitives::Scalar v(1);
            v_.push_back(v);
            indexes.push_back(i);

            secp_primitives::GroupElement c;
            c = nextgen::NextGenPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::double_commit(g, s, h_gens[0], v, h_gens[1], r);
            commits.push_back(c);
            --M_;
        }
        else{
            secp_primitives::GroupElement elem;
            elem.randomize();
            commits.push_back(elem);
        }
    }

    proofs.reserve(serials.size());

    std::vector<secp_primitives::Scalar> rA, rB, rC, rD;
    rA.resize(N);
    rB.resize(N);
    rC.resize(N);
    rD.resize(N);
    std::vector<std::vector<secp_primitives::Scalar>> sigma;
    sigma.resize(N);
    std::vector<std::vector<secp_primitives::Scalar>> Tk, Pk;
    Tk.resize(N);
    Pk.resize(N);
    std::vector<std::vector<secp_primitives::Scalar>> a;
    a.resize(N);

    for(int i = 0; i < serials.size(); ++i){
        nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof;
        proofs.push_back(proof);
        std::vector<secp_primitives::GroupElement> commits_;
        secp_primitives::GroupElement gs = g * serials[i].negate();
        for(int j = 0; j < commits.size(); ++j){
            GroupElement c_ = commits[j] + gs ;
            commits_.push_back(c_);
        }
        rA[i].randomize();
        rB[i].randomize();
        rC[i].randomize();
        rD[i].randomize();
        Tk[i].resize(m);
        Pk[i].resize(m);
        a[i].resize(n * m);
        prover.sigma_commit(commits_, indexes[i], rA[i], rB[i], rC[i], rD[i], a[i], Tk[i], Pk[i], sigma[i], proofs[i]);
    }
    nextgen::NextGenPrimitives<Scalar, GroupElement>::get_x(proofs, x);

    for(int i = 0; i < serials.size(); ++i)
        prover.sigma_response(sigma[i], a[i], rA[i], rB[i], rC[i], rD[i], v_[i], r_[i], Tk[i], Pk[i], x, proofs[i]);
}

void test_batch(int N, int n, int M)
{
    int m = (int)(log(N) / log(n));
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    std::vector<secp_primitives::GroupElement> commits;
    std::vector<secp_primitives::Scalar> serials;
    secp_primitives::Scalar x;
    std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>> proofs;

    generate_batch_proofs(g, h_gens, N, n, m, M, commits, x, serials, proofs);

    nextgen::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);


    std::clock_t verify_start = std::clock();

    std::cout << " Passed " << verifier.batchverify(commits, x, serials, proofs) <<std::endl;

    std::cout <<" N = " << N << " n = " << n << " m = " <<m <<" M = "<<M;
    auto  duration_clock = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Verify time  " <<  duration_clock << " ms \n";
}

template <class T>
void write(const std::vector<T>& obj, const std::string& path){
    int size = obj[0].memoryRequired() * obj.size();
    unsigned char buffer[size];
    unsigned char* current = buffer;
    for(int i = 0; i < obj.size(); ++i)
        current = obj[i].serialize(current);
    FILE* out = fopen(path.c_str(), "wb");
    fwrite (buffer , sizeof(unsigned char), sizeof(buffer), out);
    for(int i = 0; i < sizeof(unsigned char) * sizeof(buffer); ++i)
        std::putc(buffer[i], out);
    fclose(out);
}

void write_proofs(const std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>>& proofs, const std::string& path) {
    int size = proofs[0].memoryRequired() * proofs.size();
    unsigned char buffer[size];
    unsigned char* current = buffer;
    for (int i = 0; i < proofs.size(); ++i)
        current = proofs[i].serialize(current);
    FILE* out = fopen(path.c_str(), "wb");
    fwrite(buffer, sizeof(unsigned char), sizeof(buffer), out);
    for (int i = 0; i < sizeof(unsigned char) * sizeof(buffer); ++i)
        std::putc(buffer[i], out);
    fclose(out);
}

void read_proofs(const std::string& path,int  n, int m, int M, std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>>& proofs_) {
    nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof;
    int size = proof.memoryRequired(n, m) * M;
    unsigned char buffer[size];
    FILE* in = fopen(path.c_str(), "rb");
    for(int i = 0; i < sizeof(unsigned char) * size; ++i)
        buffer[i] = std::getc(in);
    fclose(in);

    unsigned  char* current = buffer;
    for(int i = 0; i < M; ++i) {
        nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> p;
        current = p.deserialize(current, n, m);
        proofs_.push_back(p);
    }
}

template <class T>
void read(const std::string& path, int size, std::vector<T>& obj) {
    obj.resize(size);
    unsigned char buffer[obj[0].memoryRequired() * size];
    FILE* in = fopen(path.c_str(), "rb");
    for(int i = 0; i < sizeof(unsigned char) * sizeof(buffer); ++i)
        buffer[i] = std::getc(in);
    unsigned char* current = buffer;
    for(int i = 0; i < size; ++i)
        current = obj[i].deserialize(current);
    fclose(in);
}

void get_params(int n, int m, secp_primitives::GroupElement& g_, std::vector<secp_primitives::GroupElement>& h_){
    g_ = secp_primitives::GroupElement("9216064434961179932092223867844635691966339998754536116709681652691785432045",
                                       "33986433546870000256104618635743654523665060392313886665479090285075695067131");
    secp_primitives::GroupElement h("50204771751011461524623624559944050110546921468100198079190811223951215371253",
                                    "71960464583475414858258501028406090652116947054627619400863446545880957517934");

    h_.reserve(n * m);

    h_.push_back(h);
    for(int i = 1; i < n*m; ++i) {
        GroupElement temp;
        h_.push_back(temp);
        unsigned char buff[32] = {0};
        h_[i - 1].sha256(buff);
        h_[i].generate(buff);
    }
}

void create_write_proofs(int N, int n, int M)
{
    int m = (int)(log(N) / log(n));
    secp_primitives::GroupElement g;
    std::vector<secp_primitives::GroupElement> h_;
    get_params(n, m, g, h_);

    std::vector<secp_primitives::GroupElement> commits;
    std::vector<secp_primitives::Scalar> serials;
    secp_primitives::Scalar x;
    std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>> proofs;

    generate_batch_proofs(g, h_, N, n, m, M, commits, x, serials, proofs);

    std::string path_proofs = "src/gtest/" + std::to_string(N) + "proofs.txt";
    write_proofs(proofs, path_proofs);

    std::string path_commits = "src/gtest/" + std::to_string(N) + "commits.txt";
    write(commits, path_commits);

    std::string path_serials = "src/gtest/" + std::to_string(N) + "serials.txt";
    write(serials, path_serials);

    std::string path_x = "src/gtest/" +  std::to_string(N) + "x.txt";
    unsigned char buffer_x[x.memoryRequired()];
    x.serialize(buffer_x);
    FILE* out_x = fopen(path_x.c_str(), "wb");
    for(int i = 0; i < x.memoryRequired(); ++i)
        std::putc(buffer_x[i], out_x);
    fclose(out_x);
}

void read_batch_verify(int N, int n, int M){

    int m = (int)(log(N) / log(n));
    secp_primitives::GroupElement g;
    std::vector<secp_primitives::GroupElement> h_;
    get_params(n, m, g, h_);

    std::clock_t serialize_start = std::clock();
    std::vector<nextgen::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>> proofs;
    std::string path_proofs = "src/gtest/" + std::to_string(N) + "proofs.txt";
    read_proofs(path_proofs, n, m, M, proofs);

    std::vector<secp_primitives::GroupElement> commits;
    std::string path_commits = "src/gtest/" + std::to_string(N) + "commits.txt";
    read(path_commits, N, commits);

    std::vector<secp_primitives::Scalar> serials;
    std::string path_serials = "src/gtest/" + std::to_string(N) + "serials.txt";
    read(path_serials, M, serials);


    secp_primitives::Scalar x;
    unsigned char buffer_x[x.memoryRequired()];
    std::string path_x = "src/gtest/" + std::to_string(N) + "x.txt";
    FILE* in_x = fopen(path_x.c_str(), "r");
    for(int i = 0; i < x.memoryRequired(); ++i)
        buffer_x[i] = std::getc(in_x);
    fclose(in_x);
    x.deserialize(buffer_x);

    nextgen::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_, n, m);


    std::clock_t verify_start = std::clock();

    std::cout <<" Passed " << verifier.batchverify(commits, x, serials, proofs) << std::endl;
    std::cout <<" N = " << N << " n = " << n << " m = " <<m <<" M = "<<M;
    auto  duration_clock_verify = ( std::clock() - verify_start ) / (CLOCKS_PER_SEC / 1000);
    auto  duration_clock_serialize = ( std::clock() - serialize_start ) / (CLOCKS_PER_SEC / 1000);
    std::cout << " Verify time  " <<  duration_clock_verify << " With serialize "<< duration_clock_serialize <<" ms \n";

}

int main(){
//batch verify
//    test_batch(16384, 4, 5);
//    test_batch(16384, 4, 10);
//    test_batch(16384, 4, 50);
//    test_batch(16384, 4, 100);
//    test_batch(16384, 4, 500);
//    test_batch(16384, 4, 1000);
//    test_batch(32768, 8, 5);
//    test_batch(32768, 8, 10);
//    test_batch(32768, 8, 50);
//    test_batch(32768, 8, 100);
//    test_batch(32768, 8, 500);
//    test_batch(32768, 8, 1000);
//    test_batch(65536, 4, 5);
//    test_batch(65536, 4, 10);
//    test_batch(65536, 4, 50);
//    test_batch(65536, 4, 100);
//    test_batch(65536, 4, 500);
//    test_batch(65536, 4, 1000);
//    test_batch(65536, 16, 5);
//    test_batch(65536, 16, 10);
//    test_batch(65536, 16, 50);
//    test_batch(65536, 16, 100);
//    test_batch(65536, 16, 500);
//    test_batch(65536, 16, 1000);
//    test_batch(262144, 8, 5);
//    test_batch(262144, 8, 10);
//    test_batch(262144, 8, 50);
//    test_batch(262144, 8, 100);
//    test_batch(262144, 8, 500);
//    test_batch(262144, 8, 1000);


/// write proofs
    create_write_proofs(16384, 4, 1000);
//    create_write_proofs(32768, 8,1000);
//    create_write_proofs(65536, 4,1000);
//    create_write_proofs(65536, 16,1000);
//    create_write_proofs(262144, 8,1000);
////load from file and batch verify
//    read_batch_verify(16384, 4,1000);
    return 0;
}
