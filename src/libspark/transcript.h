#ifndef FIRO_SPARK_TRANSCRIPT_H
#define FIRO_SPARK_TRANSCRIPT_H
#include <openssl/evp.h>
#include "util.h"

namespace spark {

using namespace secp_primitives;

class Transcript {
public:
    Transcript(const std::string);
    Transcript& operator=(const Transcript&);
    ~Transcript();
    void add(const std::string, const Scalar&);
    void add(const std::string, const std::vector<Scalar>&);
    void add(const std::string, const GroupElement&);
    void add(const std::string, const std::vector<GroupElement>&);
    void add(const std::string, const std::vector<unsigned char>&);
    Scalar challenge(const std::string);

private:
    void size(const std::size_t size_);
    void include_flag(const unsigned char);
    void include_label(const std::string);
    void include_data(const std::vector<unsigned char>&);
    EVP_MD_CTX* ctx;
};

}

#endif
