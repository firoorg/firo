#ifndef FIRO_SPARK_HASH_H
#define FIRO_SPARK_HASH_H

#include <span>

#include <openssl/evp.h>

#include "util.h"

namespace spark {

using namespace secp_primitives;

class Hash {
public:
   explicit Hash( const std::string &label );
   ~Hash();
   void include( const CDataStream &data );
   void include( std::span< const unsigned char > data );
   std::vector< unsigned char > finalize();
   Scalar finalize_scalar();
   GroupElement finalize_group();

private:
   void include_size( std::size_t size );
   EVP_MD_CTX *ctx;
};

}   // namespace spark

#endif
