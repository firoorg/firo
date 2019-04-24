#ifndef ADDRESSTYPE_H
#define ADDRESSTYPE_H

enum struct AddressType
{
      unknown = 0
    , payToPubKeyHash = 1
    , payToScriptHash = 2
    , zerocoinMint = 3
    , zerocoinSpend = 4
    , sigmaMint = 5
    , sigmaSpend = 6
};

namespace zerocoin { namespace utils {

inline bool isZerocoinMint(std::string const & str){
    return str == "Zeromint" || str == "zeromint";
}

inline bool isZerocoinSpend(std::string const & str){
    return str == "Zerospend";
}

inline bool isZerocoin(std::string const & str){
    return str == "Zerocoin";
}

inline bool isSigmaMint(std::string const & str){
    return str == "Sigmamint";
}

inline bool isSigmaSpend(std::string const & str){
    return str == "Sigmaspend";
}

inline bool isSigma(std::string const & str){
    return str == "Sigma";
}

}}
#endif /* ADDRESSTYPE_H */

