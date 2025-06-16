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
    , zerocoinRemint = 7
    , lelantusMint = 8
    , lelantusJMint = 9
    , lelantusJSplit = 10
    , sparkMint = 11
    , sparksMint = 12
    , sparkSpend = 13
    , payToExchangeAddress = 14
    , spatsMint = 15
    , spatsSpend = 16
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

inline bool isZerocoinRemint(std::string const & str){
    return str == "Remint";
}

inline bool isLelantus(std::string const & str){
    return str == "Lelantus";
}

inline bool isLelantusMint(std::string const & str){
    return str == "Lelantusmint";
}

inline bool isLelantusJMint(std::string const & str){
    return str == "Lelantusjmint";
}

inline bool isLelantusJSplit(std::string const & str){
    return str == "Lelantusjsplit";
}

inline bool isSpark(std::string const & str){
    return str == "Spark";
}

inline bool isSparkMint(std::string const & str){
    return str == "Sparkmint";
}

inline bool isSparkSMint(std::string const & str){
    return str == "Sparksmint";
}

inline bool isSparkSpend(std::string const & str){
    return str == "Sparkspend";
}

inline bool isSpatsMint(std::string const & str){
    return str == "Spatsmint";
}

inline bool isSpatsSpend(std::string const & str){
    return str == "SpatsSpend";
}

}}
#endif /* ADDRESSTYPE_H */

