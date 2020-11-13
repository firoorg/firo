#ifndef ZCOIN_BIP47PAYMENTCODE_H
#define ZCOIN_BIP47PAYMENTCODE_H
#include "bip47/utils.h"
#include "base58.h"
#include "crypto/hmac_sha512.h"
#include <boost/optional.hpp>

namespace bip47 {

static const unsigned int BIP47_INDEX = 47;

class CPaymentCode {
public:
    CPaymentCode();
    CPaymentCode(std::string const & paymentCode);
    CPaymentCode(CPubKey const & pubKey, ChainCode const & chainCode);

    std::vector<unsigned char> getPayload() const;

    CBitcoinAddress notificationAddress() const;
    CBitcoinAddress getNthAddress(int idx) const;

    CExtPubKey getNthPubkey(int idx) const;
    CExtPubKey const & getChildPubKey0() const;

    CPubKey const & getPubKey() const;
    ChainCode const & getChainCode() const;

    string toString() const;

    static std::vector<unsigned char> getMask(std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint);
    static std::vector<unsigned char> blind(std::vector<unsigned char> payload, std::vector<unsigned char> mask);

    bool isValid() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(valid);
        if(!valid)
            return;
        READWRITE(pubKey);
        READWRITE(chainCode);
    }

private:
    bool valid;
    CPubKey pubKey;
    ChainCode  chainCode;
   
    bool parse(std::string const & paymentCode);
    string makeV1();
    string makeV2();
    string make(int version);

    static std::vector<unsigned char> vector_xor(std::vector<unsigned char> a, std::vector<unsigned char> b);

    mutable boost::optional<CExtPubKey> childPubKey0;
};

bool operator==(CPaymentCode const & lhs, CPaymentCode const & rhs);

}

#endif // ZCOIN_BIP47PAYMENTCODE_H
