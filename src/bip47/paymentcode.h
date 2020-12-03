#ifndef ZCOIN_BIP47PAYMENTCODE_H
#define ZCOIN_BIP47PAYMENTCODE_H
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
    std::vector<unsigned char> getMaskedPayload(COutPoint const & outPoint);

    CBitcoinAddress getNotificationAddress() const;
    CBitcoinAddress getNthAddress(int idx) const;

    CExtPubKey getNthPubkey(size_t idx) const;

    CPubKey const & getPubKey() const;
    ChainCode const & getChainCode() const;

    std::string toString() const;

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
    CExtPubKey const & getChildPubKeyBase() const;
   
    bool parse(std::string const & paymentCode);

    static std::vector<unsigned char> vector_xor(std::vector<unsigned char> a, std::vector<unsigned char> b);

    mutable boost::optional<CExtPubKey> childPubKeyBase;
};

bool operator==(CPaymentCode const & lhs, CPaymentCode const & rhs);

}

#endif // ZCOIN_BIP47PAYMENTCODE_H
