#ifndef ZCOIN_BIP47PAYMENTCODE_H
#define ZCOIN_BIP47PAYMENTCODE_H
#include "base58.h"
#include "crypto/hmac_sha512.h"
#include <boost/optional.hpp>

namespace bip47 {

class CPaymentCode {
public:
    CPaymentCode() = default;
    CPaymentCode(std::string const & paymentCode);
    CPaymentCode(CPubKey const & pubKey, ChainCode const & chainCode);

    std::vector<unsigned char> getPayload() const;
    std::vector<unsigned char> getMaskedPayload(COutPoint const & outPoint);

    CBitcoinAddress getNotificationAddress() const;
    CBitcoinAddress getNthAddress(size_t idx) const;

    CExtPubKey getNthPubkey(size_t idx) const;

    CPubKey const & getPubKey() const;
    ChainCode const & getChainCode() const;

    std::string toString() const;

    static bool validate(std::string const & paymentCode);

    ADD_DESERIALIZE_CTOR(CPaymentCode);
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(pubKey);
        READWRITE(chainCode);
    }
CExtPubKey const & getChildPubKeyBase() const;
private:
    CPubKey pubKey;
    ChainCode  chainCode;

    boost::optional<CBitcoinAddress> mutable myNotificationAddress;
    mutable boost::optional<CExtPubKey> childPubKeyBase;

    bool parse(std::string const & paymentCode);
};

bool operator==(CPaymentCode const & lhs, CPaymentCode const & rhs);

//accNum, pcode, label, notificationAddress
typedef std::tuple<size_t, CPaymentCode, std::string, CBitcoinAddress> CPaymentCodeDescription;

}

#endif // ZCOIN_BIP47PAYMENTCODE_H
