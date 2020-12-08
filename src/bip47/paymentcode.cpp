
#include "bip47/paymentcode.h"
#include "bip47/utils.h"
#include "util.h"

namespace bip47 {

namespace {
const size_t PUBLIC_KEY_Y_OFFSET = 2;
const size_t PUBLIC_KEY_X_OFFSET = 3;
const size_t CHAIN_OFFSET = 35;
const size_t PUBLIC_KEY_X_LEN = 32;
const size_t PUBLIC_KEY_Y_LEN = 1;
const size_t PUBLIC_KEY_COMPRESSED_LEN = PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN;
const size_t CHAIN_CODE_LEN = 32;
const size_t PAYLOAD_LEN = 80;
const size_t PAYMENT_CODE_LEN = PAYLOAD_LEN + 1; // (0x47("P") | payload)
const unsigned char THE_P = 0x47; //"P"
}

CPaymentCode::CPaymentCode ()
:valid(false)
{}

CPaymentCode::CPaymentCode (std::string const & paymentCode)
{
    valid = parse(paymentCode);
    if(!valid) {
        throw std::runtime_error("Cannot parse the payment code.");
    }

}

CPaymentCode::CPaymentCode (CPubKey const & pubKey, ChainCode const & chainCode)
:  valid(true), pubKey(pubKey), chainCode(chainCode)
{
    if(!pubKey.IsValid() || chainCode.IsNull()) {
        throw std::runtime_error("Cannot initialize the payment code with invalid data.");
    }
}

bool CPaymentCode::isValid() const {
    return valid;
}

CBitcoinAddress CPaymentCode::getNotificationAddress() const
{
    return CBitcoinAddress(getNthPubkey(0).pubkey.GetID());
}

CBitcoinAddress CPaymentCode::getNthAddress(size_t idx) const
{
    return CBitcoinAddress(getNthPubkey(idx).pubkey.GetID());
}

std::vector<unsigned char> CPaymentCode::getPayload() const
{
    std::vector<unsigned char> payload;
    payload.reserve(PAYLOAD_LEN);

    payload.push_back(1);
    payload.push_back(0);
    std::copy(pubKey.begin(), pubKey.begin() + pubKey.size(), std::back_inserter(payload));
    std::copy(chainCode.begin(), chainCode.begin() + chainCode.size(), std::back_inserter(payload));

    if(payload.size() != 67) {
        throw std::runtime_error("Payload construction failed");
    }

    while(payload.size() < PAYLOAD_LEN) {
        payload.push_back(0);
    }

    return payload;
}

CPubKey const & CPaymentCode::getPubKey() const
{
    return pubKey;
}

ChainCode const & CPaymentCode::getChainCode() const
{
    return chainCode;
}

std::string CPaymentCode::toString() const
{
    std::vector<unsigned char> pc, pl = getPayload();
    pc.reserve(1 + PAYLOAD_LEN);
    pc.push_back(THE_P);
    pc.insert(pc.end(), pl.begin(), pl.end());
    return EncodeBase58Check(pc);
}

bool CPaymentCode::parse(std::string const & paymentCode)
{
    std::vector<unsigned char> pcBytes;
    if (!DecodeBase58Check(paymentCode, pcBytes))
        return error("Cannot Base58-decode the payment code");

    if(pcBytes.size() != PAYMENT_CODE_LEN)
        return error("Payment code lenght is invalid");

    if ( pcBytes[0] != THE_P ) {
        return error("invalid payment code version");
    }
    pubKey.Set(pcBytes.begin() + PUBLIC_KEY_X_OFFSET, pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN);
    if ( pubKey[0] != 2 && pubKey[0] != 3 ) {
        return error("invalid public key");
    }
    std::copy(pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN, pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN + PUBLIC_KEY_X_LEN, chainCode.begin());
    return true;
}


CExtPubKey CPaymentCode::getNthPubkey(size_t idx) const
{
    CExtPubKey result;
    getChildPubKeyBase().Derive(result, idx);
    result.nChild = idx;
    result.nDepth = 4;
    return result;
}

CExtPubKey const & CPaymentCode::getChildPubKeyBase() const {
    if(!childPubKeyBase) {
        childPubKeyBase.emplace();
        childPubKeyBase->pubkey = pubKey;
        childPubKeyBase->chaincode = chainCode;
    }
    return *childPubKeyBase;
}

bool operator==(CPaymentCode const & lhs, CPaymentCode const & rhs) {
    if(lhs.isValid() != rhs.isValid())
        return false;
    if(!lhs.isValid() && !rhs.isValid())
        return true;
    if(lhs.getPubKey() != rhs.getPubKey())
        return false;
    return lhs.getChainCode() == rhs.getChainCode();
}

}
