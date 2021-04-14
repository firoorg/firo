
#include "bip47/paymentcode.h"
#include "bip47/utils.h"
#include "util.h"

namespace bip47 {

namespace {
const size_t PUBLIC_KEY_Y_OFFSET = 2;
const size_t PUBLIC_KEY_X_OFFSET = 3;
const size_t PUBLIC_KEY_X_LEN = 32;
const size_t PUBLIC_KEY_COMPRESSED_LEN = 33;
const size_t CHAIN_CODE_LEN = 32;
const size_t PAYLOAD_LEN = 80;
const size_t PAYMENT_CODE_LEN = PAYLOAD_LEN + 1; // (0x47("P") | payload)
const unsigned char THE_P = 0x47; //"P"
}

CPaymentCode::CPaymentCode (std::string const & paymentCode)
{
    if (!parse(paymentCode)) {
        throw std::runtime_error("Cannot parse the payment code.");
    }
}

CPaymentCode::CPaymentCode (CPubKey const & pubKey, ChainCode const & chainCode)
: pubKey(pubKey), chainCode(chainCode)
{
    if (!pubKey.IsValid() || chainCode.IsNull()) {
        throw std::runtime_error("Cannot initialize the payment code with invalid data.");
    }
}

CBitcoinAddress CPaymentCode::getNotificationAddress() const
{
    if (!myNotificationAddress)
        myNotificationAddress.emplace(getNthPubkey(0).pubkey.GetID());
    return *myNotificationAddress;
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

    if (payload.size() != 67) {
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

namespace {
bool validateImpl(std::string const & paymentCode, CPubKey & pubKey, ChainCode & chainCode) {
    std::vector<unsigned char> pcBytes;
    if (!DecodeBase58Check(paymentCode, pcBytes))
        return error("Cannot Base58-decode the payment code");

    if (pcBytes.size() != PAYMENT_CODE_LEN)
        return error("Payment code lenght is invalid");

    if ( pcBytes[0] != THE_P ) {
        return error("invalid payment code version");
    }
    pubKey.Set(pcBytes.begin() + PUBLIC_KEY_X_OFFSET, pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN);
    if (!pubKey.IsValid())
        return false;
    std::copy(pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN, pcBytes.begin() + PUBLIC_KEY_X_OFFSET + PUBLIC_KEY_COMPRESSED_LEN + PUBLIC_KEY_X_LEN, chainCode.begin());
    if (chainCode.IsNull())
        return false;
    return true;
}
}

bool CPaymentCode::parse(std::string const & paymentCode)
{
    return validateImpl(paymentCode, pubKey, chainCode);
}

bool CPaymentCode::validate(std::string const & paymentCode)
{
    CPubKey pubkey;
    ChainCode chaincode;
    return validateImpl(paymentCode, pubkey, chaincode);
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
    if (!childPubKeyBase) {
        childPubKeyBase.emplace();
        childPubKeyBase->pubkey = pubKey;
        childPubKeyBase->chaincode = chainCode;
    }
    return *childPubKeyBase;
}

bool operator==(CPaymentCode const & lhs, CPaymentCode const & rhs) {
    if (lhs.getPubKey() != rhs.getPubKey())
        return false;
    return lhs.getChainCode() == rhs.getChainCode();
}

}
