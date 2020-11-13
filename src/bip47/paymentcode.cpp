
#include "bip47/paymentcode.h"
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

CBitcoinAddress CPaymentCode::notificationAddress() const
{
    return CBitcoinAddress(getChildPubKey0().pubkey.GetID());
}

CExtPubKey CPaymentCode::getNthPubkey(int idx) const
{
    CExtPubKey result;
    getChildPubKey0().Derive(result, idx);
    return result;
}

CBitcoinAddress CPaymentCode::getNthAddress(int idx) const
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

std::vector<unsigned char> CPaymentCode::getMask ( std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint )
{
    std::vector<unsigned char> mac_data ( PUBLIC_KEY_X_LEN + CHAIN_CODE_LEN );
    CHMAC_SHA512 (sPoint.data(), sPoint.size() ).Write ( oPoint.data(), oPoint.size()).Finalize (mac_data.data());
    return mac_data;
}

std::vector<unsigned char> CPaymentCode::blind ( std::vector<unsigned char> payload, std::vector<unsigned char> mask )
{
    std::vector<unsigned char> ret ( PAYLOAD_LEN );
    std::vector<unsigned char> pubkey ( PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> chaincode ( CHAIN_CODE_LEN );
    std::vector<unsigned char> buf0 ( PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> buf1 ( PUBLIC_KEY_X_LEN );
    utils::arraycopy ( payload, 0, ret, 0, PAYLOAD_LEN );
    utils::arraycopy ( payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN );
    utils::arraycopy ( payload, CHAIN_OFFSET, chaincode, 0, PUBLIC_KEY_X_LEN );
    utils::arraycopy ( mask, 0, buf0, 0, PUBLIC_KEY_X_LEN );
    utils::arraycopy ( mask, PUBLIC_KEY_X_LEN, buf1, 0, PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> temp1;
    std::vector<unsigned char> temp2;
    temp1 = vector_xor ( pubkey, buf0 );
    temp2 = vector_xor ( chaincode, buf1 );
    utils::arraycopy ( temp1, 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN );
    utils::arraycopy ( temp2, 0, ret, CHAIN_OFFSET, PUBLIC_KEY_X_LEN );
    return ret;
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

std::vector<unsigned char> CPaymentCode::vector_xor ( std::vector<unsigned char> a, std::vector<unsigned char> b )
{
    if ( a.size() != b.size() ) {
        LogPrintf ( "vector_xor a and b should have same size" );
        return std::vector<unsigned char> (0);
    } else {
        std::vector<unsigned char> ret ( a.size() );

        for ( size_t i = 0; i < a.size(); ++i ) {
            ret[i] = ( unsigned char ) ( b[i] ^ a[i] );
        }

        return ret;
    }
}

CExtPubKey const & CPaymentCode::getChildPubKey0() const {
    if(!childPubKey0) {
        CExtPubKey pktmp;
        pktmp.pubkey = pubKey;
        pktmp.chaincode = chainCode;

        childPubKey0.emplace();
        pktmp.Derive(*childPubKey0, 0);
        childPubKey0->nChild = 0;
        childPubKey0->nDepth = 3;
    }
    return *childPubKey0;
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
