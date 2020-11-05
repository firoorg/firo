
#include "bip47/paymentcode.h"
#include "bip47/channeladdress.h"
#include "util.h"

namespace bip47 {

CPaymentCode::CPaymentCode () : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
}
CPaymentCode::CPaymentCode (std::string payment_code) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    strPaymentCode = payment_code;
    valid = parse();
}

CPaymentCode::CPaymentCode (unsigned char* payload, int length) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    if ( length == PAYLOAD_LEN ) {
        utils::arraycopy ( payload, PUBLIC_KEY_Y_OFFSET, pubkey, 0, PUBLIC_KEY_COMPRESSED_LEN );
        utils::arraycopy ( payload, CHAIN_OFFSET, chaincode, 0, PUBLIC_KEY_X_LEN );
        strPaymentCode = makeV1();
        valid = parse();
    }
}

CPaymentCode::CPaymentCode (std::vector<unsigned char> const & v_pubkey, std::vector<unsigned char> const & v_chaincode) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    if(v_pubkey.size() < PUBLIC_KEY_COMPRESSED_LEN || v_chaincode.size() < CHAIN_CODE_LEN) {
        throw std::invalid_argument("v_pubkey or v_chaincode is too short");
    }
    utils::arraycopy ( v_pubkey.data(),0,pubkey,0,PUBLIC_KEY_COMPRESSED_LEN );
    utils::arraycopy ( v_chaincode.data(),0,chaincode, 0, PUBLIC_KEY_X_LEN );
    strPaymentCode = makeV1();
    valid = parse();
}

CChannelAddress CPaymentCode::notificationAddress()
{
    return addressAt (0);
}

CChannelAddress CPaymentCode::addressAt ( int idx ) const
{
    CExtPubKey key;
    if ( !createMasterPubKeyFromPaymentCode ( strPaymentCode,key ) ) {
        LogPrintf ( "CPaymentCode::addressAt is failed idx = %d \n",idx );
        LogPrintf ( "CChannelAddress CPaymentCode::addressAt.\n" );

    }
    return CChannelAddress ( key, idx );
}

std::vector<unsigned char> CPaymentCode::getPayload() const
{
    std::vector<unsigned char> pcBytes;
    if ( !DecodeBase58Check ( strPaymentCode,pcBytes ) ) {
        LogPrintf ( "CPaymentCode::getPayload is failed in DecodeBase58Check\n" );
        return std::vector<unsigned char> (0);

    }

    std::vector<unsigned char> payload ( PAYLOAD_LEN );
    utils::arraycopy ( pcBytes, 1, payload, 0, payload.size() );
    return payload;
}

int CPaymentCode::getVersion()
{
    std::vector<unsigned char> payload = getPayload();
    unsigned char version = payload[0];
    return version;
}

std::vector<unsigned char> CPaymentCode::decode()
{
    std::vector<unsigned char> temp;

    if ( !DecodeBase58 ( strPaymentCode,temp ) ) {
        LogPrintf ( "CPaymentCode::decode error\n" );

    }
    return temp;
}

std::vector<unsigned char> CPaymentCode::decodeChecked()
{
    std::vector<unsigned char> temp;

    if ( !DecodeBase58Check ( strPaymentCode,temp ) ) {
        LogPrintf ( "CPaymentCode::decodeChecked error\n" );

    }
    return temp;
}

std::vector<unsigned char>& CPaymentCode::getPubKey()
{
    return pubkey;
}

std::vector<unsigned char>& CPaymentCode::getChainCode()
{
    return chaincode;
}

std::string CPaymentCode::toString() const
{
    return strPaymentCode;
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

bool CPaymentCode::parse()
{
    std::vector<unsigned char> pcBytes;
    if (!DecodeBase58Check(strPaymentCode, pcBytes)) 
        return false;

    if ( pcBytes[0] != 0x47 ) {
        LogPrintf ( "invalid payment code version" );
        return false;
    } else {
        utils::arraycopy ( pcBytes, PUBLIC_KEY_X_OFFSET, pubkey, 0,  PUBLIC_KEY_COMPRESSED_LEN );
        if ( pubkey[0] != 2 && pubkey[0] != 3 ) {
            LogPrintf ( "invalid public key" );
            return false;
        } else {
            utils::arraycopy ( pcBytes, PUBLIC_KEY_X_OFFSET+PUBLIC_KEY_COMPRESSED_LEN, chaincode, 0, PUBLIC_KEY_X_LEN );
        }
    }
    return true;
}
string CPaymentCode::makeV1()
{
    return make(1);
}

string CPaymentCode::makeV2()
{
    return make(2);
}

string CPaymentCode::make (int version)
{
    std::vector<unsigned char> payload (PAYLOAD_LEN);
    std::vector<unsigned char> payment_code (PAYMENT_CODE_LEN);

    payload[0] = (unsigned char)(version);
    payload[1] = 0;
    utils::arraycopy ( pubkey, 0, payload, PUBLIC_KEY_Y_OFFSET, pubkey.size() );
    utils::arraycopy ( chaincode, 0, payload, CHAIN_OFFSET, chaincode.size() );
    payment_code[0] = 0x47;
    utils::arraycopy ( payload, 0, payment_code, 1, payload.size() );

    return EncodeBase58Check ( payment_code );
}


bool CPaymentCode::createMasterPubKeyFromBytes ( std::vector<unsigned char> &pub, std::vector<unsigned char> &chaincode, CExtPubKey &masterPubKey )
{

    masterPubKey.nDepth = 3;
    memset ( masterPubKey.vchFingerprint, 0, sizeof ( masterPubKey.vchFingerprint ) );
    memcpy ( masterPubKey.chaincode.begin(), chaincode.data(), PUBLIC_KEY_X_LEN );
    masterPubKey.pubkey.Set ( pub.begin(), pub.end() );
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


bool CPaymentCode::isValid()
{
    return valid;
}


bool CPaymentCode::createMasterPubKeyFromPaymentCode ( string payment_code_str,CExtPubKey &masterPubKey )
{

    CPaymentCode pcode ( payment_code_str );
    return CPaymentCode::createMasterPubKeyFromBytes ( pcode.getPubKey(), pcode.getChainCode(), masterPubKey );
}

}
