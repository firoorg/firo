
#include "bip47/paymentcode.h"
#include "bip47/channeladdress.h"
#include "util.h"

int CPaymentCode::PUBLIC_KEY_Y_OFFSET = 2;
int CPaymentCode::PUBLIC_KEY_X_OFFSET = 3;
int CPaymentCode::CHAIN_OFFSET = 35;
int CPaymentCode::PUBLIC_KEY_X_LEN = 32;
int CPaymentCode::PUBLIC_KEY_Y_LEN = 1;
int CPaymentCode::PUBLIC_KEY_COMPRESSED_LEN = PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN;
int CPaymentCode::CHAIN_CODE_LEN = 32;
int CPaymentCode::PAYLOAD_LEN = 80;
int CPaymentCode::PAYMENT_CODE_LEN = PAYLOAD_LEN + 1; // (0x47("P") | payload)

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
        CBIP47Util::arraycopy ( payload, PUBLIC_KEY_Y_OFFSET, pubkey, 0, PUBLIC_KEY_COMPRESSED_LEN );
        CBIP47Util::arraycopy ( payload, CHAIN_OFFSET, chaincode, 0, PUBLIC_KEY_X_LEN );
        strPaymentCode = makeV1();
        valid = parse();
    }
}

CPaymentCode::CPaymentCode (std::vector<unsigned char> &v_pubkey, std::vector<unsigned char> &v_chaincode) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    CBIP47Util::arraycopy ( v_pubkey.data(),0,pubkey,0,PUBLIC_KEY_COMPRESSED_LEN );
    CBIP47Util::arraycopy ( v_chaincode.data(),0,chaincode, 0, PUBLIC_KEY_X_LEN );
    strPaymentCode = makeV1();
    valid = parse();
}
CPaymentCode::CPaymentCode (unsigned char* v_pubkey, unsigned char* v_chaincode) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    CBIP47Util::arraycopy ( v_pubkey,0,pubkey,0,PUBLIC_KEY_COMPRESSED_LEN );
    CBIP47Util::arraycopy ( v_chaincode,0,chaincode, 0, PUBLIC_KEY_X_LEN );
    strPaymentCode = makeV1();
    valid = parse();
}
CPaymentCode::CPaymentCode ( const unsigned char* v_pubkey,  const unsigned char *v_chaincode) : pubkey(PUBLIC_KEY_COMPRESSED_LEN), chaincode(CHAIN_CODE_LEN)
{
    CBIP47Util::arraycopy (v_pubkey,    0, pubkey,    0, PUBLIC_KEY_COMPRESSED_LEN);
    CBIP47Util::arraycopy (v_chaincode, 0, chaincode, 0, PUBLIC_KEY_X_LEN);
    strPaymentCode = makeV1();
    valid = parse();
}

CBIP47ChannelAddress CPaymentCode::notificationAddress()
{
    return addressAt (0);
}

CBIP47ChannelAddress CPaymentCode::addressAt ( int idx )
{
    CExtPubKey key;
    if ( !createMasterPubKeyFromPaymentCode ( strPaymentCode,key ) ) {
        LogPrintf ( "CPaymentCode::addressAt is failed idx = %d \n",idx );
        LogPrintf ( "CBIP47ChannelAddress CPaymentCode::addressAt.\n" );

    }
    return CBIP47ChannelAddress ( key, idx );
}

std::vector<unsigned char> CPaymentCode::getPayload()
{
    std::vector<unsigned char> pcBytes;
    if ( !DecodeBase58Check ( strPaymentCode,pcBytes ) ) {
        LogPrintf ( "CPaymentCode::getPayload is failed in DecodeBase58Check\n" );
        return std::vector<unsigned char> (0);

    }

    std::vector<unsigned char> payload ( PAYLOAD_LEN );
    CBIP47Util::arraycopy ( pcBytes, 1, payload, 0, payload.size() );
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

std::string CPaymentCode::toString()
{
    return strPaymentCode;
}

std::vector<unsigned char> CPaymentCode::getMask ( std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint )
{
    std::vector<unsigned char> mac_data ( PUBLIC_KEY_X_LEN + CHAIN_CODE_LEN );
    unsigned char out[PUBLIC_KEY_X_LEN + CHAIN_CODE_LEN];
    CHMAC_SHA512 (sPoint.data(), sPoint.size() ).Write ( oPoint.data(), oPoint.size()).Finalize (out);
    memcpy (mac_data.data(), out, PUBLIC_KEY_X_LEN + CHAIN_CODE_LEN);
    return mac_data;
}

std::vector<unsigned char> CPaymentCode::blind ( std::vector<unsigned char> payload, std::vector<unsigned char> mask )
{
    std::vector<unsigned char> ret ( PAYLOAD_LEN );
    std::vector<unsigned char> pubkey ( PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> chaincode ( CHAIN_CODE_LEN );
    std::vector<unsigned char> buf0 ( PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> buf1 ( PUBLIC_KEY_X_LEN );
    CBIP47Util::arraycopy ( payload, 0, ret, 0, PAYLOAD_LEN );
    CBIP47Util::arraycopy ( payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN );
    CBIP47Util::arraycopy ( payload, CHAIN_OFFSET, chaincode, 0, PUBLIC_KEY_X_LEN );
    CBIP47Util::arraycopy ( mask, 0, buf0, 0, PUBLIC_KEY_X_LEN );
    CBIP47Util::arraycopy ( mask, PUBLIC_KEY_X_LEN, buf1, 0, PUBLIC_KEY_X_LEN );
    std::vector<unsigned char> temp1;
    std::vector<unsigned char> temp2;
    temp1 = vector_xor ( pubkey, buf0 );
    temp2 = vector_xor ( chaincode, buf1 );
    CBIP47Util::arraycopy ( temp1, 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN );
    CBIP47Util::arraycopy ( temp2, 0, ret, CHAIN_OFFSET, PUBLIC_KEY_X_LEN );
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
        CBIP47Util::arraycopy ( pcBytes, PUBLIC_KEY_X_OFFSET, pubkey, 0,  PUBLIC_KEY_COMPRESSED_LEN );
        if ( pubkey[0] != 2 && pubkey[0] != 3 ) {
            LogPrintf ( "invalid public key" );
            return false;
        } else {
            CBIP47Util::arraycopy ( pcBytes, PUBLIC_KEY_X_OFFSET+PUBLIC_KEY_COMPRESSED_LEN, chaincode, 0, PUBLIC_KEY_X_LEN );
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

    for ( int checksum = 0; checksum < payload.size(); ++checksum ) {
        payload[checksum] = 0;
    }

    payload[0] = ( unsigned char ) version;
    payload[1] = 0;
    CBIP47Util::arraycopy ( pubkey, 0, payload, PUBLIC_KEY_Y_OFFSET, pubkey.size() );
    CBIP47Util::arraycopy ( chaincode, 0, payload, CHAIN_OFFSET, chaincode.size() );
    payment_code[0] = 0x47;
    CBIP47Util::arraycopy ( payload, 0, payment_code, 1, payload.size() );


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

        for ( int i = 0; i < a.size(); ++i ) {
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
