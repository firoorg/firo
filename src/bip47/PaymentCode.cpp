#include "PaymentCode.h"
#include "Bip47ChannelAddress.h"
int PaymentCode::PUBLIC_KEY_Y_OFFSET = 2;
int PaymentCode::PUBLIC_KEY_X_OFFSET = 3;
int PaymentCode::CHAIN_OFFSET = 35;
int PaymentCode::PUBLIC_KEY_X_LEN = 32;
int PaymentCode::PUBLIC_KEY_Y_LEN = 1;
int PaymentCode::CHAIN_LEN = 32;
int PaymentCode::PAYLOAD_LEN = 80;
PaymentCode::PaymentCode() :
    pubkey ( 33 ),chain ( 32 )
{
}
PaymentCode::PaymentCode ( String payment_code ) :
    pubkey ( 33 ),chain ( 32 )
{
    strPaymentCode = payment_code;
    parse();
}

PaymentCode::PaymentCode ( unsigned char* payload, int length ) :
    pubkey ( 33 ),chain ( 32 )
{
    if ( length == 80 ) {
        Bip47_common::arraycopy ( payload, 2, pubkey, 0, 33 );
        Bip47_common::arraycopy ( payload, 35, chain, 0, 32 );
        strPaymentCode = makeV1();
    }
}

PaymentCode::PaymentCode ( std::vector<unsigned char> &v_pubkey, std::vector<unsigned char> &v_chain ) :pubkey ( 33 ),chain ( 32 )

{
    Bip47_common::arraycopy ( v_pubkey.data(),0,pubkey,0,33 );
    Bip47_common::arraycopy ( v_chain.data(),0,chain, 0, 32 );
    strPaymentCode = makeV1();
}
PaymentCode::PaymentCode ( unsigned char* v_pubkey, unsigned char* v_chain ) :
    pubkey ( 33 ),chain ( 32 )
{
    Bip47_common::arraycopy ( v_pubkey,0,pubkey,0,33 );
    Bip47_common::arraycopy ( v_chain,0,chain, 0, 32 );
    strPaymentCode = makeV1();
}
PaymentCode::PaymentCode ( const unsigned char* v_pubkey,  const unsigned char *v_chain )
    : pubkey ( 33 ),chain ( 32 )
{
    Bip47_common::arraycopy ( v_pubkey,0,pubkey,0,33 );
    Bip47_common::arraycopy ( v_chain,0,chain, 0, 32 );
    strPaymentCode = makeV1();
}
Bip47ChannelAddress PaymentCode::notificationAddress()
{
    return addressAt ( 0 );
}

Bip47ChannelAddress PaymentCode::addressAt ( int idx )
{
    CExtPubKey key;
    if ( !createMasterPubKeyFromPaymentCode ( strPaymentCode,key ) ) {
        LogPrintf ( "PaymentCode::addressAt is failed idx = %d \n",idx );
        LogPrintf ( "Bip47ChannelAddress PaymentCode::addressAt.\n" );

    }
    return Bip47ChannelAddress ( key, idx );
}

std::vector<unsigned char> PaymentCode::getPayload()
{
    std::vector<unsigned char> pcBytes;
    if ( !DecodeBase58Check ( strPaymentCode,pcBytes ) ) {
        LogPrintf ( "PaymentCode::getPayload is failed in DecodeBase58Check\n" );
        return std::vector<unsigned char> ( 0 );

    }

    std::vector<unsigned char> payload ( 80 );
    Bip47_common::arraycopy ( pcBytes, 1, payload, 0, payload.size() );
    return payload;
}

int PaymentCode::getType()
{
    std::vector<unsigned char> payload = getPayload();
    unsigned char type = payload[0];
    return type;
}

std::vector<unsigned char> PaymentCode::decode()
{
    std::vector<unsigned char> temp;

    if ( !DecodeBase58 ( strPaymentCode,temp ) ) {
        LogPrintf ( "PaymentCode::decode error\n" );

    }
    return temp ;
}

std::vector<unsigned char> PaymentCode::decodeChecked()
{
    std::vector<unsigned char> temp ;

    if ( !DecodeBase58Check ( strPaymentCode,temp ) ) {
        LogPrintf ( "PaymentCode::decodeChecked error\n" );

    }
    return temp ;
}

std::vector<unsigned char>& PaymentCode::getPubKey()
{
    return pubkey;
}

std::vector<unsigned char>& PaymentCode::getChain()
{
    return chain;
}

String PaymentCode::toString()
{
    return strPaymentCode;
}

std::vector<unsigned char> PaymentCode::getMask ( std::vector<unsigned char> sPoint, std::vector<unsigned char> oPoint )
{
    std::vector<unsigned char> mac_data ( 64 );
    unsigned char out[64];
    CHMAC_SHA512 ( sPoint.data(), sPoint.size() ).Write ( oPoint.data(), oPoint.size() ).Finalize ( out );
    memcpy ( mac_data.data(),out,64 );
    return mac_data;
}

std::vector<unsigned char> PaymentCode::blind ( std::vector<unsigned char> payload, std::vector<unsigned char> mask )
{
    std::vector<unsigned char> ret ( 80 );
    std::vector<unsigned char> pubkey ( 32 );
    std::vector<unsigned char> chain ( 32 );
    std::vector<unsigned char> buf0 ( 32 );
    std::vector<unsigned char> buf1 ( 32 );
    Bip47_common::arraycopy ( payload, 0, ret, 0, 80 );
    Bip47_common::arraycopy ( payload, 3, pubkey, 0, 32 );
    Bip47_common::arraycopy ( payload, 35, chain, 0, 32 );
    Bip47_common::arraycopy ( mask, 0, buf0, 0, 32 );
    Bip47_common::arraycopy ( mask, 32, buf1, 0, 32 );
    std::vector<unsigned char> temp1 ;
    std::vector<unsigned char> temp2 ;
    temp1 = vector_xor ( pubkey, buf0 ) ;
    temp2 = vector_xor ( chain, buf1 ) ;
    Bip47_common::arraycopy ( temp1, 0, ret, 3, 32 );
    Bip47_common::arraycopy ( temp2, 0, ret, 35, 32 );
    return ret;
}

bool PaymentCode::parse()
{
    std::vector<unsigned char> pcBytes;
    if ( !DecodeBase58Check ( strPaymentCode, pcBytes ) ) return false ;
    if ( pcBytes[0] != 0x47 ) {
        LogPrintf ( "invalid payment code version" );
        return false;
    } else {
        Bip47_common::arraycopy ( pcBytes, 3, pubkey, 0,  33 );
        if ( pubkey[0] != 2 && pubkey[0] != 3 ) {
            LogPrintf ( "invalid public key" );
            return false;
        } else {
            Bip47_common::arraycopy ( pcBytes,3+33,chain,0,32 );
        }
    }
    return true;
}
string PaymentCode::makeV1()
{
    return make ( 1 );
}

string PaymentCode::makeV2()
{
    return make ( 2 );
}

string PaymentCode::make ( int type )
{
    std::vector<unsigned char> payload ( 80 );
    std::vector<unsigned char> payment_code ( 81 );

    for ( int checksum = 0; checksum < payload.size(); ++checksum ) {
        payload[checksum] = 0;
    }

    payload[0] = ( unsigned char ) type;
    payload[1] = 0;
    Bip47_common::arraycopy ( pubkey, 0, payload, 2, pubkey.size() );
    Bip47_common::arraycopy ( chain, 0, payload, 35, chain.size() );
    payment_code[0] = 0x47;
    Bip47_common::arraycopy ( payload, 0, payment_code, 1, payload.size() );


    return EncodeBase58Check ( payment_code );
}


bool PaymentCode::createMasterPubKeyFromBytes ( std::vector<unsigned char> &pub, std::vector<unsigned char> &chain, CExtPubKey &masterPubKey )
{

    masterPubKey.nDepth = 3;
    memset ( masterPubKey.vchFingerprint, 0, sizeof ( masterPubKey.vchFingerprint ) );
    memcpy ( masterPubKey.chaincode.begin(), chain.data(), 32 );
    masterPubKey.pubkey.Set ( pub.begin(), pub.end() );
    return true;

}

std::vector<unsigned char> PaymentCode::vector_xor ( std::vector<unsigned char> a, std::vector<unsigned char> b )
{
    if ( a.size() != b.size() ) {
        LogPrintf ( "vector_xor a and b should have same size" );
        return std::vector<unsigned char> ( 0 );
    } else {
        std::vector<unsigned char> ret ( a.size() );

        for ( int i = 0; i < a.size(); ++i ) {
            ret[i] = ( unsigned char ) ( b[i] ^ a[i] );
        }

        return ret;
    }
}


bool PaymentCode::isValid()
{
    std::vector<unsigned char> afe;
    if ( !DecodeBase58Check ( strPaymentCode,afe ) ) return false;
    if ( afe[0] != 71 ) {
        LogPrintf ( "invalid version: %s\n", strPaymentCode );
        return false;
    } else {
        PaymentCode testPcode ( strPaymentCode );
        std::vector<unsigned char> l_chain = testPcode.getChain();
        std::vector<unsigned char> l_pubkey = testPcode.getPubKey();
        
        unsigned char firstByte = l_pubkey[0];
        if ( firstByte == 2 || firstByte == 3 ) {
            for ( int i = 0; i < 33; i++ ) {
                if ( l_pubkey[i] != pubkey[i] ) {
                    return false;
                }
            }
            for ( int j =0; j < 32; j++ ) {
                if ( l_chain[j] != this->chain[j] ) {
                    return false;
                }

            }
        } else {
            return false;
        }

        PaymentCode testPcode1 ( l_pubkey, l_chain );
        if ( testPcode1.toString().compare ( strPaymentCode ) != 0 ) {
            printf ( "invalid check payment code\n" );
            return false;
        }

    }

    return true;
}


bool PaymentCode::createMasterPubKeyFromPaymentCode ( string payment_code_str,CExtPubKey &masterPubKey )
{

    PaymentCode pcode ( payment_code_str );
    return PaymentCode::createMasterPubKeyFromBytes ( pcode.getPubKey(), pcode.getChain(), masterPubKey );
}
