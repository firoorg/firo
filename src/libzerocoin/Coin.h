/**
 * @file       Coin.h
 *
 * @brief      PublicCoin and PrivateCoin classes for the Zerocoin library.
 *
 * @author     Ian Miers, Christina Garman and Matthew Green
 * @date       June 2013
 *
 * @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
 * @license    This project is released under the MIT license.
 **/

#ifndef COIN_H_
#define COIN_H_
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "bitcoin_bignum/bignum.h"
#include "Params.h"
namespace libzerocoin {

enum  CoinDenomination {
    ZQ_LOVELACE = 1,
    ZQ_GOLDWASSER = 10,
    ZQ_RACKOFF = 25, 
    ZQ_PEDERSEN = 50,
    ZQ_WILLIAMSON = 100 // Malcolm J. Williamson,
                    // the scientist who actually invented
                    // Public key cryptography
};

/** A Public coin is the part of a coin that
 * is published to the network and what is handled
 * by other clients. It contains only the value
 * of commitment to a serial number and the
 * denomination of the coin.
 */
class PublicCoin {
public:
    template<typename Stream>
    PublicCoin(const Params* p, Stream& strm): params(p) {
        strm >> *this;
    }

    PublicCoin(const Params* p);

    /**Generates a public coin
     *
     * @param p cryptographic paramters
     * @param coin the value of the commitment.
     * @param denomination The denomination of the coin. Defaults to ZQ_LOVELACE
     */
    PublicCoin(const Params* p, const Bignum& coin, const CoinDenomination d = ZQ_LOVELACE);
    const Bignum& getValue() const;
    CoinDenomination getDenomination() const;
    bool operator==(const PublicCoin& rhs) const;
    bool operator!=(const PublicCoin& rhs) const;
    /** Checks that a coin prime
     *  and in the appropriate range
     *  given the parameters
     * @return true if valid
     */
    bool validate() const;
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(value);
        READWRITE(denomination);
    }
//	IMPLEMENT_SERIALIZE
//	(
//	    READWRITE(value);
//	    READWRITE(denomination);
//	)
private:
    const Params* params;
    Bignum value;
    // Denomination is stored as an INT because storing
    // and enum raises amigiuities in the serialize code //FIXME if possible
    int denomination;
};

/**
 * A private coin. As the name implies, the content
 * of this should stay private except PublicCoin.
 *
 * Contains a coin's serial number, a commitment to it,
 * and opening randomness for the commitment.
 *
 * @warning Failure to keep this secret(or safe),
 * @warning will result in the theft of your coins
 * @warning and a TOTAL loss of anonymity.
 */
class PrivateCoin {
public:
    template<typename Stream>
    PrivateCoin(const Params* p, Stream& strm): params(p), publicCoin(p) {
        strm >> *this;
    }
    PrivateCoin(const Params* p, CoinDenomination denomination = ZQ_LOVELACE, int version = ZEROCOIN_TX_VERSION_1);
    const PublicCoin& getPublicCoin() const;
    const Bignum& getSerialNumber() const;
    const Bignum& getRandomness() const;
    const unsigned char* getEcdsaSeckey() const;
    unsigned int getVersion() const;
    static Bignum serialNumberFromSerializedPublicKey(secp256k1_context *ctx, secp256k1_pubkey *pubkey);

    void setPublicCoin(const PublicCoin& p){
        publicCoin = p;
    }

    void setRandomness(const Bignum& n){
        randomness = n;
    }

    void setSerialNumber(const Bignum& n){
        serialNumber = n;
    }

    void setVersion(unsigned int nVersion){
        version = nVersion;
    };

    void setEcdsaSeckey(const std::vector<unsigned char> &seckey) {
        if (seckey.size() == sizeof(ecdsaSeckey))
            std::copy(seckey.cbegin(), seckey.cend(), &ecdsaSeckey[0]);
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(publicCoin);
        READWRITE(randomness);
        READWRITE(serialNumber);

        if (ser_action.ForRead()) {
            if (s.eof())
                version = ZEROCOIN_TX_VERSION_1;
            else
                READWRITE(version);
        }
        else {
            if (version > ZEROCOIN_TX_VERSION_1)
                READWRITE(version);
        }

        if (version == ZEROCOIN_TX_VERSION_2)
            READWRITE(ecdsaSeckey);
    }

private:
    const Params* params;
    PublicCoin publicCoin;
    Bignum randomness;
    Bignum serialNumber;
    unsigned int version = 0;
    unsigned char ecdsaSeckey[32];

    /**
     * @brief Mint a new coin.
     * @param denomination the denomination of the coin to mint
     * @throws ZerocoinException if the process takes too long
     *
     * Generates a new Zerocoin by (a) selecting a random serial
     * number, (b) committing to this serial number and repeating until
     * the resulting commitment is prime. Stores the
     * resulting commitment (coin) and randomness (trapdoor).
     **/
    void mintCoin(const CoinDenomination denomination);

    /**
     * @brief Mint a new coin using a faster process.
     * @param denomination the denomination of the coin to mint
     * @throws ZerocoinException if the process takes too long
     *
     * Generates a new Zerocoin by (a) selecting a random serial
     * number, (b) committing to this serial number and repeating until
     * the resulting commitment is prime. Stores the
     * resulting commitment (coin) and randomness (trapdoor).
     * This routine is substantially faster than the
     * mintCoin() routine, but could be more vulnerable
     * to timing attacks. Don't use it if you think someone
     * could be timing your coin minting.
     **/
    void mintCoinFast(const CoinDenomination denomination);

};

} /* namespace libzerocoin */
#endif /* COIN_H_ */
