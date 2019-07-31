#ifndef ZCOIN_SIGMA_REMINT_H
#define ZCOIN_SIGMA_REMINT_H

#include "amount.h"
#include "primitives/transaction.h"
#include "libzerocoin/Zerocoin.h"
#include "libzerocoin/Coin.h"
#include "libzerocoin/SpendMetaData.h"

namespace sigma {

/*
 * Special spend-like input. To use it disclose serial, randomness, public ECDSA key of existing zerocoin v2 mint. You can obtain sigma mint as an output
 */
class CoinRemintToV3 {
public:
    template<typename Stream>
    CoinRemintToV3(Stream &stream) { stream >> *this; coinPublicValue = CalculatePublicValue(); }

    CoinRemintToV3(unsigned mintVersion, unsigned denomination, unsigned groupId, Bignum serial, Bignum randomness,
                    uint256 originalMintBlockHash, const std::vector<unsigned char> &ecdsaPrivateKey);

    int getVersion() const { return coinRemintVersion; }
    int getMintVersion() const { return coinMintVersion; }
    Bignum getSerialNumber() const { return coinSerial; }
    Bignum getPublicCoinValue() const { return coinPublicValue; }
    int getDenomination() const { return coinDenomination; }
    int getCoinGroupId() const { return coinGroupId; }
    uint256 getMintBlockHash() const { return mintBlockHash; }

    void SignTransaction(const libzerocoin::SpendMetaData &metadata);
    void ClearSignature();

    bool Verify(const libzerocoin::SpendMetaData &metadata) const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(coinRemintVersion);
        READWRITE(coinMintVersion);
        READWRITE(coinDenomination);    // check for the fixed list of denominations is made in the Verify() method
        READWRITE(coinGroupId);
        READWRITE(coinSerial);
        READWRITE(coinRandomness);
        READWRITE(mintBlockHash);
        if (coinMintVersion > ZEROCOIN_TX_VERSION_1) {
            // coin mint version == 1 will be supported later
            READWRITE(ecdsaPublicKey); 
            READWRITE(ecdsaSignature);
        }
    }

    // Helper functions to get the amount out of remint tx
    static CAmount GetAmount(const CTransaction &tx);

    // Helper function to get serial out of remint tx
    static Bignum GetSerialNumber(const CTransaction &tx);

private:
    Bignum CalculatePublicValue() const;
    uint256 GetMetadataHash(const libzerocoin::SpendMetaData &metadata) const;

    unsigned coinDenomination;
    unsigned coinGroupId;
    unsigned coinRemintVersion;
    unsigned coinMintVersion;
    Bignum coinSerial;
    Bignum coinRandomness;
    Bignum coinPublicValue;
    std::vector<unsigned char> ecdsaPublicKey;
    std::vector<unsigned char> ecdsaPrivateKey;
    std::vector<unsigned char> ecdsaSignature;
    uint256 mintBlockHash;
};

} // namespace sigma

#endif
