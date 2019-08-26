#ifndef ZCOIN_HDCHAIN_H
#define ZCOIN_HDCHAIN_H

#include "key.h"

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter; // VERSION_BASIC
    vector<uint32_t> nExternalChainCounters; // VERSION_WITH_BIP44: vector index corresponds to account value
    SecureVector seed;
    SecureVector mnemonic;
    SecureVector passPhrase;
    bool fIsCrypted;
    CKeyID masterKeyID; //!< master key hash160

    static const int VERSION_BASIC = 1;
    static const int VERSION_WITH_BIP44 = 10;
    static const int VERSION_WITH_BIP39 = 11;
    static const int CURRENT_VERSION = VERSION_WITH_BIP39;
    static const int N_CHANGES = 3; // standard = 0/1, mint = 2
    int nVersion;

    CHDChain() { SetNull(); }
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {

        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nExternalChainCounter);
        READWRITE(masterKeyID);
        if(this->nVersion >= VERSION_WITH_BIP44){
            READWRITE(nExternalChainCounters);
        }
        if(this->nVersion >= VERSION_WITH_BIP39) {
            READWRITE(mnemonic);
            READWRITE(passPhrase);
            READWRITE(seed);
            READWRITE(fIsCrypted);
        }
    }

    void SetNull();

    bool IsNull() const;

    bool IsCrypted() const;

    void SetCrypted(bool crypted);

    bool SetMnemonic(const SecureString& mnemonic, const SecureString& passPhrase, bool setMasterKeyID);

    bool GetMnemonic(SecureString& mnemonic_, SecureString& passPhrase_) const;

    bool SetSeed(const SecureVector& seed_);

    SecureVector GetSeed() const;

    uint256 GetSeedHash() const;
};

#endif //ZCOIN_HDCHAIN_H
