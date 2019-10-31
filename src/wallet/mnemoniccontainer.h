#ifndef ZCOIN_HDCHAIN_H
#define ZCOIN_HDCHAIN_H

#include "support/allocators/secure.h"
#include "uint256.h"
#include "serialize.h"

class MnemonicConatiner
{
public:
    SecureVector seed;
    SecureVector mnemonic;
    bool fIsCrypted;
    bool f12Words;

    MnemonicConatiner() { SetNull(); }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
            READWRITE(mnemonic);
            READWRITE(seed);
            READWRITE(fIsCrypted);
            READWRITE(f12Words);
    }

    void SetNull();

    bool IsNull() const;

    bool IsCrypted() const;

    void SetCrypted(bool crypted);

    bool SetMnemonic(const SecureString& mnemonic, const SecureString& passPhrase, bool newMnemonic);

    bool GetMnemonic(SecureString& mnemonic_) const;

    bool SetSeed(const SecureVector& seed_);

    SecureVector GetSeed() const;

    void Set12Words(bool Use12Words = false);
};

#endif //ZCOIN_HDCHAIN_H
