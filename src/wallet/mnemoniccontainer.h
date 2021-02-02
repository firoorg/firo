#ifndef FIRO_HDCHAIN_H
#define FIRO_HDCHAIN_H

#include "support/allocators/secure.h"
#include "uint256.h"
#include "serialize.h"

class MnemonicContainer
{
public:
    SecureVector seed;
    SecureVector mnemonic;
    bool fIsCrypted;
    bool f12Words;

    MnemonicContainer() { SetNull(); }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
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

    bool SetMnemonic(const SecureString& mnemonic, const SecureString& passPhrase);

    bool SetMnemonic(const SecureVector& mnemonic_);

    bool GetMnemonic(SecureString& mnemonic_) const;

    bool SetSeed(const SecureVector& seed_);

    SecureVector GetSeed() const;

    void Set12Words(bool Use12Words = false);
};

#endif //FIRO_HDCHAIN_H
