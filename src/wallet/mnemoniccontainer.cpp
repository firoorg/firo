#include "mnemoniccontainer.h"
#include "bip39.h"
#include "hash.h"

void MnemonicContainer::SetNull()
{
    seed.clear();
    mnemonic.clear();
    fIsCrypted = false;
    f12Words = false;
}

bool MnemonicContainer::IsNull() const
{
    return seed.empty();
}

bool MnemonicContainer::IsCrypted() const
{
    return fIsCrypted;
}

void MnemonicContainer::SetCrypted(bool crypted)
{
    fIsCrypted = crypted;
}

bool MnemonicContainer::SetMnemonic(const SecureString& mnemonic_, const SecureString& passPhrase_)
{
    SecureString mnemonicNew = mnemonic_;
    if(newMnemonic) {
        if(mnemonicNew.empty())
            mnemonicNew = Mnemonic::mnemonic_generate(f12Words ? 128 : 256);
        if(!Mnemonic::mnemonic_check(mnemonicNew))
            throw std::runtime_error(std::string(__func__) + ": mnemonic is invalid");
        Mnemonic::mnemonic_to_seed(mnemonicNew, passPhrase_, seed);
    }

    mnemonic = SecureVector(mnemonicNew.begin(), mnemonicNew.end());
    return !IsNull();
}

bool MnemonicContainer::SetMnemonic(const SecureString& mnemonic_)
{
    mnemonic = SecureVector(mnemonicNew.begin(), mnemonicNew.end());
    return !IsNull();
}

bool MnemonicContainer::GetMnemonic(SecureString& mnemonic_) const
{
    mnemonic_ = SecureString(mnemonic.begin(), mnemonic.end());

    return !mnemonic_.empty();
}

bool MnemonicContainer::SetSeed(const SecureVector& seed_)
{
    seed = seed_;

    return !IsNull();
}

SecureVector MnemonicContainer::GetSeed() const
{
    return seed;
}

void MnemonicContainer::Set12Words(bool Use12Words)
{
    f12Words = Use12Words;
}