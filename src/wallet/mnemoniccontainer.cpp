#include "mnemoniccontainer.h"
#include "bip39.h"
#include "hash.h"

void MnemonicConatiner::SetNull()
{
    seed.clear();
    mnemonic.clear();
    passPhrase.clear();
    fIsCrypted = false;
    f12Words = false;
}

bool MnemonicConatiner::IsNull() const
{
    return seed.empty();
}

bool MnemonicConatiner::IsCrypted() const
{
    return fIsCrypted;
}

void MnemonicConatiner::SetCrypted(bool crypted)
{
    fIsCrypted = crypted;
}

bool MnemonicConatiner::SetMnemonic(const SecureString& mnemonic_, const SecureString& passPhrase_, bool newMnemonic)
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
    passPhrase = SecureVector(passPhrase_.begin(), passPhrase_.end());
    return !IsNull();
}

bool MnemonicConatiner::GetMnemonic(SecureString& mnemonic_, SecureString& passPhrase_) const
{
    mnemonic_ = SecureString(mnemonic.begin(), mnemonic.end());
    passPhrase_ = SecureString(passPhrase.begin(), passPhrase.end());

    return !mnemonic_.empty();
}

bool MnemonicConatiner::SetSeed(const SecureVector& seed_)
{
    seed = seed_;

    return !IsNull();
}

SecureVector MnemonicConatiner::GetSeed() const
{
    return seed;
}

void MnemonicConatiner::Set12Words(bool Use12Words)
{
    f12Words = Use12Words;
}