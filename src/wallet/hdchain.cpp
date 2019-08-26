#include "hdchain.h"
#include "bip39.h"

void CHDChain::SetNull()
{
    nVersion = CHDChain::CURRENT_VERSION;
    masterKeyID.SetNull();
    nExternalChainCounter = 0;
    for(int index=0;index<N_CHANGES;index++){
        nExternalChainCounters.push_back(0);
    }
    seed.clear();
    mnemonic.clear();
    passPhrase.clear();
    fIsCrypted = false;
}

bool CHDChain::IsNull() const
{   if(this->nVersion >= VERSION_WITH_BIP39)
        return seed.empty() || masterKeyID.IsNull();
    else
        return masterKeyID.IsNull();
}

bool CHDChain::IsCrypted() const
{
    return fIsCrypted;
}

void CHDChain::SetCrypted(bool crypted)
{
    fIsCrypted = crypted;
}

bool CHDChain::SetMnemonic(const SecureString& mnemonic_, const SecureString& passPhrase_, bool setMasterKeyID)
{
    SecureString mnemonicNew = mnemonic_;
    if(setMasterKeyID) {
        if(mnemonicNew.empty())
            mnemonicNew = Mnemonic::mnemonic_generate(256);
        if(!Mnemonic::mnemonic_check(mnemonicNew))
            throw std::runtime_error(std::string(__func__) + ": mnemonic is invalid");
        Mnemonic::mnemonic_to_seed(mnemonicNew, passPhrase_, seed);

        masterKeyID = CKeyID(Hash160(seed.begin(), seed.end()));
    }

    mnemonic = SecureVector(mnemonicNew.begin(), mnemonicNew.end());
    passPhrase = SecureVector(passPhrase_.begin(), passPhrase_.end());
    return !IsNull();
}

bool CHDChain::GetMnemonic(SecureString& mnemonic_, SecureString& passPhrase_) const
{
    mnemonic_ = SecureString(mnemonic.begin(), mnemonic.end());
    passPhrase_ = SecureString(passPhrase.begin(), passPhrase.end());

    return !mnemonic_.empty();
}

bool CHDChain::SetSeed(const SecureVector& seed_)
{
    seed = seed_;

    return !IsNull();
}

SecureVector CHDChain::GetSeed() const
{
    return seed;
}

uint256 CHDChain::GetSeedHash() const
{
    return Hash(seed.begin(), seed.end());
}