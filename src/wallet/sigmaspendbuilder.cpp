#include "sigmaspendbuilder.h"
#include "walletexcept.h"

#include "../primitives/transaction.h"

#include "../sigma/coin.h"
#include "../sigma/coinspend.h"
#include "../sigma/spend_metadata.h"

#include "../validation.h"
#include "../serialize.h"
#include "../streams.h"
#include "../util.h"
#include "../version.h"
#include "../sigma.h"
#include "../hdmint/wallet.h"

#include <stdexcept>
#include <tuple>

class SigmaSpendSigner : public InputSigner
{
public:
    const sigma::PrivateCoin coin;
    std::vector<sigma::PublicCoin> group;
    uint256 lastBlockOfGroup;
    bool fPadding;

public:
    SigmaSpendSigner(const sigma::PrivateCoin& coin) : coin(coin)
    {
        fPadding = true;
    }

    CScript Sign(const CMutableTransaction& tx, const uint256& sig, bool fDummy) override
    {
        // construct spend
        sigma::SpendMetaData meta(output.n, lastBlockOfGroup, sig);
        sigma::CoinSpend spend(coin.getParams(), coin, group, meta, fPadding);

        spend.setVersion(coin.getVersion());

        if (!fDummy && !spend.Verify(group, meta, fPadding)) {
            throw std::runtime_error(_("The spend coin transaction failed to verify"));
        }

        // construct spend script
        CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
        serialized << spend;

        CScript script;

        script << OP_SIGMASPEND;
        script.insert(script.end(), serialized.begin(), serialized.end());

        return script;
    }
};

static std::unique_ptr<SigmaSpendSigner> CreateSigner(const CSigmaEntry& coin)
{
    sigma::CSigmaState* state = sigma::CSigmaState::GetState();
    auto params = sigma::Params::get_default();
    auto denom = coin.get_denomination();

    // construct public part of the mint
    sigma::PublicCoin pub(coin.value, denom);

    if (!pub.validate()) {
        throw std::runtime_error(_("One of the minted coin is invalid"));
    }

    int version;
    {
        LOCK(cs_main);
        version = chainActive.Height() >= ::Params().GetConsensus().nSigmaPaddingBlock ? ZEROCOIN_TX_VERSION_3_1
                                                                                       : ZEROCOIN_TX_VERSION_3;
    }
    // construct private part of the mint
    sigma::PrivateCoin priv(params, denom, version);

    priv.setSerialNumber(coin.serialNumber);
    priv.setRandomness(coin.randomness);
    priv.setEcdsaSeckey(coin.ecdsaSecretKey);
    priv.setPublicCoin(pub);

    std::unique_ptr<SigmaSpendSigner> signer(new SigmaSpendSigner(priv));

    // get coin group
    int groupId;

    std::tie(std::ignore, groupId) = state->GetMintedCoinHeightAndId(pub);

    if (groupId < 0) {
        throw std::runtime_error(_("One of minted coin does not found in the chain"));
    }

    signer->output.n = static_cast<uint32_t>(groupId);
    signer->sequence = CTxIn::SEQUENCE_FINAL;

    if (state->GetCoinSetForSpend(
        &chainActive,
        chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 6 confirmation for mint to spend
        denom,
        groupId,
        signer->lastBlockOfGroup,
        signer->group) < 2) {
        throw std::runtime_error(_("Has to have at least two mint coins with at least 6 confirmation in order to spend a coin"));
    }

    if(version < ZEROCOIN_TX_VERSION_3_1)
        signer->fPadding = false;

    return signer;
}

SigmaSpendBuilder::SigmaSpendBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl) :
    TxBuilder(wallet),
    mintWallet(mintWallet)
{
    cs_main.lock();

    try {
        wallet.cs_wallet.lock();
    } catch (...) {
        cs_main.unlock();
        throw;
    }

    this->coinControl = coinControl;
}

SigmaSpendBuilder::~SigmaSpendBuilder()
{
    wallet.cs_wallet.unlock();
    cs_main.unlock();
}

CAmount SigmaSpendBuilder::GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required, bool fDummy)
{
    // get coins to spend

    selected.clear();
    denomChanges.clear();

    auto& consensusParams = Params().GetConsensus();

    if (!wallet.GetCoinsToSpend(required, selected, denomChanges,
        consensusParams.nMaxSigmaInputPerTransaction, consensusParams.nMaxValueSigmaSpendPerTransaction, coinControl, fDummy)) {
        throw InsufficientFunds();
    }

    // construct signers
    CAmount total = 0;
    for (auto& coin : selected) {
        total += coin.get_denomination_value();
        signers.push_back(CreateSigner(coin));
    }

    return total;
}

CAmount SigmaSpendBuilder::GetChanges(std::vector<CTxOut>& outputs, CAmount amount, CWalletDB& walletdb, bool fDummy)
{
    outputs.clear();
    changes.clear();

    auto params = sigma::Params::get_default();

    CHDMint hdMint;
    for (const auto& denomination : denomChanges) {
        CAmount denominationValue;
        sigma::DenominationToInteger(denomination, denominationValue);

        sigma::PrivateCoin newCoin(params, denomination, ZEROCOIN_TX_VERSION_3);
        
        if(!fDummy){
            hdMint.SetNull();
            mintWallet.GenerateMint(walletdb, denomination, newCoin, hdMint, boost::none, true);
        }

        auto& pubCoin = newCoin.getPublicCoin();

        if (!pubCoin.validate()) {
            throw std::runtime_error("Unable to mint a sigma coin.");
        }

        // Create script for coin
        CScript scriptSerializedCoin;
        scriptSerializedCoin << OP_SIGMAMINT;
        std::vector<unsigned char> vch = pubCoin.getValue().getvch();
        scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

        outputs.push_back(CTxOut(denominationValue, scriptSerializedCoin));

        if(!fDummy)
            changes.push_back(hdMint);

        amount -= denominationValue;
    }

    return amount;
}
