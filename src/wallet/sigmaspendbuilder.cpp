#include "sigmaspendbuilder.h"
#include "walletexcept.h"

#include "../primitives/transaction.h"

#include "../sigma/coin.h"
#include "../sigma/coinspend.h"
#include "../sigma/spend_metadata.h"

#include "../main.h"
#include "../serialize.h"
#include "../streams.h"
#include "../util.h"
#include "../version.h"
#include "../zerocoin_v3.h"
#include "../hdmint/wallet.h"

#include <stdexcept>
#include <tuple>

class SigmaSpendSigner : public InputSigner
{
public:
    const sigma::PrivateCoin coin;
    std::vector<sigma::PublicCoin> group;
    uint256 lastBlockOfGroup;

public:
    SigmaSpendSigner(const sigma::PrivateCoin& coin) : coin(coin)
    {
    }

    CScript Sign(const CMutableTransaction& tx, const uint256& sig) override
    {
        // construct spend
        sigma::SpendMetaData meta(output.n, lastBlockOfGroup, sig);
        sigma::CoinSpend spend(coin.getParams(), coin, group, meta);

        spend.setVersion(coin.getVersion());

        if (!spend.Verify(group, meta)) {
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

    // construct private part of the mint
    sigma::PrivateCoin priv(params, denom, ZEROCOIN_TX_VERSION_3);

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

    return signer;
}

SigmaSpendBuilder::SigmaSpendBuilder(CWallet& wallet, const CCoinControl *coinControl) : TxBuilder(wallet)
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

CAmount SigmaSpendBuilder::GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required)
{
    // get coins to spend

    selected.clear();
    denomChanges.clear();

    auto& consensusParams = Params().GetConsensus();

    if (!wallet.GetCoinsToSpend(required, selected, denomChanges,
        consensusParams.nMaxSigmaInputPerTransaction, consensusParams.nMaxValueSigmaSpendPerTransaction, coinControl)) {
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

CAmount SigmaSpendBuilder::GetChanges(std::vector<CTxOut>& outputs, CAmount amount)
{
    outputs.clear();
    changes.clear();

    auto params = sigma::Params::get_default();

    CHDMint hdMint;
    for (const auto& denomination : denomChanges) {
        CAmount denominationValue;
        sigma::DenominationToInteger(denomination, denominationValue);

        sigma::PrivateCoin newCoin(params, denomination, ZEROCOIN_TX_VERSION_3);
        hdMint.SetNull();
        if (zwalletMain) {
            zwalletMain->GenerateMint(denomination, newCoin, hdMint);
        }
        auto& pubCoin = newCoin.getPublicCoin();

        if (!pubCoin.validate()) {
            throw std::runtime_error("Unable to mint a V3 sigma coin.");
        }

        // Create script for coin
        CScript scriptSerializedCoin;
        scriptSerializedCoin << OP_SIGMAMINT;
        std::vector<unsigned char> vch = pubCoin.getValue().getvch();
        scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

        outputs.push_back(CTxOut(denominationValue, scriptSerializedCoin));
        changes.push_back(hdMint);

        amount -= denominationValue;
    }

    return amount;
}
