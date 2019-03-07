#include "sigmaspendbuilder.h"

#include "../libzerocoin/sigma/Coin.h"
#include "../libzerocoin/sigma/CoinSpend.h"
#include "../libzerocoin/sigma/SpendMetaDataV3.h"

#include "../main.h"
#include "../serialize.h"
#include "../streams.h"
#include "../util.h"
#include "../version.h"
#include "../zerocoin_v3.h"

#include <stdexcept>
#include <tuple>

class SigmaSpendSigner : public InputSigner
{
public:
    const sigma::PrivateCoinV3 coin;
    std::vector<sigma::PublicCoinV3> group;
    uint256 lastBlockOfGroup;

public:
    SigmaSpendSigner(const sigma::PrivateCoinV3& coin) : coin(coin)
    {
    }

    CScript Sign(const CMutableTransaction& tx, const uint256& sig) override
    {
        // construct spend
        sigma::SpendMetaDataV3 meta(sequence, lastBlockOfGroup, sig);
        sigma::CoinSpendV3 spend(coin.getParams(), coin, group, meta);

        spend.setVersion(coin.getVersion());

        if (!spend.Verify(group, meta)) {
            throw std::runtime_error(_("The spend coin transaction failed to verify"));
        }

        // construct spend script
        CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
        serialized << spend;

        CScript script;

        script << OP_ZEROCOINSPENDV3;
        script.insert(script.end(), serialized.begin(), serialized.end());

        return script;
    }
};

static std::unique_ptr<SigmaSpendSigner> CreateSigner(const CZerocoinEntryV3& coin)
{
    auto state = CZerocoinStateV3::GetZerocoinState();
    auto params = sigma::ParamsV3::get_default();
    auto denom = coin.get_denomination();

    // construct public part of the mint
    sigma::PublicCoinV3 pub(coin.value, denom);

    if (!pub.validate()) {
        throw std::runtime_error(_("One of the minted coin is invalid"));
    }

    // construct private part of the mint
    sigma::PrivateCoinV3 priv(params, denom, ZEROCOIN_TX_VERSION_3);

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

    signer->sequence = groupId;

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

SigmaSpendBuilder::SigmaSpendBuilder(CWallet& wallet) : TxBuilder(wallet)
{
    cs_main.lock();

    try {
        wallet.cs_wallet.lock();
    } catch (...) {
        cs_main.unlock();
        throw;
    }
}

SigmaSpendBuilder::~SigmaSpendBuilder()
{
    wallet.cs_wallet.unlock();
    cs_main.unlock();
}

CAmount SigmaSpendBuilder::GetInputs(std::vector<std::unique_ptr<InputSigner>>& signers, CAmount required)
{
    // get coins to spend
    std::vector<sigma::CoinDenominationV3> denomsToChanges;

    selected.clear();

    if (!wallet.GetCoinsToSpend(required, selected, denomsToChanges)) {
        throw std::runtime_error(_("Insufficient funds"));
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
    mints.clear();

    auto zcParams = sigma::ParamsV3::get_default();

    // desc sorted
    std::vector<sigma::CoinDenominationV3> denominations;
    sigma::GetAllDenoms(denominations);

    // get smallest denominations
    CAmount smallestDenomination;
    sigma::DenominationToInteger(denominations.back(), smallestDenomination);

    for (const auto& denomination : denominations) {
        CAmount denominationValue;
        sigma::DenominationToInteger(denomination, denominationValue);

        for (int i = 0; i < amount / denominationValue; i++) {
            sigma::PrivateCoinV3 newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_3);
            sigma::PublicCoinV3 pubCoin = newCoin.getPublicCoin();

            if (!pubCoin.validate()) {
                throw std::runtime_error("Unable to mint a V3 sigma coin.");
            }

            // Create script for coin
            CScript scriptSerializedCoin;
            scriptSerializedCoin << OP_ZEROCOINMINTV3;
            std::vector<unsigned char> vch = pubCoin.getValue().getvch();
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

            outputs.push_back(CTxOut(denominationValue, scriptSerializedCoin));
            mints.push_back(newCoin);
        }

        amount %= denominationValue;
    }

    return amount;
}
