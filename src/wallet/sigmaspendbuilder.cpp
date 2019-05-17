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
        sigma::SpendMetaDataV3 meta(output.n, lastBlockOfGroup, sig);
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

    selected.clear();
    denomChanges.clear();

    if (!wallet.GetCoinsToSpend(required, selected, denomChanges)) {
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

    auto params = sigma::ParamsV3::get_default();

    CHDMint hdMint;

     uint32_t nCountLastUsed = zwalletMain->GetCount();

    for (const auto& denomination : denomChanges) {
        CAmount denominationValue;
        sigma::DenominationToInteger(denomination, denominationValue);

        sigma::PrivateCoinV3 newCoin(params, denomination, ZEROCOIN_TX_VERSION_3);
        hdMint.SetNull();
        zwalletMain->GenerateHDMint(denomination, newCoin, hdMint);
        auto& pubCoin = newCoin.getPublicCoin();

        if (!pubCoin.validate()) {
            // reset countLastUsed value
            zwalletMain->SetCount(nCountLastUsed);
            throw std::runtime_error("Unable to mint a V3 sigma coin.");
        }

        // Update local count (don't write back to DB until we know coin is verified && change has been decided)
        zwalletMain->UpdateCountLocal();

        // Create script for coin
        CScript scriptSerializedCoin;
        scriptSerializedCoin << OP_ZEROCOINMINTV3;
        std::vector<unsigned char> vch = pubCoin.getValue().getvch();
        scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

        outputs.push_back(CTxOut(denominationValue, scriptSerializedCoin));
        changes.push_back(hdMint);

        amount -= denominationValue;
    }

    return amount;
}
