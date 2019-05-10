// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/wallet.h"
#include "main.h"
#include "txdb.h"
#include "init.h"
#include "hdmint/hdmint.h"
#include "sigma/openssl_context.h"
#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#include "zerocoin_v3.h"
#include "hdmint/chain.h"
#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "keystore.h"

CHDMintWallet::CHDMintWallet(std::string strWalletFile)
{
    this->strWalletFile = strWalletFile;
    CWalletDB walletdb(strWalletFile);

    //Don't try to do anything if the wallet is locked.
    if (pwalletMain->IsLocked()) {
        this->mintPool = CMintPool();
        return;
    }

    // Use MasterKeyId from HDChain as index for mintpool
    uint160 hashSeedMaster = pwalletMain->GetHDChain().masterKeyID;

    if (!SetHashSeedMaster(hashSeedMaster)) {
        LogPrintf("%s: failed to save deterministic seed for hashseed %s\n", __func__, hashSeedMaster.GetHex());
        return;
    }
    this->mintPool = CMintPool(nCountLastUsed);
}

bool CHDMintWallet::SetHashSeedMaster(const uint160& hashSeedMaster, bool fResetCount)
{

    CWalletDB walletdb(strWalletFile);
    if (pwalletMain->IsLocked())
        return false;

    if (hashSeedMaster.IsNull()) {
        return error("%s: failed to set master seed.", __func__);
    }

    this->hashSeedMaster = hashSeedMaster;

    nCountLastUsed = COUNT_LAST_USED_DEFAULT;

    if (fResetCount)
        walletdb.WriteZerocoinCount(nCountLastUsed);
    else if (!walletdb.ReadZerocoinCount(nCountLastUsed))
        nCountLastUsed = COUNT_LAST_USED_DEFAULT;

    mintPool.Reset();

    return true;
}

void CHDMintWallet::Lock()
{
    hashSeedMaster.SetNull();
}

// //Add the next 20 mints to the mint pool
void CHDMintWallet::GenerateMintPool(uint32_t nCountStart, uint32_t nCountEnd)
{

    //Is locked
    if (hashSeedMaster.IsNull())
        return;

    uint32_t n = nCountLastUsed;

    if (nCountStart > COUNT_LAST_USED_DEFAULT)
        n = nCountStart;

    uint32_t nStop = n + 20;
    if (nCountEnd > 0)
        nStop = std::max(n, n + nCountEnd);

    bool fFound;

    LogPrintf("%s : n=%d nStop=%d\n", __func__, n, nStop - 1);
    for (uint32_t i = n; i < nStop; ++i) {
        if (ShutdownRequested())
            return;

        fFound = false;

        // Prevent unnecessary repeated minted
        for (auto& pair : mintPool) {
            if(pair.second == i) {
                fFound = true;
                break;
            }
        }

        if(fFound)
            continue;

        CKeyID seedId;
        GetZerocoinSeed(i, seedId);

        mintPool.Add(seedId, i);
        CWalletDB(strWalletFile).WriteMintPoolPair(hashSeedMaster, seedId, i);
        LogPrintf("%s : %s count=%d\n", __func__, seedId.GetHex(), i);
    }
    // Load mint pool into DB following creation
    LoadMintPoolFromDB();
}

bool CHDMintWallet::LoadMintPoolFromDB()
{
    map<uint160, vector<pair<CKeyID, uint32_t> > > mapMintPool = CWalletDB(strWalletFile).MapMintPool();

    for (auto& pair : mapMintPool[hashSeedMaster])
        mintPool.Add(pair);

    return true;
}

void CHDMintWallet::GetState(int& nCount, int& nLastGenerated)
{
    nCount = this->nCountLastUsed;
    nLastGenerated = mintPool.CountOfLastGenerated();
}

//Catch the counter up with the chain
void CHDMintWallet::SyncWithChain(bool fGenerateMintPool)
{
    uint32_t nLastCountUsed = 0;
    bool found = true;
    CWalletDB walletdb(strWalletFile);

    set<uint256> setAddedTx;
    while (found) {
        found = false;
        if (fGenerateMintPool)
            GenerateMintPool();
        LogPrintf("%s: Mintpool size=%d\n", __func__, mintPool.size());

        std::set<uint160> setChecked;
        list<pair<CKeyID, uint32_t> > listMints = mintPool.List();
        for (pair<CKeyID, uint32_t> pMint : listMints) {
            LOCK(cs_main);
            if (setChecked.count(pMint.first))
                return;
            setChecked.insert(pMint.first);

            if (ShutdownRequested())
                return;

            // Regenerate pubCoinValueHash
            uint512 seedZerocoin = GetZerocoinSeed(pMint.second, pMint.first);
            GroupElement pubCoinValue;
            sigma::PrivateCoinV3 coin(sigma::ParamsV3::get_default(), sigma::CoinDenominationV3::SIGMA_DENOM_1);
            SeedToZerocoin(seedZerocoin, pubCoinValue, coin);
            uint256 pubCoinValueHash = GetPubCoinValueHash(pubCoinValue);

            if (pwalletMain->hdMintTracker->HasPubcoinHash(pubCoinValueHash)) {
                mintPool.Remove(pMint.first);
                continue;
            }

            uint256 txHash;
            if (ZerocoinGetMintTxHashV3(txHash, pubCoinValueHash)) {
                //this mint has already occurred on the chain, increment counter's state to reflect this
                LogPrintf("%s : Found wallet coin mint=%s count=%d tx=%s\n", __func__, pubCoinValueHash.GetHex(), pMint.second, txHash.GetHex());
                found = true;

                uint256 hashBlock;
                CTransaction tx;
                if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock, true)) {
                    LogPrintf("%s : failed to get transaction for mint %s!\n", __func__, pubCoinValueHash.GetHex());
                    found = false;
                    nLastCountUsed = std::max(pMint.second, nLastCountUsed);
                    continue;
                }

                //Find the denomination
                sigma::CoinDenominationV3 denomination = sigma::CoinDenominationV3::SIGMA_ERROR;
                bool fFoundMint = false;
                GroupElement bnValue;
                for (const CTxOut& out : tx.vout) {
                    if (!out.scriptPubKey.IsZerocoinMintV3())
                        continue;

                    sigma::PublicCoinV3 pubcoin;
                    CValidationState state;
                    if (!TxOutToPublicCoin(out, pubcoin, state)) {
                        LogPrintf("%s : failed to get mint from txout for %s!\n", __func__, pubCoinValueHash.GetHex());
                        continue;
                    }

                    // See if this is the mint that we are looking for
                    uint256 hashPubcoin = GetPubCoinValueHash(pubcoin.getValue());
                    if (pubCoinValueHash == hashPubcoin) {
                        denomination = pubcoin.getDenomination();
                        bnValue = pubcoin.getValue();
                        fFoundMint = true;
                        break;
                    }
                }

                if (!fFoundMint || denomination == sigma::CoinDenominationV3::SIGMA_ERROR) {
                    LogPrintf("%s : failed to get mint %s from tx %s!\n", __func__, pubCoinValueHash.GetHex(), tx.GetHash().GetHex());
                    found = false;
                    break;
                }

                CBlockIndex* pindex = nullptr;
                if (mapBlockIndex.count(hashBlock))
                    pindex = mapBlockIndex.at(hashBlock);

                if (!setAddedTx.count(txHash)) {
                    CBlock block;
                    CWalletTx wtx(pwalletMain, tx);
                    if (pindex && ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
                        wtx.SetMerkleBranch(block);

                    //Fill out wtx so that a transaction record can be created
                    wtx.nTimeReceived = pindex->GetBlockTime();
                    pwalletMain->AddToWallet(wtx, false, &walletdb);
                    setAddedTx.insert(txHash);
                }

                SetMintSeedSeen(pMint.first, pindex->nHeight, txHash, denomination);
                nLastCountUsed = std::max(pMint.second, nLastCountUsed);
                nCountLastUsed = std::max(nLastCountUsed, nCountLastUsed);
                LogPrint("zero", "%s: updated count to %d\n", __func__, nCountLastUsed);
            }
        }
    }
}

bool CHDMintWallet::SetMintSeedSeen(CKeyID& seedId, const int& nHeight, const uint256& txid, const sigma::CoinDenominationV3& denom)
{
    if (!mintPool.Has(seedId))
        return error("%s: value not in pool", __func__);
    pair<CKeyID, uint32_t> pMint;
    mintPool.Get(seedId, pMint);

    // Regenerate the mint
    uint512 seedZerocoin = GetZerocoinSeed(pMint.second, seedId);
    GroupElement bnValue;
    sigma::PrivateCoinV3 coin(sigma::ParamsV3::get_default(), denom, false);
    SeedToZerocoin(seedZerocoin, bnValue, coin);
    CWalletDB walletdb(strWalletFile);

    // Create mint object and database it
    uint256 hashSerial = GetSerialHash(coin.getSerialNumber());
    CHDMint dMint(pMint.second, seedId, hashSerial, bnValue);
    dMint.SetDenomination(denom);
    dMint.SetHeight(nHeight);

    // Check if this is also already spent
    int nHeightTx;
    uint256 txidSpend;
    CTransaction txSpend;
    if (IsSerialInBlockchain(hashSerial, nHeightTx, txidSpend, txSpend)) {
        //Find transaction details and make a wallettx and add to wallet
        dMint.SetUsed(true);
        CWalletTx wtx(pwalletMain, txSpend);
        CBlockIndex* pindex = chainActive[nHeightTx];
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
            wtx.SetMerkleBranch(block);

        wtx.nTimeReceived = pindex->nTime;
        pwalletMain->AddToWallet(wtx, false, &walletdb);
    }

    // Add to hdMintTracker which also adds to database
    pwalletMain->hdMintTracker->Add(dMint, true);

    //Update the count if it is less than the mint's count
    if (nCountLastUsed < pMint.second) {
        nCountLastUsed = pMint.second;
        walletdb.WriteZerocoinCount(nCountLastUsed);
    }

    //remove from the pool
    mintPool.Remove(seedId);

    return true;
}

void CHDMintWallet::SeedToZerocoin(const uint512& seedZerocoin, GroupElement& commit, sigma::PrivateCoinV3& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = seedZerocoin.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());
    coin.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, coin.getEcdsaSeckey())){
        throw ZerocoinException("Unable to create public key.");
    }
    // Hash the public key in the group to obtain a serial number
    Scalar serialNumber = coin.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey); 
    coin.setSerialNumber(serialNumber);

    //hash randomness seed with Bottom 256 bits of seedZerocoin
    Scalar randomness;
    uint256 nSeedRandomness = ArithToUint512(UintToArith512(seedZerocoin) >> 256).trim256();
    randomness.memberFromSeed(nSeedRandomness.begin());
    coin.setRandomness(randomness);

    // Generate a Pedersen commitment to the serial number
    commit = SigmaPrimitives<Scalar, GroupElement>::commit(
             coin.getParams()->get_g(), coin.getSerialNumber(), coin.getParams()->get_h0(), coin.getRandomness());
}

CKeyID CHDMintWallet::GetZerocoinSeedID(uint32_t n){
    // Get CKeyID for n from mintpool
    std::pair<CKeyID,uint32_t> mintPoolEntry;
    if(!mintPool.Get(n, mintPoolEntry)){
        // Top up mintpool if empty
        GenerateMintPool();
        mintPool.Get(n, mintPoolEntry);
    }

    return mintPoolEntry.first;
}

uint512 CHDMintWallet::GetZerocoinSeed(uint32_t n, CKeyID& seedId)
{ 
    LOCK(pwalletMain->cs_wallet);
    CKey key;
    // if passed seedId, we assume generation of seed has occured.
    // Otherwise get new key to be used as seed
    if(seedId.IsNull()){
        CPubKey pubKey = pwalletMain->GenerateNewKey(BIP44_MINT_INDEX);
        seedId = pubKey.GetID();
    }

    if (!pwalletMain->CCryptoKeyStore::GetKey(seedId, key)){
        throw ZerocoinException("Unable to retrieve generated key for mint seed.");
    }

    // HMAC-SHA512(count,key)
    unsigned int KEY_SIZE = 64;
    std::string nCount = to_string(n);
    unsigned char *out = new unsigned char[KEY_SIZE];

    CHMAC_SHA512(reinterpret_cast<const unsigned char*>(nCount.c_str()), nCount.size()).Write(key.begin(), key.size()).Finalize(out);
    std::vector<unsigned char> outVec(out, out+KEY_SIZE);

    return uint512(outVec);
}

uint32_t CHDMintWallet::GetCount()
{
    return nCountLastUsed;
}

void CHDMintWallet::SetCount(uint32_t nCount)
{
    nCountLastUsed = nCount;
}

void CHDMintWallet::UpdateCountLocal()
{
    nCountLastUsed++;
}

void CHDMintWallet::UpdateCountDB()
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteZerocoinCount(nCountLastUsed);
}

void CHDMintWallet::UpdateCount()
{
    UpdateCountLocal();
    UpdateCountDB();
}

void CHDMintWallet::GenerateHDMint(sigma::CoinDenominationV3 denom, sigma::PrivateCoinV3& coin, CHDMint& dMint, bool fGenerateOnly)
{
    GenerateMint(nCountLastUsed, denom, dMint.GetSeedId(), coin, dMint);
    if (fGenerateOnly)
        return;

    //TODO remove this leak of seed from logs before merge to master
    //LogPrintf("%s : Generated new deterministic mint. Count=%d pubcoin=%s seed=%s\n", __func__, nCount, coin.getPublicCoin().getValue().GetHex().substr(0,6), seedZerocoin.GetHex().substr(0, 4));
}

void CHDMintWallet::GenerateMint(const uint32_t& nCount, const sigma::CoinDenominationV3 denom, CKeyID seedId, sigma::PrivateCoinV3& coin, CHDMint& dMint)
{
    if(seedId.IsNull()){
        seedId = GetZerocoinSeedID(nCount);
    }
    uint512 seedZerocoin = GetZerocoinSeed(nCount, seedId);

    GroupElement commitmentValue;
    SeedToZerocoin(seedZerocoin, commitmentValue, coin);

    coin.setPublicCoin(sigma::PublicCoinV3(commitmentValue, denom));

    uint256 hashSerial = GetSerialHash(coin.getSerialNumber());
    dMint = CHDMint(nCount, seedId, hashSerial, coin.getPublicCoin().getValue());
    dMint.SetDenomination(denom);

}

// bool CHDMintWallet::CheckSeed(const CHDMint& dMint)
// {
//     //Check that the seed is correct    todo:handling of incorrect, or multiple seeds
//     uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
//     return hashSeed == dMint.GetSeedHash();
// }

bool CHDMintWallet::RegenerateMint(const CHDMint& dMint, CZerocoinEntryV3& zerocoin)
{
    // if (!CheckSeed(dMint)) {
    //     uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
    //     return error("%s: master seed does not match!\ndmint:\n %s \nhashSeed: %s\nseed: %s", __func__, dMint.ToString(), hashSeed.GetHex(), seedMaster.GetHex());
    // }

    //Generate the coin
    sigma::PrivateCoinV3 coin(sigma::ParamsV3::get_default(), dMint.GetDenomination(), false);
    CHDMint dMintDummy;
    GenerateMint(dMint.GetCount(), dMint.GetDenomination(), dMint.GetSeedId(), coin, dMintDummy);

    //Fill in the zerocoinmint object's details
    GroupElement bnValue = coin.getPublicCoin().getValue();
    if (GetPubCoinValueHash(bnValue) != dMint.GetPubCoinHash())
        return error("%s: failed to correctly generate mint, pubcoin hash mismatch", __func__);
    zerocoin.value = bnValue;

    Scalar bnSerial = coin.getSerialNumber();
    if (GetSerialHash(bnSerial) != dMint.GetSerialHash())
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);

    zerocoin.set_denomination(dMint.GetDenomination());
    zerocoin.randomness = coin.getRandomness();
    zerocoin.serialNumber = bnSerial;
    zerocoin.IsUsed = dMint.IsUsed();
    zerocoin.nHeight = dMint.GetHeight();
    zerocoin.id = dMint.GetId();
    zerocoin.ecdsaSecretKey = std::vector<unsigned char>(&coin.getEcdsaSeckey()[0],&coin.getEcdsaSeckey()[32]);

    return true;
}

bool CHDMintWallet::IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransaction& tx)
{
    txidSpend.SetNull();
    CMintMeta mMeta;
    Scalar bnSerial;
    if (!CZerocoinStateV3::GetZerocoinState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!pwalletMain->hdMintTracker->Get(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool CHDMintWallet::TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoinV3& pubCoin, CValidationState& state)
{
    // If you wonder why +1, go to file wallet.cpp and read the comments in function
    // CWallet::CreateZerocoinMintModelV3 around "scriptSerializedCoin << OP_ZEROCOINMINTV3";
    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
    secp_primitives::GroupElement publicZerocoin;
    publicZerocoin.deserialize(&coin_serialised[0]);

    sigma::CoinDenominationV3 denomination;
    IntegerToDenomination(txout.nValue, denomination);
    LogPrint("zero", "%s ZCPRINT denomination %d pubcoin %s\n", __func__, denomination, publicZerocoin.GetHex());
    if (denomination == CoinDenominationV3::SIGMA_ERROR)
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    sigma::PublicCoinV3 checkPubCoin(publicZerocoin, denomination);
    pubCoin = checkPubCoin;

    return true;
}
