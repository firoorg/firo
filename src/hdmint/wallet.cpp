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
#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "keystore.h"
#include <boost/optional.hpp>

CHDMintWallet::CHDMintWallet(std::string strWalletFile)
{
    this->strWalletFile = strWalletFile;
    CWalletDB walletdb(strWalletFile);
    this->mintPool = CMintPool();

    //Don't try to do anything else if the wallet is locked.
    if (pwalletMain->IsLocked()) {
        return;
    }

    // Use MasterKeyId from HDChain as index for mintpool
    uint160 hashSeedMaster = pwalletMain->GetHDChain().masterKeyID;

    if (!SetupWallet(hashSeedMaster)) {
        LogPrintf("%s: failed to save deterministic seed for hashseed %s\n", __func__, hashSeedMaster.GetHex());
        return;
    }
}
bool CHDMintWallet::SetupWallet(const uint160& hashSeedMaster, bool fResetCount)
{

    CWalletDB walletdb(strWalletFile);
    if (pwalletMain->IsLocked())
        return false;

    if (hashSeedMaster.IsNull()) {
        return error("%s: failed to set master seed.", __func__);
    }

    this->hashSeedMaster = hashSeedMaster;

    nCountLastUsed = COUNT_DEFAULT;
    nCountLastGenerated = COUNT_DEFAULT;

    if (fResetCount){
        walletdb.WriteZerocoinCount(nCountLastUsed);
        walletdb.WriteZerocoinSeedCount(nCountLastUsed);
    }else{
        if (!walletdb.ReadZerocoinCount(nCountLastUsed))
            nCountLastUsed = COUNT_DEFAULT;
        if (!walletdb.ReadZerocoinSeedCount(nCountLastGenerated))
            nCountLastGenerated = COUNT_DEFAULT;
    }

    return true;
}

// //Add the next 20 mints to the mint pool
void CHDMintWallet::GenerateMintPool()
{
    CWalletDB walletdb(strWalletFile);
    //Is locked
    if (pwalletMain->IsLocked())
        return;

    // Only generate new values (ie. if last generated less than or the same, proceed)
    if(nCountLastGenerated > nCountLastUsed){
        return;
    }

    int32_t nLastCount = nCountLastGenerated;

    // Generate 20 more
    int32_t nStop = nLastCount + 20;
    LogPrintf("%s : nLastCount=%d nStop=%d\n", __func__, nLastCount, nStop - 1);
    for (; nLastCount < nStop; ++nLastCount) {
        if (ShutdownRequested())
            return;

        CKeyID seedId;
        uint512 seedZerocoin = CreateZerocoinSeed(nLastCount, seedId);

        GroupElement commitmentValue;
        sigma::PrivateCoin coin(sigma::Params::get_default(), sigma::CoinDenomination::SIGMA_DENOM_1);
        if(!SeedToZerocoin(seedZerocoin, commitmentValue, coin))
            continue;

        uint256 hashPubcoin = sigma::GetPubCoinValueHash(commitmentValue);

        MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nLastCount);
        mintPool.Add(make_pair(hashPubcoin, mintPoolEntry));
        CWalletDB(strWalletFile).WriteSerialHash(sigma::GetSerialHash(coin.getSerialNumber()), hashPubcoin);
        CWalletDB(strWalletFile).WriteMintPoolPair(hashPubcoin, mintPoolEntry);
        LogPrintf("%s : %s count=%d\n", __func__, hashPubcoin.GetHex(), nLastCount);
    }

    // Update local + DB entries for count last generated
    nCountLastGenerated = nLastCount;
    walletdb.WriteZerocoinSeedCount(nCountLastGenerated);

}

bool CHDMintWallet::LoadMintPoolFromDB()
{
    vector<std::pair<uint256, MintPoolEntry>> listMintPool = CWalletDB(strWalletFile).ListMintPool();

    for (auto& mintPoolPair : listMintPool)
        mintPool.Add(mintPoolPair);

    return true;
}

//Catch the counter up with the chain
void CHDMintWallet::SyncWithChain(bool fGenerateMintPool, boost::optional<list<pair<uint256, MintPoolEntry>>> listMints)
{
    int32_t nLastCountUsed = 0;
    bool found = true;
    CWalletDB walletdb(strWalletFile);

    set<uint256> setAddedTx;
    while (found) {
        found = false;
        if (fGenerateMintPool)
            GenerateMintPool();
        LogPrintf("%s: Mintpool size=%d\n", __func__, mintPool.size());

        std::set<uint256> setChecked;
        if(listMints==boost::none){
            listMints = list<pair<uint256, MintPoolEntry>>();
            mintPool.List(listMints.get());
        }
        for (pair<uint256, MintPoolEntry>& pMint : listMints.get()) {
            LOCK(cs_main);
            if (setChecked.count(pMint.first))
                return;
            setChecked.insert(pMint.first);

            if (ShutdownRequested())
                return;

            uint160& mintHashSeedMaster = get<0>(pMint.second);
            int32_t& mintCount = get<2>(pMint.second);

            if (pwalletMain->hdMintTracker->HasPubcoinHash(pMint.first)) {
                mintPool.Remove(pMint.first);
                continue;
            }
            
            COutPoint outPoint;
            if (sigma::GetOutPoint(outPoint, pMint.first)) {
                const uint256& txHash = outPoint.hash;
                //this mint has already occurred on the chain, increment counter's state to reflect this
                LogPrintf("%s : Found wallet coin mint=%s count=%d tx=%s\n", __func__, pMint.first.GetHex(), mintCount, txHash.GetHex());
                found = true;

                uint256 hashBlock;
                CTransaction tx;
                if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock, true)) {
                    LogPrintf("%s : failed to get transaction for mint %s!\n", __func__, pMint.first.GetHex());
                    found = false;
                    nLastCountUsed = std::max(mintCount, nLastCountUsed);
                    continue;
                }

                //Find the denomination
                boost::optional<sigma::CoinDenomination> denomination = boost::none;
                bool fFoundMint = false;
                GroupElement bnValue;
                for (const CTxOut& out : tx.vout) {
                    if (!out.scriptPubKey.IsSigmaMint())
                        continue;

                    sigma::PublicCoin pubcoin;
                    CValidationState state;
                    if (!TxOutToPublicCoin(out, pubcoin, state)) {
                        LogPrintf("%s : failed to get mint from txout for %s!\n", __func__, pMint.first.GetHex());
                        continue;
                    }

                    // See if this is the mint that we are looking for
                    uint256 hashPubcoin = sigma::GetPubCoinValueHash(pubcoin.getValue());
                    if (pMint.first == hashPubcoin) {
                        denomination = pubcoin.getDenomination();
                        bnValue = pubcoin.getValue();
                        fFoundMint = true;
                        break;
                    }
                }

                if (!fFoundMint || denomination == boost::none) {
                    LogPrintf("%s : failed to get mint %s from tx %s!\n", __func__, pMint.first.GetHex(), tx.GetHash().GetHex());
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

                // TODO - temp solution to stop failure with locked wallet during syncz
                if(!pwalletMain->IsLocked())
                    SetMintSeedSeen(pMint.second, pindex->nHeight, txHash, denomination.get());

                if(!pwalletMain->IsCrypted() || (pwalletMain->IsCrypted() && hashSeedMaster == mintHashSeedMaster)){
                    nLastCountUsed = std::max(mintCount, nLastCountUsed);
                    nCountLastUsed = std::max(nLastCountUsed, nCountLastUsed);
                    LogPrint("zero", "%s: updated count to %d\n", __func__, nCountLastUsed);
                }
            }
        }
    }
}

bool CHDMintWallet::SetMintSeedSeen(MintPoolEntry mintPoolEntry, const int& nHeight, const uint256& txid, const sigma::CoinDenomination& denom)
{
    // Regenerate the mint
    uint160 mintHashSeedMaster = get<0>(mintPoolEntry);
    CKeyID seedId = get<1>(mintPoolEntry);
    int32_t mintCount = get<2>(mintPoolEntry);
    uint512 seedZerocoin = CreateZerocoinSeed(mintCount, seedId, false);
    GroupElement bnValue;
    sigma::PrivateCoin coin(sigma::Params::get_default(), denom, false);
    SeedToZerocoin(seedZerocoin, bnValue, coin);
    CWalletDB walletdb(strWalletFile);

    // Create mint object and database it
    uint256 hashSerial = sigma::GetSerialHash(coin.getSerialNumber());

    CHDMint dMint(mintCount, seedId, hashSerial, bnValue);
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

    //Update the count if it is less than the mint's count (Only update if the mint matches the current hashSeedMaster)
    if(!pwalletMain->IsCrypted() || (pwalletMain->IsCrypted() && hashSeedMaster == mintHashSeedMaster)){
        if (nCountLastUsed < mintCount) {
            nCountLastUsed = mintCount;
            walletdb.WriteZerocoinCount(nCountLastUsed);
        }
    }

    uint256 hashPubcoin = dMint.GetPubCoinHash();
    //remove from the pool
    mintPool.Remove(hashPubcoin);

    return true;
}

bool CHDMintWallet::SeedToZerocoin(const uint512& seedZerocoin, GroupElement& commit, sigma::PrivateCoin& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = seedZerocoin.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());
    coin.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, coin.getEcdsaSeckey())){
        return false;
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
    commit = sigma::SigmaPrimitives<Scalar, GroupElement>::commit(
             coin.getParams()->get_g(), coin.getSerialNumber(), coin.getParams()->get_h0(), coin.getRandomness());

    return true;
}

CKeyID CHDMintWallet::GetZerocoinSeedData(int32_t nCount, uint160 hashSeedMaster){
    // Get CKeyID for n from mintpool
    uint256 hashPubcoin;
    std::pair<uint256,MintPoolEntry> mintPoolEntryPair;

    while(!mintPool.Get(nCount, hashSeedMaster, mintPoolEntryPair)){
        // Top up mintpool if empty
        GenerateMintPool();
    }

    return get<1>(mintPoolEntryPair.second);
}

uint512 CHDMintWallet::CreateZerocoinSeed(int32_t& n, CKeyID& seedId, bool checkIndex)
{ 
    LOCK(pwalletMain->cs_wallet);
    CKey key;
    // Ensures value of child index is correct for seed being generated
    if(checkIndex){
        if(n != pwalletMain->GetHDChain().nExternalChainCounters[BIP44_MINT_INDEX])
            throw ZerocoinException("Unable to generate mint seed: incorrect value of child index.");
    }
    
    // if passed seedId, we assume generation of seed has occured.
    // Otherwise get new key to be used as seed
    if(seedId.IsNull()){
        CPubKey pubKey = pwalletMain->GenerateNewKey(BIP44_MINT_INDEX);
        seedId = pubKey.GetID();
    }

    if (!pwalletMain->CCryptoKeyStore::GetKey(seedId, key)){
        throw ZerocoinException("Unable to retrieve generated key for mint seed.");
    }

    // HMAC-SHA512(SHA256(count),key)
    unsigned char countHash[CSHA256().OUTPUT_SIZE];
    unsigned char *result = new unsigned char[CSHA512().OUTPUT_SIZE];

    std::string nCount = to_string(n);
    CSHA256().Write(reinterpret_cast<const unsigned char*>(nCount.c_str()), nCount.size()).Finalize(countHash);
    
    CHMAC_SHA512(countHash, CSHA256().OUTPUT_SIZE).Write(key.begin(), key.size()).Finalize(result);
    std::vector<unsigned char> resultVector(result, result+CSHA512().OUTPUT_SIZE);

    return uint512(resultVector);
}

int32_t CHDMintWallet::GetCount()
{
    return nCountLastUsed;
}

void CHDMintWallet::SetCount(int32_t nCount)
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

bool CHDMintWallet::GenerateMint(const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, boost::optional<MintPoolEntry> mintPoolEntry)
{
    if(mintPoolEntry==boost::none){
        CKeyID seedId = GetZerocoinSeedData(nCountLastUsed, hashSeedMaster);
        mintPoolEntry = MintPoolEntry(hashSeedMaster, seedId, nCountLastUsed);
        // Empty mintPoolEntry implies this is a new mint being created, so update nCountLastUsed
        UpdateCountLocal();
    }
    
    uint512 seedZerocoin = CreateZerocoinSeed(get<2>(mintPoolEntry.get()), get<1>(mintPoolEntry.get()), false);

    GroupElement commitmentValue;
    if(!SeedToZerocoin(seedZerocoin, commitmentValue, coin)){
        return false;
    }

    coin.setPublicCoin(sigma::PublicCoin(commitmentValue, denom));

    uint256 hashSerial = sigma::GetSerialHash(coin.getSerialNumber());
    dMint = CHDMint(get<2>(mintPoolEntry.get()), get<1>(mintPoolEntry.get()), hashSerial, coin.getPublicCoin().getValue());
    dMint.SetDenomination(denom);

    return true;
}

bool CHDMintWallet::RegenerateMint(const CHDMint& dMint, CSigmaEntry& zerocoin)
{
    //Generate the coin
    sigma::PrivateCoin coin(sigma::Params::get_default(), dMint.GetDenomination().get(), false);
    CHDMint dMintDummy;
    CKeyID seedId = dMint.GetSeedId();
    int32_t nCount = dMint.GetCount();
    MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nCount);
    GenerateMint(dMint.GetDenomination().get(), coin, dMintDummy, mintPoolEntry);

    //Fill in the zerocoinmint object's details
    GroupElement bnValue = coin.getPublicCoin().getValue();
    if (sigma::GetPubCoinValueHash(bnValue) != dMint.GetPubCoinHash())
        return error("%s: failed to correctly generate mint, pubcoin hash mismatch", __func__);
    zerocoin.value = bnValue;

    Scalar bnSerial = coin.getSerialNumber();
    if (sigma::GetSerialHash(bnSerial) != dMint.GetSerialHash())
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);

    zerocoin.set_denomination(dMint.GetDenomination().get());
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
    if (!sigma::CSigmaState::GetState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!pwalletMain->hdMintTracker->Get(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool CHDMintWallet::TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state)
{
    // If you wonder why +1, go to file wallet.cpp and read the comments in function
    // CWallet::CreateZerocoinMintModelV3 around "scriptSerializedCoin << OP_ZEROCOINMINTV3";
    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
    secp_primitives::GroupElement publicZerocoin;
    publicZerocoin.deserialize(&coin_serialised[0]);

    sigma::CoinDenomination denomination;
    if(!IntegerToDenomination(txout.nValue, denomination))
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    LogPrint("zero", "%s ZCPRINT denomination %d pubcoin %s\n", __func__, denomination, publicZerocoin.GetHex());

    sigma::PublicCoin checkPubCoin(publicZerocoin, denomination);
    pubCoin = checkPubCoin;

    return true;
}
