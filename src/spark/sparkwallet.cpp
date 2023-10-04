#include "../liblelantus/threadpool.h"
#include "sparkwallet.h"
#include "../wallet/wallet.h"
#include "../wallet/coincontrol.h"
#include "../wallet/walletexcept.h"
#include "../hash.h"
#include "../validation.h"
#include "../policy/policy.h"
#include "../script/sign.h"
#include "state.h"
#include "../llmq/quorums_instantsend.h"

#include <boost/format.hpp>

const uint32_t DEFAULT_SPARK_NCOUNT = 1;

CSparkWallet::CSparkWallet(const std::string& strWalletFile) {

    CWalletDB walletdb(strWalletFile);
    this->strWalletFile = strWalletFile;

    const spark::Params* params = spark::Params::get_default();

    fullViewKey = spark::FullViewKey(params);
    viewKey = spark::IncomingViewKey(params);

    bool fWalletJustUnlocked = false;

    // try to get incoming view key from db, if it fails, that means it is first start
    if (!walletdb.readFullViewKey(fullViewKey)) {
        if (pwalletMain->IsLocked()) {
            pwalletMain->RequestUnlock();
            if (pwalletMain->WaitForUnlock()) {
                fWalletJustUnlocked = true;
            } else {
                throw std::runtime_error("Spark wallet creation FAILED, wallet could not be unlocked\n");
                return;
            }
        }

        // Generating spark key set first time
        spark::SpendKey spendKey = generateSpendKey(params);
        fullViewKey = generateFullViewKey(spendKey);
        viewKey = generateIncomingViewKey(fullViewKey);

        // Write incoming view key into db, it is safe to be kept in db, it is used to identify incoming coins belonging to the wallet
        walletdb.writeFullViewKey(fullViewKey);
        // generate one initial address for wallet
        lastDiversifier = 0;
        addresses[lastDiversifier] = getDefaultAddress();
        // set 0 as last diversifier into db, we will update it later, in case coin comes, or user manually generates new address
        walletdb.writeDiversifier(lastDiversifier);
    } else {
        viewKey = generateIncomingViewKey(fullViewKey);
        int32_t diversifierInDB = 0;
        // read diversifier from db
        walletdb.readDiversifier(diversifierInDB);
        lastDiversifier = -1;

        // generate all used addresses
         while (lastDiversifier <  diversifierInDB) {
             addresses[lastDiversifier] = generateNextAddress();
         }

         // get the list of coin metadata from db
        {
            LOCK(cs_spark_wallet);
            coinMeta = walletdb.ListSparkMints();
            for (auto& coin : coinMeta) {
                coin.second.coin.setParams(params);
                coin.second.coin.setSerialContext(coin.second.serial_context);

            }
        }

    }
    threadPool = new ParallelOpThreadPool<void>(boost::thread::hardware_concurrency());

    if (fWalletJustUnlocked)
        pwalletMain->Lock();
}

CSparkWallet::~CSparkWallet() {
    delete (ParallelOpThreadPool<void>*)threadPool;
}

void CSparkWallet::resetDiversifierFromDB(CWalletDB& walletdb) {
    walletdb.readDiversifier(lastDiversifier);
}

void CSparkWallet::updatetDiversifierInDB(CWalletDB& walletdb) {
    walletdb.writeDiversifier(lastDiversifier);
}

CAmount CSparkWallet::getFullBalance() {
    return getAvailableBalance() + getUnconfirmedBalance();
}

CAmount CSparkWallet::getAvailableBalance() {
    CAmount result = 0;
    LOCK(cs_spark_wallet);
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;

        if (mint.isUsed)
            continue;

        // Not confirmed
        if (mint.nHeight < 1)
            continue;

        result += mint.v;
    }

    return result;
}

CAmount CSparkWallet::getUnconfirmedBalance() {
    CAmount result = 0;
    LOCK(cs_spark_wallet);
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;
        if (mint.isUsed)
            continue;

        // Continue if confirmed
        if (mint.nHeight > 1)
            continue;

        result += mint.v;
    }

    return result;
}

CAmount CSparkWallet::getAddressFullBalance(const spark::Address& address) {
    return getAddressAvailableBalance(address) + getAddressUnconfirmedBalance(address);
}

CAmount CSparkWallet::getAddressAvailableBalance(const spark::Address& address) {
    CAmount result = 0;
    LOCK(cs_spark_wallet);
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;

        if (mint.isUsed)
            continue;

        // Not confirmed
        if (mint.nHeight < 1)
            continue;

        if (address.get_d() != mint.d)
            continue;

        result += mint.v;
    }

    return result;
}

CAmount CSparkWallet::getAddressUnconfirmedBalance(const spark::Address& address) {
    CAmount result = 0;
    LOCK(cs_spark_wallet);
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;

        if (mint.isUsed)
            continue;

        // Not confirmed
        if (mint.nHeight > 1)
            continue;

        if (address.get_d() != mint.d)
            continue;

        result += mint.v;
    }

    return result;
}

spark::Address CSparkWallet::generateNextAddress() {
    lastDiversifier++;
    return spark::Address(viewKey, lastDiversifier);
}

spark::Address CSparkWallet::generateNewAddress() {
    lastDiversifier++;
    spark::Address address(viewKey, lastDiversifier);

    addresses[lastDiversifier] = address;
    CWalletDB walletdb(strWalletFile);
    updatetDiversifierInDB(walletdb);
    return  address;
}

spark::Address CSparkWallet::getDefaultAddress() {
    if (addresses.count(0))
        return addresses[0];
    lastDiversifier = 0;
    return spark::Address(viewKey, lastDiversifier);
}

spark::Address CSparkWallet::getChangeAddress() {
    return spark::Address(viewKey, SPARK_CHANGE_D);
}

spark::SpendKey CSparkWallet::generateSpendKey(const spark::Params* params) {
    if (pwalletMain->IsLocked()) {
        LogPrintf("Spark spend key generation FAILED, wallet is locked\n");
        return spark::SpendKey(params);
    }

    CKey secret;
    uint32_t nCount;
    {
        LOCK(pwalletMain->cs_wallet);
        nCount = GetArg("-sparkncount", DEFAULT_SPARK_NCOUNT);
        pwalletMain->GetKeyFromKeypath(BIP44_SPARK_INDEX, nCount, secret);
    }

    std::string nCountStr = std::to_string(nCount);
    CHash256 hasher;
    std::string prefix = "r_generation";
    hasher.Write(reinterpret_cast<const unsigned char*>(prefix.c_str()), prefix.size());
    hasher.Write(secret.begin(), secret.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(nCountStr.c_str()), nCountStr.size());
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);

    secp_primitives::Scalar r;
    r.memberFromSeed(hash);
    spark::SpendKey key(params, r);
    return key;
}

spark::FullViewKey CSparkWallet::generateFullViewKey(const spark::SpendKey& spend_key) {
    return spark::FullViewKey(spend_key);
}

spark::IncomingViewKey CSparkWallet::generateIncomingViewKey(const spark::FullViewKey& full_view_key) {
    viewKey = spark::IncomingViewKey(full_view_key);
    return viewKey;
}

std::unordered_map<int32_t, spark::Address> CSparkWallet::getAllAddresses() {
    return addresses;
}

spark::Address CSparkWallet::getAddress(const int32_t& i) {
    if (lastDiversifier < i || addresses.count(i) == 0)
        return spark::Address(viewKey, lastDiversifier);

    return addresses[i];
}

bool CSparkWallet::isAddressMine(const std::string& encodedAddr) {
    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);
    try {
        address.decode(encodedAddr);
    } catch (...) {
        return false;
    }

    for (const auto& itr : addresses) {
        if (itr.second.get_Q1() == address.get_Q1() && itr.second.get_Q2() == address.get_Q2())
            return true;
    }

    uint64_t d;

    try {
        d = viewKey.get_diversifier(address.get_d());
    } catch (...) {
        return false;
    }

    spark::Address newAddr = getAddress(int32_t(d));
    if (newAddr.get_Q1() == address.get_Q1() && newAddr.get_Q2() == address.get_Q2())
        return true;

    return false;
}

bool CSparkWallet::isChangeAddress(const uint64_t& i) const {
    return i == SPARK_CHANGE_D;
}

std::vector<CSparkMintMeta> CSparkWallet::ListSparkMints(bool fUnusedOnly, bool fMatureOnly) const {
    std::vector<CSparkMintMeta> setMints;
    LOCK(cs_spark_wallet);
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;
        if (fUnusedOnly && mint.isUsed)
            continue;

        // Not confirmed
        if (fMatureOnly && mint.nHeight < 1)
            continue;

        setMints.push_back(mint);
    }

    return setMints;
}

std::list<CSparkSpendEntry> CSparkWallet::ListSparkSpends() const {
    std::list<CSparkSpendEntry> result;
    CWalletDB walletdb(strWalletFile);
    walletdb.ListSparkSpends(result);
    return result;
}

std::unordered_map<uint256, CSparkMintMeta> CSparkWallet::getMintMap() const {
    LOCK(cs_spark_wallet);
    return coinMeta;
}


spark::Coin CSparkWallet::getCoinFromMeta(const CSparkMintMeta& meta) const {
    const spark::Params* params = spark::Params::get_default();
    if (meta.coin != spark::Coin())
        return meta.coin;

    spark::Address address(viewKey, meta.i);
    return spark::Coin(params, meta.type, meta.k, address, meta.v, meta.memo, meta.serial_context);
}

spark::Coin CSparkWallet::getCoinFromLTagHash(const uint256& lTagHash) const {
    LOCK(cs_spark_wallet);
    CSparkMintMeta meta;
    if (coinMeta.count(lTagHash)) {
        meta = coinMeta.at(lTagHash);
        return getCoinFromMeta(meta);
    }
    return spark::Coin();
}

spark::Coin CSparkWallet::getCoinFromLTag(const GroupElement& lTag) const {
    uint256 lTagHash = primitives::GetLTagHash(lTag);
    return getCoinFromLTagHash(lTagHash);
}


void CSparkWallet::clearAllMints(CWalletDB& walletdb) {
    LOCK(cs_spark_wallet);
    for (auto& itr : coinMeta) {
        walletdb.EraseSparkMint(itr.first);
    }

    coinMeta.clear();
    lastDiversifier = 0;
    walletdb.writeDiversifier(lastDiversifier);
}

void CSparkWallet::eraseMint(const uint256& hash, CWalletDB& walletdb) {
    LOCK(cs_spark_wallet);
    walletdb.EraseSparkMint(hash);
    coinMeta.erase(hash);
}

void CSparkWallet::addOrUpdateMint(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb) {
    LOCK(cs_spark_wallet);

    if (mint.i > lastDiversifier) {
        lastDiversifier = mint.i;
        walletdb.writeDiversifier(lastDiversifier);
    }
    coinMeta[lTagHash] = mint;
    walletdb.WriteSparkMint(lTagHash, mint);
}

void CSparkWallet::updateMint(const CSparkMintMeta& mint, CWalletDB& walletdb) {
    LOCK(cs_spark_wallet);
    for (const auto& coin : coinMeta) {
        if (mint ==  coin.second) {
            addOrUpdateMint(mint, coin.first, walletdb);
        }
    }
}

void CSparkWallet::setCoinUnused(const GroupElement& lTag) {
    LOCK(cs_spark_wallet);
    CWalletDB walletdb(strWalletFile);
    uint256 lTagHash = primitives::GetLTagHash(lTag);
    CSparkMintMeta coinMeta = getMintMeta(lTagHash);

    if (coinMeta != CSparkMintMeta()) {
        coinMeta.isUsed = false;
        updateMint(coinMeta, walletdb);
    }
}

void CSparkWallet::updateMintInMemory(const CSparkMintMeta& mint) {
    LOCK(cs_spark_wallet);
    for (auto& itr : coinMeta) {
        if (itr.second == mint) {
            coinMeta[itr.first] = mint;
            break;
        }
    }
}

CSparkMintMeta CSparkWallet::getMintMeta(const uint256& hash) {
    LOCK(cs_spark_wallet);
    if (coinMeta.count(hash))
        return coinMeta[hash];
    return CSparkMintMeta();
}

CSparkMintMeta CSparkWallet::getMintMeta(const secp_primitives::Scalar& nonce) {
    LOCK(cs_spark_wallet);
    for (const auto& meta : coinMeta) {
        if (meta.second.k == nonce)
            return meta.second;
    }

    return CSparkMintMeta();
}

bool CSparkWallet::getMintAmount(spark::Coin coin, CAmount& amount) {
    spark::IdentifiedCoinData identifiedCoinData;
    try {
        identifiedCoinData = coin.identify(this->viewKey);
    } catch (...) {
        return false;
    }
    amount = identifiedCoinData.v;
    return true;
}

void CSparkWallet::UpdateSpendState(const GroupElement& lTag, const uint256& lTagHash, const uint256& txHash, bool fUpdateMint) {
    if (coinMeta.count(lTagHash)) {
        auto mintMeta = coinMeta[lTagHash];

        CSparkSpendEntry spendEntry;
        spendEntry.lTag = lTag;
        spendEntry.lTagHash = lTagHash;
        spendEntry.hashTx = txHash;
        spendEntry.amount = mintMeta.v;

        CWalletDB walletdb(strWalletFile);
        walletdb.WriteSparkSpendEntry(spendEntry);

        if (fUpdateMint) {
            mintMeta.isUsed = true;
            addOrUpdateMint(mintMeta, lTagHash, walletdb);
        }

//        pwalletMain->NotifyZerocoinChanged(
//                pwalletMain,
//                lTagHash.GetHex(),
//                std::string("used (") + std::to_string((double)mintMeta.v / COIN) + "mint)",
//                CT_UPDATED);
    }
}

void CSparkWallet::UpdateSpendState(const GroupElement& lTag, const uint256& txHash, bool fUpdateMint) {
    uint256 lTagHash = primitives::GetLTagHash(lTag);
    UpdateSpendState(lTag, lTagHash, txHash, fUpdateMint);
}

void CSparkWallet::UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags, const uint256& txHash, bool fUpdateMint) {
    ((ParallelOpThreadPool<void>*)threadPool)->PostTask([=]() {
        LOCK(cs_spark_wallet);
        for (const auto& lTag : lTags) {
            uint256 lTagHash = primitives::GetLTagHash(lTag);
            if (coinMeta.count(lTagHash)) {
                UpdateSpendState(lTag, lTagHash, txHash, fUpdateMint);
            }
        }
    });
}

void CSparkWallet::UpdateSpendStateFromBlock(const CBlock& block) {
    const auto& transactions = block.vtx;
    ((ParallelOpThreadPool<void>*)threadPool)->PostTask([=]() {
        LOCK(cs_spark_wallet);
        for (const auto& tx : transactions) {
            if (tx->IsSparkSpend()) {
                try {
                    spark::SpendTransaction spend = spark::ParseSparkSpend(*tx);
                    const auto& txLTags = spend.getUsedLTags();
                    for (const auto& txLTag : txLTags) {
                        uint256 txHash = tx->GetHash();
                        uint256 lTagHash = primitives::GetLTagHash(txLTag);
                        UpdateSpendState(txLTag, lTagHash, txHash);
                    }
                } catch (...) {
                }
            }
        }
    });
}

bool CSparkWallet::isMine(spark::Coin coin) const {
    try {
        spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
    } catch (...) {
        return false;
    }

    return true;
}

bool CSparkWallet::isMine(const std::vector<GroupElement>& lTags) const {
    LOCK(cs_spark_wallet);
    for (const auto& lTag : lTags) {
        uint256 lTagHash = primitives::GetLTagHash(lTag);
        if (coinMeta.count(lTagHash)) {
            return true;
        }
    }

    return false;
}

CAmount CSparkWallet::getMyCoinV(spark::Coin coin) const {
    CAmount v(0);
    try {
        spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
        v = identifiedCoinData.v;
    } catch (const std::runtime_error& e) {
        //don nothing
    }
    return v;
}

bool CSparkWallet::getMyCoinIsChange(spark::Coin coin) const {
    try {
        spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
        return isChangeAddress(identifiedCoinData.i);
    } catch (const std::runtime_error& e) {
        return false;
    }
}

CAmount CSparkWallet::getMySpendAmount(const std::vector<GroupElement>& lTags) const {
    CAmount result = 0;
    LOCK(cs_spark_wallet);
    for (const auto& lTag : lTags) {
        uint256 lTagHash = primitives::GetLTagHash(lTag);
        if (coinMeta.count(lTagHash)) {
            result += coinMeta.at(lTagHash).v;
        }
    }

    return result;
}

void CSparkWallet::UpdateMintState(const std::vector<spark::Coin>& coins, const uint256& txHash, CWalletDB& walletdb) {
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    for (auto coin : coins) {
        try {
            spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
            spark::RecoveredCoinData recoveredCoinData = coin.recover(this->fullViewKey, identifiedCoinData);
            CSparkMintMeta mintMeta;
            auto mintedCoinHeightAndId = sparkState->GetMintedCoinHeightAndId(coin);
            mintMeta.nHeight = mintedCoinHeightAndId.first;
            mintMeta.nId = mintedCoinHeightAndId.second;
            mintMeta.isUsed = false;
            mintMeta.txid = txHash;
            mintMeta.i = identifiedCoinData.i;
            mintMeta.d = identifiedCoinData.d;
            mintMeta.v = identifiedCoinData.v;
            mintMeta.k = identifiedCoinData.k;
            mintMeta.memo = identifiedCoinData.memo;
            mintMeta.serial_context = coin.serial_context;
            mintMeta.coin = coin;
            mintMeta.type = coin.type;
            //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
            {
                LOCK(mempool.cs);
                mintMeta.isUsed = mempool.sparkState.HasLTag(recoveredCoinData.T);
            }

            uint256 lTagHash = primitives::GetLTagHash(recoveredCoinData.T);
            addOrUpdateMint(mintMeta, lTagHash, walletdb);

            if (mintMeta.isUsed) {
                uint256 spendTxHash;
                {
                    LOCK(mempool.cs);
                    spendTxHash = mempool.sparkState.GetMempoolConflictingTxHash(recoveredCoinData.T);
                }
                UpdateSpendState(recoveredCoinData.T, lTagHash, spendTxHash, false);
            }

//            pwalletMain->NotifyZerocoinChanged(
//                    pwalletMain,
//                    lTagHash.GetHex(),
//                    std::string("Update (") + std::to_string((double)mintMeta.v / COIN) + "mint)",
//                    CT_UPDATED);
        } catch (const std::runtime_error& e) {
            continue;
        }
    }
}

void CSparkWallet::UpdateMintStateFromMempool(const std::vector<spark::Coin>& coins, const uint256& txHash) {
    ((ParallelOpThreadPool<void>*)threadPool)->PostTask([=]() mutable {
        LOCK(cs_spark_wallet);
        CWalletDB walletdb(strWalletFile);
        UpdateMintState(coins, txHash, walletdb);
    });
}

void CSparkWallet::UpdateMintStateFromBlock(const CBlock& block) {
    const auto& transactions = block.vtx;

    ((ParallelOpThreadPool<void>*)threadPool)->PostTask([=] () mutable {
        LOCK(cs_spark_wallet);
        CWalletDB walletdb(strWalletFile);
        for (const auto& tx : transactions) {
            if (tx->IsSparkTransaction()) {
                auto coins =  spark::GetSparkMintCoins(*tx);
                uint256 txHash = tx->GetHash();
                UpdateMintState(coins, txHash, walletdb);
            }
        }
    });
}

void CSparkWallet::RemoveSparkMints(const std::vector<spark::Coin>& mints) {
    for (auto coin : mints) {
        try {
            spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
            spark::RecoveredCoinData recoveredCoinData = coin.recover(this->fullViewKey, identifiedCoinData);

            CWalletDB walletdb(strWalletFile);
            uint256 lTagHash = primitives::GetLTagHash(recoveredCoinData.T);

            eraseMint(lTagHash, walletdb);
        } catch (const std::runtime_error &e) {
            continue;
        }
    }
}


void CSparkWallet::RemoveSparkSpends(const std::unordered_map<GroupElement, int>& spends) {
    LOCK(cs_spark_wallet);
    for (const auto& spend : spends) {
        uint256 lTagHash = primitives::GetLTagHash(spend.first);
        if (coinMeta.count(lTagHash)) {
            auto mintMeta = coinMeta[lTagHash];
            mintMeta.isUsed = false;
            CWalletDB walletdb(strWalletFile);
            addOrUpdateMint(mintMeta, lTagHash, walletdb);
            walletdb.EraseSparkSpendEntry(spend.first);
        }
    }
}

void CSparkWallet::AbandonSparkMints(const std::vector<spark::Coin>& mints) {
    RemoveSparkMints(mints);
}

void CSparkWallet::AbandonSpends(const std::vector<GroupElement>& spends) {
    LOCK(cs_spark_wallet);
    for (const auto& spend : spends) {
        uint256 lTagHash = primitives::GetLTagHash(spend);
        if (coinMeta.count(lTagHash)) {
            auto mintMeta = coinMeta[lTagHash];
            mintMeta.isUsed = false;
            CWalletDB walletdb(strWalletFile);
            addOrUpdateMint(mintMeta, lTagHash, walletdb);
            walletdb.EraseSparkSpendEntry(spend);
        }
    }
}

std::vector<CSparkMintMeta> CSparkWallet::listAddressCoins(const int32_t& i, bool fUnusedOnly) {
    std::vector<CSparkMintMeta> listMints;
    LOCK(cs_spark_wallet);
    for (auto& itr : coinMeta) {
        if (itr.second.i == i) {
            if (fUnusedOnly && itr.second.isUsed)
                continue;
            listMints.push_back(itr.second);
        }
    }
    return listMints;
}

std::vector<CRecipient> CSparkWallet::CreateSparkMintRecipients(
        const std::vector<spark::MintedCoinData>& outputs,
        const std::vector<unsigned char>& serial_context,
        bool generate)
{
    const spark::Params* params = spark::Params::get_default();

    // create spark mints, if generate is false, skip actual math operations
    spark::MintTransaction sparkMint(params, outputs, serial_context, generate);

    // verify if the mint is valid
    if (generate && !sparkMint.verify()) {
        throw std::runtime_error("Unable to validate spark mint.");
    }

    // get serialized coins, also a schnorr proof with first coin,
    std::vector<CDataStream> serializedCoins = sparkMint.getMintedCoinsSerialized();

    if (outputs.size() != serializedCoins.size())
        throw std::runtime_error("Spark mint output number should be equal to required number.");

    std::vector<CRecipient> results;
    results.reserve(outputs.size());

    // serialize coins and put into scripts
    for (size_t i = 0; i < outputs.size(); i++) {
        // Create script for a coin
        CScript script;
        // opcode is inserted as 1 byte according to file script/script.h
        script << OP_SPARKMINT;
        script.insert(script.end(), serializedCoins[i].begin(), serializedCoins[i].end());
        CRecipient recipient = {script, CAmount(outputs[i].v), false};
        results.emplace_back(recipient);
    }

    return results;
}

bool CSparkWallet::CreateSparkMintTransactions(
    const std::vector<spark::MintedCoinData>& outputs,
    std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
    std::list<CReserveKey>& reservekeys,
    bool subtractFeeFromAmount,
    std::string& strFailReason,
    const CCoinControl *coinControl,
    bool autoMintAll)
{
    AssertLockHeld(pwalletMain->cs_wallet);

    std::vector<CTransparentTxout> vTransparentTxouts = pwalletMain->GetTransparentTxouts();
    return CreateSparkMintTransactions(
        outputs,
        wtxAndFee,
        reservekeys,
        subtractFeeFromAmount,
        strFailReason,
        coinControl,
        autoMintAll,
        vTransparentTxouts
    );
}

bool CSparkWallet::CreateSparkMintTransactions(
    const std::vector<spark::MintedCoinData>& sparkOutputs,
    std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
    std::list<CReserveKey>& reservekeys,
    bool subtractFeeFromAmount,
    std::string& strFailReason,
    const CCoinControl *coinControl,
    bool autoMintAll,
    const std::vector<CTransparentTxout>& vTransparentTxouts)
{
    size_t SPARK_FIRST_MINT_SIZE = 311;

    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);
    AssertLockHeld(llmq::quorumInstantSendManager->cs);

    assert(sparkOutputs.empty() == autoMintAll);
    assert(!autoMintAll || subtractFeeFromAmount);

    reservekeys.clear();
    strFailReason.clear();
    wtxAndFee.clear();

    size_t nConstantSize = 4 + // version
        GetSizeOfCompactSize(sparkOutputs.size() + 1) + // This is a varint representing the number of outputs. In the
                                                        // event that there are 0xfc outputs and a change output is not
                                                        // required we will pay the fee for one extra byte.
        4 + // locktime
        8 + // output value
        GetSizeOfCompactSize(SPARK_FIRST_MINT_SIZE) +
        SPARK_FIRST_MINT_SIZE;


    // Note that vAvailable is deterministic, but not sorted.
    std::vector<CTransparentTxout> vAvailable;
    try {
        std::vector<CTransparentTxout> vCoinControlInputs;
        pwalletMain->GetAvailableInputs(vTransparentTxouts, vAvailable, vCoinControlInputs, coinControl, true);
        vAvailable.insert(vAvailable.end(), vCoinControlInputs.begin(), vCoinControlInputs.end());
    } catch (std::runtime_error& e) {
        strFailReason = _(e.what());
        return false;
    }

    // Group CTransparentTxouts by output address. vSegmented is deterministic but unsorted.
    std::vector<std::pair<CAmount, std::vector<CTransparentTxout>>> vSegmented;
    for (const CTransparentTxout& txout: vAvailable) {
        bool fFound = false;
        for (std::pair<CAmount, std::vector<CTransparentTxout>>& vAmountSegment: vSegmented) {
            if (vAmountSegment.second.at(0).GetScriptPubkey() == txout.GetScriptPubkey()) {
                vAmountSegment.first += txout.GetValue();
                vAmountSegment.second.push_back(txout);
                fFound = true;
                break;
            }
        }

        if (!fFound)
            vSegmented.emplace_back(std::make_pair(txout.GetValue(), std::vector<CTransparentTxout>{txout}));
    }

    std::vector<spark::MintedCoinData> sparkOutputs_ = sparkOutputs;
    if (autoMintAll) {
        spark::MintedCoinData output;
        output.v = 0;
        output.memo = "";
        output.address = getDefaultAddress();

        sparkOutputs_.emplace_back(output);
    }

    // Create input, output pairs for our new transactions. In certain rare cases with multiple sparkOutputs, this
    // algorithm may fail to find a solution even if one exists.
    std::vector<std::pair<std::vector<CTransparentTxout>, std::pair<spark::MintedCoinData, CAmount>>> vInOut;
    for (const spark::MintedCoinData& output: sparkOutputs_) {
        if (output.v > INT64_MAX)
            throw std::runtime_error("Invalid amount");

        bool isMintAll = output.v == 0;
        CAmount nRequired = isMintAll ? INT64_MAX : output.v;

        for (std::pair<CAmount, std::vector<CTransparentTxout>>& vAmountSegment: vSegmented) {
            std::vector<CTransparentTxout>& vRemaining = vAmountSegment.second;

            while (!vRemaining.empty() && nRequired > 0) {
                CAmount nInputSize = 0;

                spark::MintedCoinData output_ = output;
                std::vector<CTransparentTxout> vSingleTxInputs;
                CAmount nFee = 0;
                CAmount nCollected = 0;
                if (pwalletMain->GetInputsForTx(vRemaining, vSingleTxInputs, nFee, nCollected, nRequired, nConstantSize,
                                                coinControl, true, subtractFeeFromAmount, true)) {
                    output_.v = subtractFeeFromAmount ? nRequired - nFee : nRequired;
                } else {
                    if (!nFee)
                        break;

                    output_.v = nCollected - nFee;
                }

                nRequired -= output_.v;
                if (subtractFeeFromAmount)
                    nRequired -= nFee;
                assert(nRequired >= 0);

                vInOut.emplace_back(std::make_pair(vSingleTxInputs, std::make_pair(output_, nFee)));

                vRemaining.erase(
                    std::remove_if(
                        vRemaining.begin(),
                        vRemaining.end(),
                        [&vSingleTxInputs](const CTransparentTxout& txout_) {
                            for (const CTransparentTxout& txout: vSingleTxInputs) {
                                if (txout.GetOutpoint() == txout_.GetOutpoint())
                                    return true;
                            }
                            return false;
                        }
                    ),
                    vRemaining.end()
                );
            }
        }

        if (!isMintAll && nRequired > 0)
            throw std::runtime_error("Insufficient funds");
    }

    for (const std::pair<std::vector<CTransparentTxout>, std::pair<spark::MintedCoinData, CAmount>>& inOut: vInOut) {
        const std::vector<CTransparentTxout>& vInputs = inOut.first;
        const spark::MintedCoinData& output = inOut.second.first;
        const CAmount& nFee = inOut.second.second;

        CAmount extraFee = 0;
        CReserveKey reservekey(pwalletMain);
        CWalletTx wtx;

        try {
            CreateSparkMintTransaction(output, wtx, reservekey, nFee, extraFee, vInputs, coinControl);
        } catch(std::runtime_error& e) {
            LogPrintf("%s(): %s\n", __func__, e.what());
            strFailReason = e.what();
            reservekeys.clear();
            wtxAndFee.clear();
            return false;
        }

        reservekeys.emplace_back(std::move(reservekey));
        wtxAndFee.emplace_back(std::make_pair(wtx, nFee + extraFee));
    }

    return true;
}

void CSparkWallet::CreateSparkMintTransaction(
    const spark::MintedCoinData& sparkOutput,
    CWalletTx& wtx,
    CReserveKey& reservekey,
    CAmount nFee,
    CAmount& extraFee,
    const std::vector<CTransparentTxout>& vInputTxs,
    const CCoinControl* coinControl)
{
    size_t SPARK_FIRST_MINT_SIZE = 311;

    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);
    AssertLockHeld(llmq::quorumInstantSendManager->cs);

    extraFee = 0;
    wtx.Init(nullptr);
    reservekey = CReserveKey(pwalletMain);

    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();

    CDataStream serialContextStream(SER_NETWORK, PROTOCOL_VERSION);

    CAmount nCollected = 0;
    for (const CTransparentTxout& txin: vInputTxs) {
        serialContextStream << CTxIn(txin.GetOutpoint());
        txNew.vin.emplace_back(txin.GetOutpoint());
        nCollected += txin.GetValue();
    }

    std::vector<unsigned char> serialContext{serialContextStream.begin(), serialContextStream.end()};
    std::vector<CRecipient> recipients = CreateSparkMintRecipients({sparkOutput}, serialContext, true);

    assert(recipients.size() == 1);
    assert(recipients.at(0).scriptPubKey.size() == SPARK_FIRST_MINT_SIZE);

    txNew.vout.emplace_back(recipients.at(0).nAmount, recipients.at(0).scriptPubKey);

    bool fHasChange = false;
    if (recipients.at(0).nAmount < nCollected - nFee) {
        CAmount nChange = nCollected - recipients.at(0).nAmount - nFee;

        CPubKey changeKey;
        if (!reservekey.GetReservedKey(changeKey))
            throw std::runtime_error("Couldn't reserve changeKey");


        CTxDestination dest(changeKey.GetID());
        CScript changeScript = GetScriptForDestination(dest);

        CTxOut change(nChange, changeScript);

        if (change.IsDust()) {
            reservekey.ReturnKey();
            extraFee = nChange;
        } else {
            reservekey.KeepKey();
            txNew.vout.push_back(change);
            fHasChange = true;
        }
    } else {
        reservekey.ReturnKey();
    }

    CCoinControl coinControl_;
    if (coinControl) {
        coinControl_ = *coinControl;
        coinControl_.fAllowOtherInputs = true;
        coinControl_.fRequireAllInputs = false;
        coinControl_.UnSelectAll();
    }

    pwalletMain->SignTransparentInputs(txNew, vInputTxs, true);
    pwalletMain->CheckTransparentTransactionSanity(txNew, vInputTxs, &coinControl_, nFee, fHasChange, true);

    wtx.fFromMe = true;
    wtx.fTimeReceivedIsTxTime = true;
    wtx.BindWallet(pwalletMain);
    wtx.SetTx(MakeTransactionRef(std::move(txNew)));
}

bool getIndex(const spark::Coin& coin, const std::vector<spark::Coin>& anonymity_set, size_t& index) {
    for (std::size_t j = 0; j < anonymity_set.size(); ++j) {
        if (anonymity_set[j] == coin){
            index = j;
            return true;
        }
    }
    return false;
}

CWalletTx CSparkWallet::CreateSparkSpendTransaction(
        const std::vector<CRecipient>& recipients,
        const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
        CAmount &fee,
        const CCoinControl *coinControl) {

    if (recipients.empty() && privateRecipients.empty()) {
        throw std::runtime_error(_("Either recipients or newMints has to be nonempty."));
    }

    const auto &consensusParams = Params().GetConsensus();
    if (privateRecipients.size() >= (consensusParams.nMaxSparkOutLimitPerTx - 1))
        throw std::runtime_error(_("Spark shielded output limit exceeded."));

    // calculate total value to spend
    CAmount vOut = 0;
    CAmount mintVOut = 0;
    unsigned recipientsToSubtractFee = 0;

    for (size_t i = 0; i < recipients.size(); i++) {
        auto& recipient = recipients[i];

        if (!MoneyRange(recipient.nAmount)) {
            throw std::runtime_error(boost::str(boost::format(_("Recipient has invalid amount")) % i));
        }

        vOut += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            recipientsToSubtractFee++;
        }
    }

    for (const auto& privRecipient : privateRecipients) {
        mintVOut += privRecipient.first.v;
        if (privRecipient.second) {
            recipientsToSubtractFee++;
        }
    }

    if (vOut > consensusParams.nMaxValueSparkSpendPerTransaction)
        throw std::runtime_error(_("Spend to transparent address limit exceeded (10,000 Firo per transaction)."));

    std::vector<CWalletTx> result;
    std::vector<CMutableTransaction> txs;
    CWalletTx wtxNew;
    CMutableTransaction tx;
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(pwalletMain);


    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    tx.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0) {
        tx.nLockTime = std::max(0, static_cast<int>(tx.nLockTime) - GetRandInt(100));
    }

    assert(tx.nLockTime <= static_cast<unsigned>(chainActive.Height()));
    assert(tx.nLockTime < LOCKTIME_THRESHOLD);
    std::list<CSparkMintMeta> coins = GetAvailableSparkCoins(coinControl);

    std::pair<CAmount, std::vector<CSparkMintMeta>> estimated =
            SelectSparkCoins(vOut + mintVOut, recipientsToSubtractFee, coins, privateRecipients.size(), recipients.size(), coinControl);

    std::vector<CRecipient> recipients_ = recipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients_ = privateRecipients;
    {
        bool remainderSubtracted = false;
        fee = estimated.first;
        for (size_t i = 0; i < recipients_.size(); i++) {
            auto &recipient = recipients_[i];

            if (recipient.fSubtractFeeFromAmount) {
                // Subtract fee equally from each selected recipient.
                recipient.nAmount -= fee / recipientsToSubtractFee;

                if (!remainderSubtracted) {
                    // First receiver pays the remainder not divisible by output count.
                    recipient.nAmount -= fee % recipientsToSubtractFee;
                    remainderSubtracted = true;
                }
            }
        }

        for (size_t i = 0; i < privateRecipients_.size(); i++) {
            auto &privateRecipient = privateRecipients_[i];

            if (privateRecipient.second) {
                // Subtract fee equally from each selected recipient.
                privateRecipient.first.v -= fee / recipientsToSubtractFee;

                if (!remainderSubtracted) {
                    // First receiver pays the remainder not divisible by output count.
                    privateRecipient.first.v -= fee % recipientsToSubtractFee;
                    remainderSubtracted = true;
                }
            }
        }

    }

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        {
            const spark::Params* params = spark::Params::get_default();
            spark::CSparkState *sparkState = spark::CSparkState::GetState();
            spark::SpendKey spendKey(params);
            try {
                spendKey = std::move(generateSpendKey(params));
            } catch (std::exception& e) {
                throw std::runtime_error(_("Unable to generate spend key."));
            }

            if (spendKey == spark::SpendKey(params))
                throw std::runtime_error(_("Unable to generate spend key, looks wallet locked."));


            tx.vin.clear();
            tx.vout.clear();
            wtxNew.fFromMe = true;
            wtxNew.changes.clear();

            CAmount spendInCurrentTx = 0;
            for (auto& spendCoin : estimated.second)
                spendInCurrentTx += spendCoin.v;
            spendInCurrentTx -= fee;

            uint64_t transparentOut = 0;
            // fill outputs
            for (size_t i = 0; i < recipients_.size(); i++) {
                auto& recipient = recipients_[i];
                if (recipient.nAmount == 0)
                    continue;

                CTxOut vout(recipient.nAmount, recipient.scriptPubKey);

                if (vout.IsDust(minRelayTxFee)) {
                    std::string err;

                    if (recipient.fSubtractFeeFromAmount && fee > 0) {
                        if (vout.nValue < 0) {
                            err = boost::str(boost::format(_("Amount for recipient %1% is too small to pay the fee")) % i);
                        } else {
                            err = boost::str(boost::format(_("Amount for recipient %1% is too small to send after the fee has been deducted")) % i);
                        }
                    } else {
                        err = boost::str(boost::format(_("Amount for recipient %1% is too small")) % i);
                    }

                    throw std::runtime_error(err);
                }

                transparentOut += vout.nValue;
                tx.vout.push_back(vout);
            }

            spendInCurrentTx -= transparentOut;
            std::vector<spark::OutputCoinData> privOutputs;
            // fill outputs
            for (size_t i = 0; i < privateRecipients_.size(); i++) {
                auto& recipient = privateRecipients_[i];
                if (recipient.first.v == 0)
                    continue;

                CAmount recipientAmount = recipient.first.v;
                spendInCurrentTx -= recipientAmount;
                spark::OutputCoinData output = recipient.first;
                output.v = recipientAmount;
                privOutputs.push_back(output);
            }

            if (spendInCurrentTx < 0)
                throw std::invalid_argument(_("Unable to create spend transaction."));

            if (!privOutputs.size() || spendInCurrentTx > 0) {
                spark::OutputCoinData output;
                output.address = getChangeAddress();
                output.memo = "";
                if (spendInCurrentTx > 0)
                    output.v = spendInCurrentTx;
                else
                    output.v = 0;
                wtxNew.changes.insert(static_cast<uint32_t>(tx.vout.size() + privOutputs.size()));
                privOutputs.push_back(output);
            }


            // fill inputs
            uint32_t sequence = CTxIn::SEQUENCE_FINAL;
            CScript script;
            script << OP_SPARKSPEND;
            tx.vin.emplace_back(COutPoint(), script, sequence);

            // clear vExtraPayload to calculate metadata hash correctly
            tx.vExtraPayload.clear();

            // set correct type of transaction (this affects metadata hash)
            tx.nVersion = 3;
            tx.nType = TRANSACTION_SPARK;

            // now every field is populated then we can sign transaction
            // We will write this into cover set representation, with anonymity set hash
            uint256 sig = tx.GetHash();

            std::vector<spark::InputCoinData> inputs;
            std::map<uint64_t, uint256> idAndBlockHashes;
            std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
            for (auto& coin : estimated.second) {
                spark::CSparkState::SparkCoinGroupInfo nextCoinGroupInfo;
                uint64_t groupId = coin.nId;
                if (sparkState->GetLatestCoinID() > groupId && sparkState->GetCoinGroupInfo(groupId + 1, nextCoinGroupInfo)) {
                    if (nextCoinGroupInfo.firstBlock->nHeight <= coin.nHeight)
                        groupId += 1;
                }

                if (cover_set_data.count(groupId) == 0) {
                    std::vector<spark::Coin> set;
                    uint256 blockHash;
                    std::vector<unsigned char> setHash;
                    if (sparkState->GetCoinSetForSpend(
                            &chainActive,
                            chainActive.Height() -
                            (ZC_MINT_CONFIRMATIONS - 1), // required 1 confirmation for mint to spend
                            groupId,
                            blockHash,
                            set,
                            setHash) < 2)
                        throw std::runtime_error(
                                _("Has to have at least two mint coins with at least 1 confirmation in order to spend a coin"));

                    spark::CoverSetData coverSetData;
                    coverSetData.cover_set = set;
                    coverSetData.cover_set_representation = setHash;
                    coverSetData.cover_set_representation.insert(coverSetData.cover_set_representation.end(), sig.begin(), sig.end());
                    cover_set_data[groupId] = coverSetData;
                    idAndBlockHashes[groupId] = blockHash;
                }


                spark::InputCoinData inputCoinData;
                inputCoinData.cover_set_id = groupId;
                std::size_t index = 0;
                if (!getIndex(coin.coin, cover_set_data[groupId].cover_set, index))
                    throw std::runtime_error(
                            _("No such coin in set"));
                inputCoinData.index = index;
                inputCoinData.v = coin.v;
                inputCoinData.k = coin.k;

                spark::IdentifiedCoinData identifiedCoinData;
                identifiedCoinData.i = coin.i;
                identifiedCoinData.d = coin.d;
                identifiedCoinData.v = coin.v;
                identifiedCoinData.k = coin.k;
                identifiedCoinData.memo = coin.memo;
                spark::RecoveredCoinData recoveredCoinData = coin.coin.recover(fullViewKey, identifiedCoinData);

                inputCoinData.T = recoveredCoinData.T;
                inputCoinData.s = recoveredCoinData.s;
                inputs.push_back(inputCoinData);

            }

            spark::SpendTransaction spendTransaction(params, fullViewKey, spendKey, inputs, cover_set_data, fee, transparentOut, privOutputs);
            spendTransaction.setBlockHashes(idAndBlockHashes);
            CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
            serialized << spendTransaction;
            tx.vExtraPayload.assign(serialized.begin(), serialized.end());


            const std::vector<spark::Coin>& outCoins = spendTransaction.getOutCoins();
            for (auto& outCoin : outCoins) {
                // construct spend script
                CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
                serialized << outCoin;
                CScript script;
                script << OP_SPARKSMINT;
                script.insert(script.end(), serialized.begin(), serialized.end());
                tx.vout.push_back(CTxOut(0, script));
            }

            // check fee
            wtxNew.SetTx(MakeTransactionRef(std::move(tx)));

            if (GetTransactionWeight(tx) >= MAX_NEW_TX_WEIGHT) {
                throw std::runtime_error(_("Transaction too large"));
            }

            // check fee
            unsigned size = GetVirtualTransactionSize(tx);
            CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);

            // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
            // because we must be at the maximum allowed fee.
            if (feeNeeded < minRelayTxFee.GetFee(size)) {
                throw std::invalid_argument(_("Transaction too large for fee policy"));
            }

            if (fee < feeNeeded) {
                throw std::invalid_argument(_("Not enough fee estimated"));
            }

                result.push_back(wtxNew);
        }
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;

        for (auto &tx_: txs) {
            LockPoints lp;
            CTxMemPoolEntry entry(MakeTransactionRef(tx_), 0, 0, 0, 0, false, 0, lp);
            CTxMemPool::setEntries setAncestors;
            if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                                   nLimitDescendants, nLimitDescendantSize, errString)) {
                throw std::runtime_error(_("Transaction has too long of a mempool chain"));
            }
        }
    }

    return wtxNew;
}

template<typename Iterator>
static CAmount CalculateBalance(Iterator begin, Iterator end) {
    CAmount balance(0);
    for (auto itr = begin; itr != end; itr++) {
        balance += itr->v;
    }
    return balance;
}

bool GetCoinsToSpend(
        CAmount required,
        std::vector<CSparkMintMeta>& coinsToSpend_out,
        std::list<CSparkMintMeta> coins,
        int64_t& changeToMint,
        const CCoinControl *coinControl)
{
    CAmount availableBalance = CalculateBalance(coins.begin(), coins.end());

    if (required > availableBalance) {
        throw InsufficientFunds();
    }

    // sort by biggest amount. if it is same amount we will prefer the older block
    auto comparer = [](const CSparkMintMeta& a, const CSparkMintMeta& b) -> bool {
        return a.v != b.v ? a.v > b.v : a.nHeight < b.nHeight;
    };
    coins.sort(comparer);

    CAmount spend_val(0);

    std::list<CSparkMintMeta> coinsToSpend;

    // If coinControl, want to use all inputs
    bool coinControlUsed = false;
    if (coinControl != NULL) {
        if (coinControl->HasSelected()) {
            auto coinIt = coins.rbegin();
            for (; coinIt != coins.rend(); coinIt++) {
                spend_val += coinIt->v;
            }
            coinControlUsed = true;
            coinsToSpend.insert(coinsToSpend.begin(), coins.begin(), coins.end());
        }
    }

    if (!coinControlUsed) {
        while (spend_val < required) {
            if (coins.empty())
                break;

            CSparkMintMeta choosen;
            CAmount need = required - spend_val;

            auto itr = coins.begin();
            if (need >= itr->v) {
                choosen = *itr;
                coins.erase(itr);
            } else {
                for (auto coinIt = coins.rbegin(); coinIt != coins.rend(); coinIt++) {
                    auto nextItr = coinIt;
                    nextItr++;

                    if (coinIt->v >= need && (nextItr == coins.rend() || nextItr->v != coinIt->v)) {
                        choosen = *coinIt;
                        coins.erase(std::next(coinIt).base());
                        break;
                    }
                }
            }

            spend_val += choosen.v;
            coinsToSpend.push_back(choosen);
        }
    }

    // sort by group id ay ascending order. it is mandatory for creting proper joinsplit
    auto idComparer = [](const CSparkMintMeta& a, const CSparkMintMeta& b) -> bool {
        return a.nId < b.nId;
    };
    coinsToSpend.sort(idComparer);

    changeToMint = spend_val - required;
    coinsToSpend_out.insert(coinsToSpend_out.begin(), coinsToSpend.begin(), coinsToSpend.end());

    return true;
}

std::pair<CAmount, std::vector<CSparkMintMeta>> CSparkWallet::SelectSparkCoins(
        CAmount required,
        bool subtractFeeFromAmount,
        std::list<CSparkMintMeta> coins,
        std::size_t mintNum,
        std::size_t utxoNum,
        const CCoinControl *coinControl) {

    CAmount fee;
    unsigned size;
    int64_t changeToMint = 0; // this value can be negative, that means we need to spend remaining part of required value with another transaction (nMaxInputPerTransaction exceeded)

    std::vector<CSparkMintMeta> spendCoins;
    for (fee = payTxFee.GetFeePerK();;) {
        CAmount currentRequired = required;

        if (!subtractFeeFromAmount)
            currentRequired += fee;
        spendCoins.clear();
        if (!GetCoinsToSpend(currentRequired, spendCoins, coins, changeToMint, coinControl)) {
            throw std::invalid_argument(_("Unable to select cons for spend"));
        }

        // 924 is constant part, mainly Schnorr and Range proofs, 2535 is for each grootle proof/aux data
        // 213 for each private output, 144 other parts of tx,
        size = 924 + 2535 * (spendCoins.size()) + 213 * mintNum + 144; //TODO (levon) take in account also utxoNum
        CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);

        if (fee >= feeNeeded) {
            break;
        }

        fee = feeNeeded;

        if (subtractFeeFromAmount)
            break;
    }

    if (changeToMint < 0)
        throw std::invalid_argument(_("Unable to select cons for spend"));

    return std::make_pair(fee, spendCoins);
}

std::list<CSparkMintMeta> CSparkWallet::GetAvailableSparkCoins(const CCoinControl *coinControl) const {
    std::list<CSparkMintMeta> coins;
    // get all unsued coins from spark wallet
    std::vector<CSparkMintMeta> vecMints = this->ListSparkMints(true, true);
    for (const auto& mint : vecMints) {
        if (mint.v == 0) // ignore 0 mints which where created to increase privacy
            continue;
        coins.push_back(mint);
    }

    std::set<COutPoint> lockedCoins = pwalletMain->setLockedCoins;

    // Filter out coins that have not been selected from CoinControl should that be used
    coins.remove_if([lockedCoins, coinControl](const CSparkMintMeta& coin) {
        COutPoint outPoint;

        // ignore if the coin is not actually on chain
        if (!spark::GetOutPoint(outPoint, coin.coin)) {
            return true;
        }

        // if we are using coincontrol, filter out unselected coins
        if (coinControl != NULL){
            if (coinControl->HasSelected()){
                if (!coinControl->IsSelected(outPoint)){
                    return true;
                }
            }
        }

        // ignore if coin is locked
        if (lockedCoins.count(outPoint) > 0){
            return true;
        }

        return false;
    });

    return coins;
}