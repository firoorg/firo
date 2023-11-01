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

#include <optional>
#include <boost/format.hpp>

const uint32_t DEFAULT_SPARK_NCOUNT = 1;

uint256 CSparkTxout::GetHash() const {
    assert(meta.has_value());

    return meta->txid;
}

COutPoint CSparkTxout::GetOutpoint() const {
    assert(meta.has_value());
    assert(pwallet);
    assert(pwallet->sparkWallet);
    AssertLockHeld(pwallet->cs_wallet);

    CWalletTx wtx = pwallet->mapWallet.at(GetHash());
    std::vector<uint8_t> serialContext = spark::getSerialContext(*wtx.tx);
    uint32_t i = 0;
    for (const CTxOut& txout: wtx.tx->vout) {
        spark::Coin mintedCoinData(spark::Params::get_default());

        spark::IdentifiedCoinData identifiedCoinData;
        try {
            spark::ParseSparkMintCoin(txout.scriptPubKey, mintedCoinData);
            mintedCoinData.setSerialContext(serialContext);
            identifiedCoinData = mintedCoinData.identify(pwallet->sparkWallet->viewKey);
        } catch (const std::exception& e) {
            continue;
        }

        if (identifiedCoinData.k == meta->k) {
            return COutPoint(wtx.GetHash(), i);
        }

        i++;
    }

    // meta data is incorrect; this should never happen.
    assert(false);
}

CAmount CSparkTxout::GetValue() const {
    assert(pwallet);
    assert(meta.has_value());

    return meta->v;
}

CScript CSparkTxout::GetScriptPubkey() const {
    assert(pwallet);
    assert(meta.has_value());
    AssertLockHeld(pwallet->cs_wallet);

    COutPoint outpoint = GetOutpoint();
    CWalletTx wtx = pwallet->mapWallet.at(outpoint.hash);
    return wtx.tx->vout[outpoint.n].scriptPubKey;
}

size_t CSparkTxout::GetMarginalSpendSize(std::vector<CSparkTxout>& previousInputs) const {
    assert(meta.has_value());

    return 10000; // FIXME
}

bool CSparkTxout::IsMine(const CCoinControl* coinControl) const {
    assert(meta.has_value());

    // We'll only have meta information for our own mints.
    return true;
}

bool CSparkTxout::IsSpendable() const {
    assert(meta.has_value());
    assert(pwallet);
    assert(pwallet->sparkWallet);
    AssertLockHeld(pwallet->sparkWallet->cs_spark_wallet);

    if (meta.value().isUsed)
        return false;

    const std::unordered_map<int, spark::CSparkState::SparkCoinGroupInfo>& coinGroups =
        spark::CSparkState::GetState()->GetCoinGroups();
    return coinGroups.count(GetCoverSetId()) && coinGroups.at(GetCoverSetId()).nCoins > 1;
}

bool CSparkTxout::IsLocked() const {
    assert(pwallet);
    AssertLockHeld(pwallet->cs_wallet);

    // This is done because it's somewhat expensive to determine what output index we are.
    bool hasLocked = false;
    for (size_t i = 0; i < pwallet->mapWallet.at(GetHash()).tx->vout.size(); i++) {
        if (pwallet->IsLockedCoin(GetHash(), i)) {
            hasLocked = true;
            break;
        }
    }
    if (!hasLocked)
        return false;

    COutPoint outpoint = GetOutpoint();
    return pwallet->IsLockedCoin(outpoint.hash, outpoint.n);
}

bool CSparkTxout::IsAbandoned() const {
    assert(pwallet);
    AssertLockHeld(pwallet->cs_wallet);

    return pwallet->mapWallet.at(GetHash()).isAbandoned();
}

bool CSparkTxout::IsCoinTypeCompatible(const CCoinControl* coinControl) const {
    assert(meta.has_value());

    if (!coinControl)
        return true;
    else if (coinControl->nCoinType == CoinType::ALL_COINS)
        return true;
    else if (coinControl->nCoinType == CoinType::ONLY_DENOMINATED)
        assert(false); // This type is unused.
    else if (coinControl->nCoinType == CoinType::ONLY_NOT1000IFMN)
        return true;
    else if (coinControl->nCoinType == CoinType::ONLY_NONDENOMINATED_NOT1000IFMN)
        return true;
    else if (coinControl->nCoinType == CoinType::ONLY_1000)
        return false; // Mints are not eligible for masternode collateral.
    else if (coinControl->nCoinType == CoinType::ONLY_PRIVATESEND_COLLATERAL)
        assert(false); // This type is unused.
    else if (coinControl->nCoinType == CoinType::ONLY_MINTS)
        return true;
    else if (coinControl->nCoinType == CoinType::WITH_MINTS)
        return true;
    else if (coinControl->nCoinType == CoinType::WITH_1000)
        return true;
    else
        assert(false);
}

bool CSparkTxout::IsLLMQInstantSendLocked() const {
    // We can't spend LLMQ instant send locked coins, so the caller shouldn't ask this question.
    assert(false);
}

bool CSparkTxout::IsCoinBase() const {
    assert(pwallet);
    assert(meta.has_value());
    AssertLockHeld(pwallet->cs_wallet);

    return pwallet->mapWallet.at(GetHash()).IsCoinBase();
}

unsigned int CSparkTxout::GetDepthInMainChain() const {
    assert(pwallet);
    assert(meta.has_value());
    AssertLockHeld(pwallet->cs_wallet);

    return pwallet->mapWallet.at(GetHash()).GetDepthInMainChain();
}

uint64_t CSparkTxout::GetCoverSetId() const {
    assert(meta.has_value());

    return meta->nId;
}

spark::InputCoinData CSparkTxout::GetInputCoinData(spark::FullViewKey& fullViewKey,
                                                   spark::CoverSetData& coverSetData) const {
    assert(pwallet);
    assert(meta.has_value());
    AssertLockHeld(pwallet->cs_wallet);

    spark::IdentifiedCoinData identifiedCoinData;
    identifiedCoinData.i = meta.value().i;
    identifiedCoinData.d = meta.value().d;
    identifiedCoinData.v = meta.value().v;
    identifiedCoinData.k = meta.value().k;
    identifiedCoinData.memo = meta.value().memo;

    spark::InputCoinData inputCoinData;
    inputCoinData.cover_set_id = GetCoverSetId();
    inputCoinData.v = meta.value().v;
    inputCoinData.k = meta.value().k;

    spark::RecoveredCoinData recoveredCoinData = meta.value().coin.recover(fullViewKey, identifiedCoinData);
    inputCoinData.T = recoveredCoinData.T;
    inputCoinData.s = recoveredCoinData.s;

    inputCoinData.index = 0;
    for (const spark::Coin& coin: coverSetData.cover_set) {
        if (coin == meta.value().coin)
            break;

        inputCoinData.index++;
    }

    return inputCoinData;
}

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

std::vector<CSparkTxout> CSparkWallet::GetSparkTxouts() const {
    AssertLockHeld(cs_spark_wallet);

    std::vector<CSparkTxout> txouts;
    for (std::pair<uint256, CSparkMintMeta> meta: coinMeta)
        txouts.emplace_back(pwalletMain, meta.second);

    return txouts;
}

void CSparkWallet::GetCoverSetData(spark::CoverSetData& coverSetData, uint256& blockHash, uint256 txHash,
                                   uint64_t coverSetId) const {
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_spark_wallet);

    coverSetData.cover_set.clear();
    coverSetData.cover_set_representation.clear();
    blockHash.SetNull();

    spark::CSparkState *sparkState = spark::CSparkState::GetState();

    std::vector<spark::Coin> set;
    std::vector<unsigned char> setHash;
    if (sparkState->GetCoinSetForSpend(&chainActive, chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), coverSetId,
                                       blockHash, set, setHash) < 2)
        throw std::runtime_error("Cover set must have at least 2 coins to be spendable.");

    coverSetData.cover_set = set;
    coverSetData.cover_set_representation = setHash;
    coverSetData.cover_set_representation.insert(coverSetData.cover_set_representation.end(), txHash.begin(),
                                                 txHash.end());
}

void CSparkWallet::CheckSparkTransactionSanity(
    const CTransaction& tx,
    const std::unordered_map<uint64_t, spark::CoverSetData>& coverSetData,
    std::map<uint64_t, uint256>& idAndBlockHashes,
    CAmount nFee
) const {
    CAmount vout = 0;
    std::vector<spark::Coin> outCoins;
    for (const CTxOut& txout: tx.vout) {
        vout += txout.nValue;

        if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSparkSMint()) {
            spark::Coin coin;
            spark::ParseSparkMintCoin(txout.scriptPubKey, coin);
            outCoins.emplace_back(coin);
        }
    }

    spark::SpendTransaction spendTx = spark::ParseSparkSpend(tx);
    spendTx.setBlockHashes(idAndBlockHashes);
    spendTx.setCoverSets(coverSetData);
    spendTx.setOutCoins(outCoins);
    spendTx.setVout(vout);

    std::unordered_map<uint64_t, std::vector<spark::Coin>> coverSetCoins;
    for (const auto& it: coverSetData)
        coverSetCoins[it.first] = it.second.cover_set;

    if (!spendTx.verify(spendTx, coverSetCoins))
        throw std::runtime_error("created invalid spark tx");

    if (spendTx.getFee() != nFee)
        throw std::runtime_error("created spark tx with unexpected fee");

    int64_t txSize = GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

    if (txSize * WITNESS_SCALE_FACTOR >= MAX_NEW_TX_WEIGHT)
        throw std::runtime_error("Transaction too large");

    if (nFee < minRelayTxFee.GetFee(txSize))
        throw std::runtime_error("Created spark tx with less than minimum relay fee");

    if (nFee > maxTxFee)
        throw std::runtime_error("Created spark tx with more than maximum fee");
}

CWalletTx CSparkWallet::CreateSparkSpendTransaction(
    const std::vector<CRecipient>& recipients,
    const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
    CAmount &fee,
    const CCoinControl *coinControl)
{
    size_t SPARK_FIRST_MINT_SIZE = 311;
    size_t SPARK_SUBSEQUENT_MINT_SIZE = 301;
    const Consensus::Params& params = Params().GetConsensus();
    const spark::Params* sparkParams = spark::Params::get_default();

    AssertLockHeld(cs_main);
    AssertLockHeld(cs_spark_wallet);
    AssertLockHeld(pwalletMain->cs_wallet);

    if (pwalletMain->IsLocked())
        throw std::runtime_error("Wallet is locked.");

    if (recipients.empty() && privateRecipients.empty())
        throw std::runtime_error("Either recipients or newMints has to be non-empty.");

    if (privateRecipients.size() >= params.nMaxSparkOutLimitPerTx - 1)
        throw std::runtime_error("Spark shielded output limit exceeded.");

    size_t nConstantSize = 4 + // version
        GetSizeOfCompactSize(recipients.size() + privateRecipients.size()) + // This is a varint representing the
                                                                             // number of outputs. In the event that
                                                                             // there are 0xfc outputs and a change
                                                                             // output is not required we will pay the
                                                                             // fee for one extra byte.
        4; // locktime

    if (!privateRecipients.empty())
        nConstantSize += 8 + GetSizeOfCompactSize(SPARK_FIRST_MINT_SIZE) + SPARK_FIRST_MINT_SIZE;
    if (privateRecipients.size() > 1)
        nConstantSize +=
            (8 + GetSizeOfCompactSize(SPARK_SUBSEQUENT_MINT_SIZE) + SPARK_SUBSEQUENT_MINT_SIZE) *
            (privateRecipients.size() - 1);

    size_t nRecipientsToSubtractFee = 0;
    CAmount nRequired = 0;

    for (const CRecipient& recipient: recipients) {
        nRequired += recipient.nAmount;
        nConstantSize += 8 + GetSizeOfCompactSize(recipient.scriptPubKey.size()) + recipient.scriptPubKey.size();

        if (recipient.fSubtractFeeFromAmount)
            nRecipientsToSubtractFee++;
    }

    for (const std::pair<spark::OutputCoinData, bool>& privateRecipient: privateRecipients) {
        nRequired += privateRecipient.first.v;

        if (privateRecipient.second)
            nRecipientsToSubtractFee++;
    }

    std::vector<CSparkTxout> selectedTxos;
    CAmount nCollectedRet = 0;
    pwalletMain->GetInputsForTx(GetSparkTxouts(), selectedTxos, fee, nCollectedRet, nRequired, nConstantSize,
                                coinControl, false, nRecipientsToSubtractFee > 0, false, SPARK_SUBSEQUENT_MINT_SIZE);

    // Input coins must be sorted by group id in ascending order in spark::SpendTransaction's constructor.
    std::sort(selectedTxos.begin(), selectedTxos.end(), [](const CSparkTxout& a, const CSparkTxout& b) -> bool {
        return a.GetCoverSetId() < b.GetCoverSetId();
    });

    CMutableTransaction txNew;
    // Because we use Dandelion, we want to delay nLockTime for all transactions, not just 10% of them. Fee sniping is
    // not an issue due to chain locks.
    if (chainActive[101]) txNew.nLockTime = chainActive.Height() - GetRandInt(100);
    else txNew.nLockTime = 0;

    CScript inScript;
    inScript << OP_SPARKSPEND;
    txNew.vin.emplace_back(CTxIn(COutPoint(), inScript, CTxIn::SEQUENCE_FINAL));

    txNew.nVersion = 3;
    txNew.nType = TRANSACTION_SPARK;

    std::vector<spark::OutputCoinData> sparkOutputs;
    for (const std::pair<spark::OutputCoinData, bool>& privateRecipient: privateRecipients) {
        spark::OutputCoinData sparkOutput = privateRecipient.first;

        if (privateRecipient.second) {
            CAmount toSubtract = fee / nRecipientsToSubtractFee;
            if (sparkOutputs.empty())
                toSubtract += fee % nRecipientsToSubtractFee;

            if (toSubtract >= sparkOutput.v)
                throw std::runtime_error("Recipient amount is too small to subtract fee from.");

            sparkOutput.v -= toSubtract;
        }

        sparkOutputs.emplace_back(sparkOutput);
    }

    CAmount nTransparentOut = 0;
    for (const CRecipient& recipient: recipients) {
        CAmount nOut = recipient.nAmount;
        if (recipient.fSubtractFeeFromAmount) {
            CAmount toSubtract = fee / nRecipientsToSubtractFee;
            if (toSubtract > nOut)
                throw std::runtime_error("Recipient amount is too small to subtract fee from.");

            nOut -= toSubtract;
        }

        txNew.vout.emplace_back(nOut, recipient.scriptPubKey);
        nTransparentOut += nOut;
    }

    std::vector<spark::InputCoinData> sparkInputData;
    std::map<uint64_t, uint256> idAndBlockHashes;
    std::unordered_map<uint64_t, spark::CoverSetData> coverSetData;
    for (const CSparkTxout& txout: selectedTxos) {
        uint64_t coverSetId = txout.GetCoverSetId();

        if (!coverSetData.count(coverSetId)) {
            uint256 blockHash;
            spark::CoverSetData coverSet;
            GetCoverSetData(coverSet, blockHash, txNew.GetHash(), coverSetId);

            coverSetData[coverSetId] = coverSet;
            idAndBlockHashes[coverSetId] = blockHash;
        }

        sparkInputData.emplace_back(txout.GetInputCoinData(fullViewKey, coverSetData[coverSetId]));
    }

    CAmount nChange = nCollectedRet - nRequired - (nRecipientsToSubtractFee > 0 ? 0 : fee);
    if (nChange > 0) {
        spark::OutputCoinData changeCoin;
        changeCoin.address = getChangeAddress();
        changeCoin.v = nChange;
        sparkOutputs.emplace_back(changeCoin);
    }

    spark::SpendTransaction spendTransaction(sparkParams, fullViewKey, generateSpendKey(sparkParams), sparkInputData,
                                             coverSetData, fee, nTransparentOut, sparkOutputs);
    spendTransaction.setBlockHashes(idAndBlockHashes);


    std::unordered_map<uint64_t, std::vector<spark::Coin>> coverSetCoins;
    for (const auto& it: coverSetData)
        coverSetCoins[it.first] = it.second.cover_set;

    assert(spendTransaction.verify(spendTransaction, coverSetCoins));

    CDataStream extraPayloadSerialized(SER_NETWORK, PROTOCOL_VERSION);
    extraPayloadSerialized << spendTransaction;
    txNew.vExtraPayload.assign(extraPayloadSerialized.begin(), extraPayloadSerialized.end());

    for (const spark::Coin& outCoin: spendTransaction.getOutCoins()) {
        CDataStream coinSerialized(SER_NETWORK, PROTOCOL_VERSION);
        coinSerialized << outCoin;

        CScript script;
        script << OP_SPARKSMINT;
        script.insert(script.end(), coinSerialized.begin(), coinSerialized.end());

        txNew.vout.emplace_back(0, script);
    }

    CWalletTx wtxNew;
    wtxNew.BindWallet(pwalletMain);
    wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));
    wtxNew.fFromMe = true;
    wtxNew.fTimeReceivedIsTxTime = true;
    if (nChange > 0)
        wtxNew.changes.emplace(wtxNew.tx->vout.size() - 1);

    CheckSparkTransactionSanity(*wtxNew.tx, coverSetData, idAndBlockHashes, fee);

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