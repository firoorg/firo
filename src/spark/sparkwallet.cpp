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
#include "sparkname.h"
#include "../chain.h"
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

void CSparkWallet::FinishTasks() {
    ((ParallelOpThreadPool<void>*)threadPool)->Shutdown();
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
    } catch (const std::exception &) {
        return false;
    }

    return isAddressMine(address);
}

bool CSparkWallet::isAddressMine(const spark::Address& address) {
    for (const auto& itr : addresses) {
        if (itr.second.get_Q1() == address.get_Q1() && itr.second.get_Q2() == address.get_Q2())
            return true;
    }

    uint64_t d;

    try {
        d = viewKey.get_diversifier(address.get_d());
    } catch (const std::exception &) {
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

    if (cmp::greater(mint.i, lastDiversifier)) {
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

bool CSparkWallet::getMintMeta(spark::Coin coin, CSparkMintMeta& mintMeta) {
    spark::IdentifiedCoinData identifiedCoinData;
    try {
        identifiedCoinData = coin.identify(this->viewKey);
    } catch (...) {
        return false;
    }
    mintMeta = getMintMeta(identifiedCoinData.k);
    if(mintMeta == CSparkMintMeta())
        return false;
    return true;
}

bool CSparkWallet::getMintAmount(spark::Coin coin, CAmount& amount) {
    spark::IdentifiedCoinData identifiedCoinData;
    try {
        identifiedCoinData = coin.identify(this->viewKey);
    } catch (const std::exception &) {
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
                } catch (const std::exception &) {
                }
            }
        }
    });
}

bool CSparkWallet::isMine(spark::Coin coin) const {
    try {
        spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
    } catch (const std::exception &) {
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

spark::Address CSparkWallet::getMyCoinAddress(spark::Coin coin) {
    spark::Address address;
    try {
        spark::IdentifiedCoinData identifiedCoinData = coin.identify(this->viewKey);
        address = getAddress(int32_t(identifiedCoinData.i));
    } catch (const std::runtime_error& e) {
        // do nothing
    }
    return address;
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
        if (cmp::equal(itr.second.i, i)) {
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
        unsigned char network = spark::GetNetworkType();
        std::string addr = outputs[i].address.encode(network);
        std::string memo = outputs[i].memo;
        const std::size_t max_memo_size = outputs[i].address.get_params()->get_memo_bytes();
        if (memo.length() > max_memo_size) {
            throw std::runtime_error(strprintf("Memo exceeds maximum length of %d bytes", max_memo_size));
        }
        CRecipient recipient = {script, CAmount(outputs[i].v), false, addr, memo};
        results.emplace_back(recipient);
    }

    return results;
}

bool CSparkWallet::CreateSparkMintTransactions(
        const std::vector<spark::MintedCoinData>& outputs,
        std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
        CAmount& nAllFeeRet,
        std::list<CReserveKey>& reservekeys,
        int& nChangePosInOut,
        bool subtractFeeFromAmount,
        std::string& strFailReason,
        bool fSplit,
        const CCoinControl *coinControl,
        bool autoMintAll)
{

    int nChangePosRequest = nChangePosInOut;

    // Create transaction template
    CWalletTx wtxNew;
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(pwalletMain);

    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);
    std::vector<spark::MintedCoinData> outputs_ = outputs;
    CAmount valueToMint = 0;

    for (auto& output : outputs_)
        valueToMint += output.v;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        {
            std::list<CWalletTx> cacheWtxs;
            // vector pairs<available amount, outputs> for each transparent address
            std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
            if (fSplit) {
                pwalletMain->AvailableCoinsForLMint(valueAndUTXO, coinControl);
                Shuffle(valueAndUTXO.begin(), valueAndUTXO.end(), FastRandomContext());
            } else {
                std::vector<COutput> vAvailableCoins;
                pwalletMain->AvailableCoins(vAvailableCoins, true, coinControl);
                CAmount balance = 0;
                for (auto& coin : vAvailableCoins)
                    balance += coin.tx->tx->vout[coin.i].nValue;
                valueAndUTXO.emplace_back(std::make_pair(balance, vAvailableCoins));
            }
            while (!valueAndUTXO.empty()) {

                // initialize
                CWalletTx wtx = wtxNew;
                CMutableTransaction tx = txNew;

                reservekeys.emplace_back(pwalletMain);
                auto &reservekey = reservekeys.back();

                if (GetRandInt(10) == 0)
                    tx.nLockTime = std::max(0, (int) tx.nLockTime - GetRandInt(100));

                auto nFeeRet = 0;
                LogPrintf("nFeeRet=%s\n", nFeeRet);

                auto itr = valueAndUTXO.begin();

//                CAmount valueToMintInTx = std::min(
//                        ::Params().GetConsensus().nMaxValueLelantusMint, itr->first);

                CAmount valueToMintInTx = itr->first;

                if (!autoMintAll) {
                    valueToMintInTx = std::min(valueToMintInTx, valueToMint);
                }

                CAmount nValueToSelect, mintedValue;

                std::set<std::pair<const CWalletTx *, unsigned int>> setCoins;
                bool skipCoin = false;
                // Start with no fee and loop until there is enough fee
                while (true) {
                    mintedValue = valueToMintInTx;
                    if (subtractFeeFromAmount)
                        nValueToSelect = mintedValue;
                    else
                        nValueToSelect = mintedValue + nFeeRet;

                    // if no enough coins in this group then subtract fee from mint
                    if (nValueToSelect > itr->first && !subtractFeeFromAmount) {
                        nValueToSelect = mintedValue;
                        mintedValue -= nFeeRet;
                    }

                    if (!MoneyRange(mintedValue) || mintedValue == 0) {
                        valueAndUTXO.erase(itr);
                        skipCoin = true;
                        break;
                    }

                    nChangePosInOut = nChangePosRequest;
                    tx.vin.clear();
                    tx.vout.clear();
                    wtx.fFromMe = true;
                    wtx.changes.clear();
                    setCoins.clear();
                    std::vector<spark::MintedCoinData>  remainingOutputs = outputs_;
                    std::vector<spark::MintedCoinData> singleTxOutputs;
                    if (autoMintAll) {
                        spark::MintedCoinData  mintedCoinData;
                        mintedCoinData.v = mintedValue;
                        mintedCoinData.memo = "";
                        mintedCoinData.address = getDefaultAddress();
                        singleTxOutputs.push_back(mintedCoinData);
                    } else {
                        uint64_t remainingMintValue = mintedValue;
                        while (remainingMintValue > 0){
                            // Create the mint data and push into vector
                            uint64_t singleMintValue = std::min(remainingMintValue, remainingOutputs.begin()->v);
                            spark::MintedCoinData mintedCoinData;
                            mintedCoinData.v = singleMintValue;
                            mintedCoinData.address = remainingOutputs.begin()->address;
                            mintedCoinData.memo = remainingOutputs.begin()->memo;
                            singleTxOutputs.push_back(mintedCoinData);

                            // subtract minted amount from remaining value
                            remainingMintValue -= singleMintValue;
                            remainingOutputs.begin()->v -= singleMintValue;

                            if (remainingOutputs.begin()->v == 0)
                                remainingOutputs.erase(remainingOutputs.begin());
                        }
                    }

                    if (subtractFeeFromAmount) {
                        CAmount singleFee = nFeeRet / singleTxOutputs.size();
                        CAmount reminder = nFeeRet % singleTxOutputs.size();
                        for (size_t i = 0; i < singleTxOutputs.size(); ++i) {
                            if (cmp::less_equal(singleTxOutputs[i].v, singleFee)) {
                                singleTxOutputs.erase(singleTxOutputs.begin() + i);
                                reminder += singleTxOutputs[i].v - singleFee;
                                if (!singleTxOutputs.size()) {
                                    strFailReason = _("Transaction amount too small");
                                    return false;
                                }
                                --i;
                            }
                            singleTxOutputs[i].v -= singleFee;
                            if (reminder > 0 && singleTxOutputs[i].v > nFeeRet % singleTxOutputs.size()) {// first receiver pays the remainder not divisible by output count
                                singleTxOutputs[i].v -= reminder;
                                reminder = 0;
                            }
                        }
                    }

                    // Generate dummy mint coins to save time
                    std::vector<unsigned char> serial_context;
                    std::vector<CRecipient> recipients = CSparkWallet::CreateSparkMintRecipients(singleTxOutputs, serial_context, false);
                    for (auto& recipient : recipients) {
                        // vout to create mint
                        CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                        if (txout.IsDust(::minRelayTxFee)) {
                            strFailReason = _("Transaction amount too small");
                            return false;
                        }

                        tx.vout.push_back(txout);
                    }
                    // Choose coins to use
                    CAmount nValueIn = 0;
                    if (!pwalletMain->SelectCoins(itr->second, nValueToSelect, setCoins, nValueIn, coinControl)) {

                        if (nValueIn < nValueToSelect) {
                            strFailReason = _("Insufficient funds");
                        }
                        return false;
                    }

                    double dPriority = 0;
                    for (auto const &pcoin : setCoins) {
                        CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                        //The coin age after the next block (depth+1) is used instead of the current,
                        //reflecting an assumption the user would accept a bit more delay for
                        //a chance at a free transaction.
                        //But mempool inputs might still be in the mempool, so their age stays 0
                        int age = pcoin.first->GetDepthInMainChain();
                        assert(age >= 0);
                        if (age != 0)
                            age += 1;
                        dPriority += (double) nCredit * age;
                    }

                    CAmount nChange = nValueIn - nValueToSelect;

                    if (nChange > 0) {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange;

                        // coin control: send change to custom address
                        if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                            scriptChange = GetScriptForDestination(coinControl->destChange);

                            // send change to one of the specified change addresses
                        else if (IsArgSet("-change") && mapMultiArgs.at("-change").size() > 0) {
                            CBitcoinAddress address(
                                    mapMultiArgs.at("change")[GetRandInt(mapMultiArgs.at("-change").size())]);
                            CKeyID keyID;
                            if (!address.GetKeyID(keyID)) {
                                strFailReason = _("Bad change address");
                                return false;
                            }
                            scriptChange = GetScriptForDestination(keyID);
                        }

                            // no coin control: send change to newly generated address
                        else {
                            // Note: We use a new key here to keep it from being obvious which side is the change.
                            //  The drawback is that by not reusing a previous key, the change may be lost if a
                            //  backup is restored, if the backup doesn't have the new private key for the change.
                            //  If we reused the old key, it would be possible to add code to look for and
                            //  rediscover unknown transactions that were written with keys of ours to recover
                            //  post-backup change.

                            // Reserve a new key pair from key pool
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            if (!ret) {
                                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                                return false;
                            }

                            scriptChange = GetScriptForDestination(vchPubKey.GetID());
                        }

                        CTxOut newTxOut(nChange, scriptChange);

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust(::minRelayTxFee)) {
                            nChangePosInOut = -1;
                            nFeeRet += nChange;
                            reservekey.ReturnKey();
                        } else {

                            if (nChangePosInOut == -1) {

                                // Insert change txn at random position:
                                nChangePosInOut = GetRandInt(tx.vout.size() + 1);
                            } else if ((unsigned int) nChangePosInOut > tx.vout.size()) {

                                strFailReason = _("Change index out of range");
                                return false;
                            }

                            std::vector<CTxOut>::iterator position = tx.vout.begin() + nChangePosInOut;
                            tx.vout.insert(position, newTxOut);
                            wtx.changes.insert(static_cast<uint32_t>(nChangePosInOut));
                        }
                    } else {
                        reservekey.ReturnKey();
                    }

                    // Fill vin
                    //
                    // Note how the sequence number is set to max()-1 so that the
                    // nLockTime set above actually works.
                    for (const auto &coin : setCoins) {
                        tx.vin.push_back(CTxIn(
                                coin.first->GetHash(),
                                coin.second,
                                CScript(),
                                std::numeric_limits<unsigned int>::max() - 1));
                    }

                    // Fill in dummy signatures for fee calculation.
                    if (!pwalletMain->DummySignTx(tx, setCoins)) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }

                    unsigned int nBytes = GetVirtualTransactionSize(tx);

                    // Limit size
                    CTransaction txConst(tx);
                    if (GetTransactionWeight(txConst) >= MAX_NEW_TX_WEIGHT) {
                        strFailReason = _("Transaction is too large (size limit: 250Kb). Select less inputs or consolidate your UTXOs");
                        return false;
                    }
                    dPriority = txConst.ComputePriority(dPriority, nBytes);

                    // Remove scriptSigs to eliminate the fee calculation dummy signatures
                    for (auto &vin : tx.vin) {
                        vin.scriptSig = CScript();
                        vin.scriptWitness.SetNull();
                    }

                    // Can we complete this as a free transaction?
                    if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                        // Not enough fee: enough priority?
                        double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                        // Require at least hard-coded AllowFree.
                        if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                            break;
                    }
                    CAmount nFeeNeeded = CWallet::GetMinimumFee(nBytes, nTxConfirmTarget, mempool);

                    if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                        nFeeNeeded = coinControl->nMinimumTotalFee;
                    }

                    if (coinControl && coinControl->fOverrideFeeRate)
                        nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);

                    // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                    // because we must be at the maximum allowed fee.
                    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
                        strFailReason = _("Transaction too large for fee policy");
                        return false;
                    }

                    if (nFeeRet >= nFeeNeeded) {
                        for (auto &usedCoin : setCoins) {
                            for (auto coin = itr->second.begin(); coin != itr->second.end(); coin++) {
                                if (usedCoin.first == coin->tx && cmp::equal(usedCoin.second, coin->i)) {
                                    itr->first -= coin->tx->tx->vout[coin->i].nValue;
                                    itr->second.erase(coin);
                                    break;
                                }
                            }
                        }

                        if (itr->second.empty()) {
                            valueAndUTXO.erase(itr);
                        }

                        // Generate real mint coins
                        CDataStream serialContextStream(SER_NETWORK, PROTOCOL_VERSION);
                        for (auto& input : tx.vin) {
                            serialContextStream << input;
                        }

                        recipients = CSparkWallet::CreateSparkMintRecipients(singleTxOutputs, std::vector<unsigned char>(serialContextStream.begin(), serialContextStream.end()), true);

                        size_t i = 0;
                        for (auto& recipient : recipients) {
                            CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                            LogPrintf("txout: %s\n", txout.ToString());
                            while (i < tx.vout.size()) {
                                if (tx.vout[i].scriptPubKey.IsSparkMint()) {
                                    tx.vout[i] = txout;
                                    CWalletDB walletdb(pwalletMain->strWalletFile);
                                    CSparkOutputTx output;
                                    output.address = recipient.address;
                                    output.amount = recipient.nAmount;
                                    output.memo = recipient.memo;
                                    walletdb.WriteSparkOutputTx(recipient.scriptPubKey, output);
                                    break;
                                }
                                ++i;
                            }
                            ++i;
                        }

                        //remove output from outputs_ vector if it got all requested value
                        outputs_ = remainingOutputs;

                        break; // Done, enough fee included.
                    }

                    // Include more fee and try again.
                    nFeeRet = nFeeNeeded;
                    continue;
                }

                if (skipCoin)
                    continue;

                if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
                    // Lastly, ensure this tx will pass the mempool's chain limits
                    LockPoints lp;
                    CTxMemPoolEntry entry(MakeTransactionRef(tx), 0, 0, 0, 0, false, 0, lp);
                    CTxMemPool::setEntries setAncestors;
                    size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
                    size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
                    size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
                    size_t nLimitDescendantSize =
                            GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
                    std::string errString;
                    if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                                           nLimitDescendants, nLimitDescendantSize, errString)) {
                        strFailReason = _("Transaction has too long of a mempool chain");
                        return false;
                    }
                }

                // Sign
                int nIn = 0;
                CTransaction txNewConst(tx);
                for (const auto &coin : setCoins) {
                    bool signSuccess = false;
                    const CScript &scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &txNewConst, nIn,
                                                                               coin.first->tx->vout[coin.second].nValue,
                                                                               SIGHASH_ALL), scriptPubKey, sigdata);

                    if (!signSuccess) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(tx, nIn, sigdata);
                    }
                    nIn++;
                }

                {
                    CValidationState state;
                    if (!mempool.IsTransactionAllowed(*wtx.tx, state)) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                }

                wtx.SetTx(MakeTransactionRef(std::move(tx)));

                wtxAndFee.push_back(std::make_pair(wtx, nFeeRet));

                if (nChangePosInOut >= 0) {
                    // Cache wtx to somewhere because COutput use pointer of it.
                    cacheWtxs.push_back(wtx);
                    auto &wtx = cacheWtxs.back();

                    COutput out(&wtx, nChangePosInOut, wtx.GetDepthInMainChain(false), true, true);
                    auto val = wtx.tx->vout[nChangePosInOut].nValue;

                    bool added = false;
                    for (auto &utxos : valueAndUTXO) {
                        auto const &o = utxos.second.front();
                        if (o.tx->tx->vout[o.i].scriptPubKey == wtx.tx->vout[nChangePosInOut].scriptPubKey) {
                            utxos.first += val;
                            utxos.second.push_back(out);

                            added = true;
                        }
                    }

                    if (!added) {
                        valueAndUTXO.push_back({val, {out}});
                    }
                }

                nAllFeeRet += nFeeRet;
                if (!autoMintAll) {
                    valueToMint -= mintedValue;
                    if (valueToMint == 0)
                        break;
                }
            }
        }
    }

    if (!autoMintAll && valueToMint > 0) {
        return false;
    }

    return true;
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
        const CCoinControl *coinControl,
        CAmount additionalTxSize) {

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

        if (recipient.scriptPubKey.IsPayToExchangeAddress()) {
            throw std::runtime_error("Exchange addresses cannot receive private funds. Please transfer your funds to a transparent address first before sending to an Exchange address");
        }

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

    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height();
    }

    if (vOut > consensusParams.GetMaxValueSparkSpendPerBlock(nHeight))
        throw std::runtime_error(_("Spend to transparent address limit exceeded."));

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
            SelectSparkCoins(vOut + mintVOut, recipientsToSubtractFee, coins, privateRecipients.size(), recipients.size(), coinControl, additionalTxSize);

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
            std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
            for (auto& coin : estimated.second) {
                spark::CSparkState::SparkCoinGroupInfo nextCoinGroupInfo;
                uint64_t groupId = coin.nId;
                if (cmp::greater(sparkState->GetLatestCoinID(), groupId) && sparkState->GetCoinGroupInfo(groupId + 1, nextCoinGroupInfo)) {
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
                    coverSetData.cover_set_size = set.size();
                    coverSetData.cover_set_representation = setHash;
                    coverSetData.cover_set_representation.insert(coverSetData.cover_set_representation.end(), sig.begin(), sig.end());
                    cover_set_data[groupId] = coverSetData;
                    cover_sets[groupId] = set;
                    idAndBlockHashes[groupId] = blockHash;
                }


                spark::InputCoinData inputCoinData;
                inputCoinData.cover_set_id = groupId;
                std::size_t index = 0;
                if (!getIndex(coin.coin, cover_sets[groupId], index))
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

            spark::SpendTransaction spendTransaction(params, fullViewKey, spendKey, inputs, cover_set_data, cover_sets, fee, transparentOut, privOutputs);
            spendTransaction.setBlockHashes(idAndBlockHashes);
            CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
            serialized << spendTransaction;
            tx.vExtraPayload.assign(serialized.begin(), serialized.end());


            size_t i = 0;
            const std::vector<spark::Coin>& outCoins = spendTransaction.getOutCoins();
            unsigned char network = spark::GetNetworkType();
            for (auto& outCoin : outCoins) {
                // construct spend script
                CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
                serialized << outCoin;
                CScript script;
                script << OP_SPARKSMINT;
                script.insert(script.end(), serialized.begin(), serialized.end());
                CWalletDB walletdb(strWalletFile);
                CSparkOutputTx output;
                output.address =  privOutputs[i].address.encode(network);
                output.amount = privOutputs[i].v;
                output.memo = privOutputs[i].memo;
                walletdb.WriteSparkOutputTx(script, output);
                tx.vout.push_back(CTxOut(0, script));
                i++;
            }

            if (GetTransactionWeight(tx) >= MAX_NEW_TX_WEIGHT) {
                throw std::runtime_error(_("Transaction is too large (size limit: 250Kb). Select less inputs or consolidate your UTXOs"));
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

            wtxNew.SetTx(MakeTransactionRef(std::move(tx)));
            
            result.push_back(wtxNew);
        }
    }
    {
        CValidationState state;
        for (CWalletTx& wtx : result) {
            if (!mempool.IsTransactionAllowed(*wtx.tx, state))
                throw std::invalid_argument(_("Spark transactions are disabled at the moment"));
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

CWalletTx CSparkWallet::CreateSparkNameTransaction(CSparkNameTxData &nameData, CAmount sparkNameFee, CAmount &txFee, const CCoinControl *coinConrol) {
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

    const auto &consensusParams = Params().GetConsensus();
    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height();
    }
    std::string payoutAddress = nHeight >= consensusParams.stage41StartBlockDevFundAddressChange
        ? consensusParams.stage3CommunityFundAddress
        : consensusParams.stage3DevelopmentFundAddress;

    CRecipient devPayout;
    devPayout.nAmount = sparkNameFee;
    devPayout.scriptPubKey = GetScriptForDestination(CBitcoinAddress(payoutAddress).Get());
    devPayout.fSubtractFeeFromAmount = false;

    CWalletTx wtxSparkSpend = CreateSparkSpendTransaction({devPayout}, {}, txFee, coinConrol,
        sparkNameManager->GetSparkNameTxDataSize(nameData) + 20 /* add a little bit to the fee to be on the safe side */);

    const spark::Params* params = spark::Params::get_default();
    spark::SpendKey spendKey(params);
    try {
        spendKey = std::move(generateSpendKey(params));
    } catch (std::exception& e) {
        throw std::runtime_error(_("Unable to generate spend key."));
    }

    if (spendKey == spark::SpendKey(params))
        throw std::runtime_error(_("Unable to generate spend key, looks the wallet is locked."));

    spark::Address  address(spark::Params::get_default());
    try {
        address.decode(nameData.sparkAddress);
    } catch (std::exception& e) {
        throw std::runtime_error(_("Invalid spark address"));
    }

    if (!isAddressMine(address))
        throw std::runtime_error(_("Spark address doesn't belong to the wallet"));

    CMutableTransaction tx = CMutableTransaction(*wtxSparkSpend.tx);    
    sparkNameManager->AppendSparkNameTxData(tx, nameData, spendKey, fullViewKey);

    wtxSparkSpend.tx = MakeTransactionRef(std::move(tx));
    return wtxSparkSpend;
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
            if (cmp::greater_equal(need, itr->v)) {
                choosen = *itr;
                coins.erase(itr);
            } else {
                for (auto coinIt = coins.rbegin(); coinIt != coins.rend(); coinIt++) {
                    auto nextItr = coinIt;
                    nextItr++;

                    if (cmp::greater_equal(coinIt->v, need) && (nextItr == coins.rend() || nextItr->v != coinIt->v)) {
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
        const CCoinControl *coinControl,
        size_t additionalTxSize) {

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

        // 1803 is for first grootle proof/aux data
        // 213 for each private output, 34 for each utxo,924 constant parts of tx parts of tx,
        size = 924 + 1803*(spendCoins.size()) + 322*(mintNum+1) + 34*utxoNum + additionalTxSize;
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