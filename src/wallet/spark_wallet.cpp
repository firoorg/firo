#include "spark_wallet.h"
#include "wallet.h"
#include "walletdb.h"
#include "../hash.h"

const uint32_t DEFAULT_SPARK_NCOUNT = 1;

CSparkWallet::CSparkWallet(const std::string& strWalletFile) {

    CWalletDB walletdb(strWalletFile);

    const spark::Params* params = spark::Params::get_default();
    viewKey = spark::IncomingViewKey(params);

    // try to get incoming view key from db, if it fails, that means it is first start
    if (!walletdb.readIncomingViewKey(viewKey)) {
        if (pwalletMain->IsLocked()) {
            LogPrintf("Spark wallet creation FAILED, wallet is locked\n");
            return;
        }
        // Generating spark key set first time
        spark::SpendKey spendKey = generateSpendKey();
        spark::FullViewKey fullViewKey = generateFullViewKey(spendKey);
        viewKey = generateIncomingViewKey(fullViewKey);

        // Write incoming view key into db, it is safe to be kept in db, it is used to identify incoming coins belonging to the wallet
        walletdb.writeIncomingViewKey(viewKey);
        lastDiversifier = -1;
        // generate one initial address for wallet
        addresses[lastDiversifier] = generateNextAddress();
        // set 0 as last diversifier into db, we will update it later, in case coin comes, or user manually generates new address
        walletdb.writeDiversifier(lastDiversifier);
    } else {
        int32_t diversifierInDB = 0;
        // read diversifier from db
        walletdb.readDiversifier(diversifierInDB);
        lastDiversifier = -1;

        // generate all used addresses
         while (lastDiversifier <  diversifierInDB) {
             addresses[lastDiversifier] = generateNextAddress();
         }

         // get the list of coin metadata from db
         std::list<CSparkMintMeta> listMints = walletdb.ListSparkMints();
         for (const auto& itr : listMints) {
             coinMeta[itr.GetNonceHash()] = itr;
         }
    }
}

void CSparkWallet::resetDiversifierFromDB(CWalletDB& walletdb) {
    walletdb.writeDiversifier(lastDiversifier);
}

void CSparkWallet::updatetDiversifierInDB(CWalletDB& walletdb) {
    walletdb.readDiversifier(lastDiversifier);
}

CAmount CSparkWallet::getFullBalance() {
    return getAvailableBalance() + getUnconfirmedBalance();
}

CAmount CSparkWallet::getAvailableBalance() {
    CAmount result = 0;
    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;

        if (mint.isUsed)
            continue;

        // Not confirmed
        if (!mint.nHeight)
            continue;

        result += mint.v;
    }
    return result;
}

CAmount CSparkWallet::getUnconfirmedBalance() {
    CAmount result = 0;

    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;
        if (mint.isUsed)
            continue;

        // Continue if confirmed
        if (mint.nHeight)
            continue;

        result += mint.v;
    }

    return result;
}

spark::Address CSparkWallet::generateNextAddress() {
    lastDiversifier++;
    return spark::Address(viewKey, lastDiversifier);
}

spark::SpendKey CSparkWallet::generateSpendKey() {
    if (pwalletMain->IsLocked()) {
        LogPrintf("Spark spend key generation FAILED, wallet is locked\n");
        return spark::SpendKey();
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
    hasher.Write(secret.begin(), secret.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(nCountStr.c_str()), nCountStr.size());
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);

    secp_primitives::Scalar r;
    r.memberFromSeed(hash);
    const spark::Params* params = spark::Params::get_default();
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

std::vector<CSparkMintMeta> CSparkWallet::ListSparkMints(bool fUnusedOnly, bool fMatureOnly) {
    std::vector<CSparkMintMeta> setMints;

    for (auto& it : coinMeta) {
        CSparkMintMeta mint = it.second;
        if (fUnusedOnly && mint.isUsed)
            continue;

        // Not confirmed
        if (fMatureOnly && !mint.nHeight)
            continue;

        setMints.push_back(mint);
    }

    return setMints;
}

spark::Coin CSparkWallet::getCoinFromMeta(const CSparkMintMeta& meta) {
    const spark::Params* params = spark::Params::get_default();
    spark::Address address = getAddress(meta.i);
    // type we are passing 0; as we don't care about type now
    char type = 0;
    return spark::Coin(params, type, meta.k, address, meta.v, meta.memo);
}

void CSparkWallet::clearAllMints(CWalletDB& walletdb) {

    for (auto& itr : coinMeta) {
        walletdb.EraseSparkMint(itr.first);
    }

    coinMeta.clear();
    lastDiversifier = 0;
    walletdb.writeDiversifier(lastDiversifier);
}

void CSparkWallet::eraseMint(const uint256& hash, CWalletDB& walletdb) {
    walletdb.EraseSparkMint(hash);
    coinMeta.erase(hash);
}
void CSparkWallet::addOrUpdate(const CSparkMintMeta& mint, CWalletDB& walletdb) {
    if (mint.i > lastDiversifier) {
        lastDiversifier = mint.i;
        walletdb.writeDiversifier(lastDiversifier);
    }
    coinMeta[mint.GetNonceHash()] = mint;
    walletdb.WriteSparkMint(mint.GetNonceHash(), mint);
}

CSparkMintMeta CSparkWallet::getMintMeta(const uint256& hash) {
    if (coinMeta.count(hash))
        return coinMeta[hash];
    return CSparkMintMeta();
}

std::vector<CSparkMintMeta> CSparkWallet::listAddressCoins(const int32_t& i, bool fUnusedOnly) {
    std::vector<CSparkMintMeta> listMints;

    for (auto& itr : coinMeta) {
        if (itr.second.i == i) {
            if (fUnusedOnly && itr.second.isUsed)
                continue;
            listMints.push_back(itr.second);
        }
    }
    return listMints;
}