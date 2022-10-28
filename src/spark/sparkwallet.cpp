#include "sparkwallet.h"
#include "../wallet/wallet.h"
#include "../wallet/coincontrol.h"
#include "../wallet/walletexcept.h"
#include "../hash.h"
#include "../validation.h"
#include "../policy/policy.h"
#include "../script/sign.h"
#include "state.h"

#include <boost/format.hpp>

const uint32_t DEFAULT_SPARK_NCOUNT = 1;

CSparkWallet::CSparkWallet(const std::string& strWalletFile) {

    CWalletDB walletdb(strWalletFile);
    this->strWalletFile = strWalletFile;
    const spark::Params* params = spark::Params::get_default();
    fullViewKey = spark::FullViewKey(params);
    viewKey = spark::IncomingViewKey(params);

    // try to get incoming view key from db, if it fails, that means it is first start
    if (!walletdb.readFullViewKey(fullViewKey)) {
        if (pwalletMain->IsLocked()) {
            LogPrintf("Spark wallet creation FAILED, wallet is locked\n");
            return;
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
        coinMeta = walletdb.ListSparkMints();
    }
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

std::vector<CSparkMintMeta> CSparkWallet::ListSparkMints(bool fUnusedOnly, bool fMatureOnly) const {
    std::vector<CSparkMintMeta> setMints;

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

spark::Coin CSparkWallet::getCoinFromMeta(const CSparkMintMeta& meta) const {
    const spark::Params* params = spark::Params::get_default();
    spark::Address address(viewKey, meta.i);
    return spark::Coin(params, meta.type, meta.k, address, meta.v, meta.memo, meta.serial_context);
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

void CSparkWallet::addOrUpdateMint(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb) {
    if (mint.i > lastDiversifier) {
        lastDiversifier = mint.i;
        walletdb.writeDiversifier(lastDiversifier);
    }
    coinMeta[lTagHash] = mint;
    walletdb.WriteSparkMint(lTagHash, mint);
}

void CSparkWallet::updateMintInMemory(const CSparkMintMeta& mint) {
    for (auto& itr : coinMeta) {
        if (itr.second == mint) {
            coinMeta[itr.first] = mint;
            break;
        }
    }
}

CSparkMintMeta CSparkWallet::getMintMeta(const uint256& hash) {
    if (coinMeta.count(hash))
        return coinMeta[hash];
    return CSparkMintMeta();
}

CSparkMintMeta CSparkWallet::getMintMeta(const secp_primitives::Scalar& nonce) {
    for (const auto& meta : coinMeta) {
        if (meta.second.k == nonce)
            return meta.second;
    }

    return CSparkMintMeta();
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

        pwalletMain->NotifyZerocoinChanged(
                pwalletMain,
                lTagHash.GetHex(),
                std::string("used (") + std::to_string((double)mintMeta.v / COIN) + "mint)",
                CT_UPDATED);
    }
}

void CSparkWallet::UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags, const uint256& txHash, bool fUpdateMint) {
    for (const auto& lTag : lTags) {
        uint256 lTagHash = primitives::GetLTagHash(lTag);
        if (coinMeta.count(lTagHash)) {
            UpdateSpendState(lTag, lTagHash, txHash, fUpdateMint);
        }
    }
}

void CSparkWallet::UpdateSpendStateFromBlock(const CBlock& block) {
    const auto& transactions = block.vtx;
    for (const auto& tx : transactions) {
        if (tx->IsSparkSpend()) {
            try {
                const auto& txLTags = spark::ParseSparkSpend(*tx).getUsedLTags();
                for (const auto& txLTag : txLTags) {
                    uint256 txHash = tx->GetHash();
                    uint256 lTagHash = primitives::GetLTagHash(txLTag);
                    UpdateSpendState(txLTag, lTagHash, txHash);
                }
            } catch (...) {
            }
        }
    }
}

void CSparkWallet::UpdateMintState(const std::vector<spark::Coin>& coins, const uint256& txHash) {
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
            mintMeta.type = coin.type;
            //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
            {
                LOCK(mempool.cs);
                mintMeta.isUsed = mempool.sparkState.HasLTag(recoveredCoinData.T);
            }

            CWalletDB walletdb(strWalletFile);
            uint256 lTagHash = primitives::GetLTagHash(recoveredCoinData.T);
            addOrUpdateMint(mintMeta, lTagHash, walletdb);

            if (mintMeta.isUsed) {
                LOCK(mempool.cs);
                uint256 spendTxHash = mempool.sparkState.GetMempoolConflictingTxHash(recoveredCoinData.T);
                UpdateSpendState(recoveredCoinData.T, lTagHash, spendTxHash, false);
            }

            pwalletMain->NotifyZerocoinChanged(
                    pwalletMain,
                    lTagHash.GetHex(),
                    std::string("Update (") + std::to_string((double)mintMeta.v / COIN) + "mint)",
                    CT_UPDATED);
        } catch (const std::runtime_error& e) {
            continue;
        }
    }
}

void CSparkWallet::UpdateMintStateFromMempool(const std::vector<spark::Coin>& coins, const uint256& txHash) {
    UpdateMintState(coins, txHash);
}

void CSparkWallet::UpdateMintStateFromBlock(const CBlock& block) {
    const auto& transactions = block.vtx;
    for (const auto& tx : transactions) {
        if (tx->IsSparkTransaction()) {
            auto coins =  spark::GetSparkMintCoins(*tx);
            for (auto& coin : coins) {
                uint256 txHash = tx->GetHash();
                UpdateMintState(coins, txHash);
            }
        }
    }
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
        CAmount& nAllFeeRet,
        std::list<CReserveKey>& reservekeys,
        int& nChangePosInOut,
        std::string& strFailReason,
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
    std::vector<spark::MintedCoinData>  outputs_ = outputs;
    CAmount valueToMint = 0;

    for (auto& output : outputs_)
        valueToMint += output.v;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        {
            std::list<CWalletTx> cacheWtxs;
            // vector pairs<available amount, outputs> for each transparent address
            std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
            pwalletMain->AvailableCoinsForLMint(valueAndUTXO, coinControl);

            Shuffle(valueAndUTXO.begin(), valueAndUTXO.end(), FastRandomContext());

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

                // TODO(levon) do we need mint limit? if yes, define new MaxValue Mint for spark
                CAmount valueToMintInTx = std::min(
                        ::Params().GetConsensus().nMaxValueLelantusMint,
                        itr->first);

                if (!autoMintAll) {
                    valueToMintInTx = std::min(valueToMintInTx, valueToMint);
                }

                CAmount nValueToSelect, mintedValue;

                std::set<std::pair<const CWalletTx *, unsigned int>> setCoins;
                bool skipCoin = false;
                // Start with no fee and loop until there is enough fee
                while (true) {
                    mintedValue = valueToMintInTx;
                    nValueToSelect = mintedValue + nFeeRet;

                    // if have no enough coins in this group then subtract fee from mint
                    if (nValueToSelect > itr->first) {
                        mintedValue -= nFeeRet;
                        nValueToSelect = mintedValue + nFeeRet;
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
                    if (GetTransactionWeight(txConst) >= MAX_STANDARD_TX_WEIGHT) {
                        strFailReason = _("Transaction too large");
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
                                if (usedCoin.first == coin->tx && usedCoin.second == coin->i) {
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

std::vector<CWalletTx> CSparkWallet::CreateSparkSpendTransaction(
        const std::vector<CRecipient>& recipients,
        const std::vector<std::pair<spark::OutputCoinData, bool>>& privateRecipients,
        CAmount &fee,
        const CCoinControl *coinControl) {

    if (recipients.empty() && privateRecipients.empty()) {
        throw std::runtime_error(_("Either recipients or newMints has to be nonempty."));
    }

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
    std::list<std::pair<spark::Coin, CSparkMintMeta>> coins = GetAvailableSparkCoins(coinControl);
    // TODO levon check spend limit
    std::vector<std::pair<CAmount, std::vector<std::pair<spark::Coin, CSparkMintMeta>>>> estimated =
            SelectSparkCoins(vOut + mintVOut, recipientsToSubtractFee, coins, privateRecipients.size(), recipients.size(), coinControl);

    std::vector<CRecipient> recipients_ = recipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients_ = privateRecipients;
    for (auto& feeAndSpendCoins : estimated) {
        bool remainderSubtracted = false;
        auto& fee = feeAndSpendCoins.first;
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


            for (auto& feeAndSpendCoins : estimated) {
                tx.vin.clear();
                tx.vout.clear();
                wtxNew.fFromMe = true;
                wtxNew.changes.clear();

                CAmount spendInCurrentTx = 0;
                for (auto& spendCoin : feeAndSpendCoins.second)
                    spendInCurrentTx += spendCoin.second.v;
                CAmount fee = feeAndSpendCoins.first;
                spendInCurrentTx -= fee;

                uint64_t transparentOut = 0;
                // fill outputs
                for (size_t i = 0; i < recipients_.size(); i++) {
                    auto& recipient = recipients_[i];
                    if (recipient.nAmount == 0)
                        continue;

                    if (spendInCurrentTx <= 0)
                        break;

                    CAmount recipientAmount = std::min(recipient.nAmount, spendInCurrentTx);
                    spendInCurrentTx -= recipientAmount;
                    recipient.nAmount -= recipientAmount;
                    CTxOut vout(recipientAmount, recipient.scriptPubKey);

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

                std::vector<spark::OutputCoinData> privOutputs;
                // fill outputs
                for (size_t i = 0; i < privateRecipients_.size(); i++) {
                    auto& recipient = privateRecipients_[i];
                    if (recipient.first.v == 0)
                        continue;

                    if (spendInCurrentTx <= 0)
                        break;

                    CAmount recipientAmount = recipient.first.v;
                    recipientAmount = std::min(recipientAmount, spendInCurrentTx);
                    spendInCurrentTx -= recipientAmount;
                    recipient.first.v -= recipientAmount;
                    spark::OutputCoinData output = recipient.first;
                    output.v = recipientAmount;
                    privOutputs.push_back(output);
                }

                if (!privOutputs.size() || spendInCurrentTx > 0) {
                    spark::OutputCoinData output;
                    output.address = getDefaultAddress();
                    output.memo = "";
                    if (spendInCurrentTx > 0)
                        output.v = spendInCurrentTx;
                    else
                        output.v = 0;
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
                for (auto& coin : feeAndSpendCoins.second) {
                    spark::CSparkState::SparkCoinGroupInfo nextCoinGroupInfo;
                    uint64_t groupId = coin.second.nId;
                    if (sparkState->GetLatestCoinID() > groupId && sparkState->GetCoinGroupInfo(groupId + 1, nextCoinGroupInfo)) {
                        if (nextCoinGroupInfo.firstBlock->nHeight <= coin.second.nHeight)
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
                    if (!getIndex(coin.first, cover_set_data[groupId].cover_set, index))
                        throw std::runtime_error(
                                _("No such coin in set"));
                    inputCoinData.index = index;
                    inputCoinData.v = coin.second.v;
                    inputCoinData.k = coin.second.k;

                    spark::IdentifiedCoinData identifiedCoinData;
                    identifiedCoinData.i = coin.second.i;
                    identifiedCoinData.d = coin.second.d;
                    identifiedCoinData.v = coin.second.v;
                    identifiedCoinData.k = coin.second.k;
                    identifiedCoinData.memo = coin.second.memo;
                    spark::RecoveredCoinData recoveredCoinData = coin.first.recover(fullViewKey, identifiedCoinData);

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

                if (GetTransactionWeight(tx) >= MAX_LELANTUS_TX_WEIGHT) {
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

    return result;
}

template<typename Iterator>
static CAmount CalculateBalance(Iterator begin, Iterator end) {
    CAmount balance(0);
    for (auto itr = begin; itr != end; itr++) {
        balance += itr->second.v;
    }
    return balance;
}

bool GetCoinsToSpend(
        CAmount required,
        std::vector<std::pair<spark::Coin, CSparkMintMeta>>& coinsToSpend_out,
        std::list<std::pair<spark::Coin, CSparkMintMeta>> coins,
        int64_t& changeToMint,
        const size_t coinsToSpendLimit,
        const CCoinControl *coinControl)
{
    CAmount availableBalance = CalculateBalance(coins.begin(), coins.end());

    if (required > availableBalance) {
        throw InsufficientFunds();
    }

    typedef std::pair<spark::Coin, CSparkMintMeta> CoinData;

    // sort by biggest amount. if it is same amount we will prefer the older block
    auto comparer = [](const CoinData& a, const CoinData& b) -> bool {
        return a.second.v != b.second.v ? a.second.v > b.second.v : a.second.nHeight < b.second.nHeight;
    };
    coins.sort(comparer);

    CAmount spend_val(0);

    std::list<CoinData> coinsToSpend;

    // If coinControl, want to use all inputs
    bool coinControlUsed = false;
    if (coinControl != NULL) {
        if (coinControl->HasSelected()) {
            auto coinIt = coins.rbegin();
            for (; coinIt != coins.rend(); coinIt++) {
                spend_val += coinIt->second.v;
            }
            coinControlUsed = true;
            coinsToSpend.insert(coinsToSpend.begin(), coins.begin(), coins.end());
        }
    }

    if (!coinControlUsed) {
        while (spend_val < required) {
            if (coins.empty())
                break;

            CoinData choosen;
            CAmount need = required - spend_val;

            auto itr = coins.begin();
            if (need >= itr->second.v) {
                choosen = *itr;
                coins.erase(itr);
            } else {
                for (auto coinIt = coins.rbegin(); coinIt != coins.rend(); coinIt++) {
                    auto nextItr = coinIt;
                    nextItr++;

                    if (coinIt->second.v >= need && (nextItr == coins.rend() || nextItr->second.v != coinIt->second.v)) {
                        choosen = *coinIt;
                        coins.erase(std::next(coinIt).base());
                        break;
                    }
                }
            }

            spend_val += choosen.second.v;
            coinsToSpend.push_back(choosen);

            if (coinsToSpend.size() == coinsToSpendLimit) // if we pass input number limit, we stop and try to spend remaining part with another transaction
                break;
        }
    }

    // sort by group id ay ascending order. it is mandatory for creting proper joinsplit
    auto idComparer = [](const CoinData& a, const CoinData& b) -> bool {
        return a.second.nId < b.second.nId;
    };
    coinsToSpend.sort(idComparer);

    changeToMint = spend_val - required;
    coinsToSpend_out.insert(coinsToSpend_out.begin(), coinsToSpend.begin(), coinsToSpend.end());

    return true;
}

std::vector<std::pair<CAmount, std::vector<std::pair<spark::Coin, CSparkMintMeta>>>> CSparkWallet::SelectSparkCoins(
        CAmount required,
        bool subtractFeeFromAmount,
        std::list<std::pair<spark::Coin, CSparkMintMeta>> coins,
        std::size_t mintNum,
        std::size_t utxoNum,
        const CCoinControl *coinControl) {

    std::vector<std::pair<CAmount, std::vector<std::pair<spark::Coin, CSparkMintMeta>>>> result;

    while (required > 0) {
        CAmount fee;
        unsigned size;
        int64_t changeToMint = 0; // this value can be negative, that means we need to spend remaining part of required value with another transaction (nMaxInputPerTransaction exceeded)

        std::vector<std::pair<spark::Coin, CSparkMintMeta>> spendCoins;
        for (fee = payTxFee.GetFeePerK();;) {
            CAmount currentRequired = required;

            if (!subtractFeeFromAmount)
                currentRequired += fee;
            spendCoins.clear();
            const auto &consensusParams = Params().GetConsensus();
            if (!GetCoinsToSpend(currentRequired, spendCoins, coins, changeToMint,
                                           consensusParams.nMaxLelantusInputPerTransaction, coinControl)) {
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

        result.push_back({fee, spendCoins});
        if (changeToMint < 0)
            required = - changeToMint;
        else
            required = 0;
    }
    return result;
}

std::list<std::pair<spark::Coin, CSparkMintMeta>> CSparkWallet::GetAvailableSparkCoins(const CCoinControl *coinControl) const {
    std::list<std::pair<spark::Coin, CSparkMintMeta>> coins;
    // get all unsued coins from spark wallet
    std::vector<CSparkMintMeta> vecMints = this->ListSparkMints(true, true);
    for (const auto& mint : vecMints) {
        if (mint.v == 0) // ignore 0 mints which where created to increase privacy
            continue;

        spark::Coin coin = this->getCoinFromMeta(mint);
        coins.push_back(std::make_pair(coin, mint));
    }

    std::set<COutPoint> lockedCoins = pwalletMain->setLockedCoins;

    // Filter out coins that have not been selected from CoinControl should that be used
    coins.remove_if([lockedCoins, coinControl](const std::pair<spark::Coin, CSparkMintMeta>& coin) {
        COutPoint outPoint;

        // ignore if the coin is not actually on chain
        if (!spark::GetOutPoint(outPoint, coin.first)) {
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

//TODO levon implement wallet scanning when restoring wallet, or opening wallet file witg synced chain