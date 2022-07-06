#include "wallet.h"
#include "../wallet/wallet.h"
#include "../wallet/coincontrol.h"
#include "../hash.h"
#include "../validation.h"
#include "../policy/policy.h"
#include "../script/sign.h"
#include "state.h"

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
        // generate one initial address for wallet
        lastDiversifier = 0;
        addresses[lastDiversifier] = getDefaultAddress();
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
        coinMeta = walletdb.ListSparkMints();
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

spark::Address CSparkWallet::getDefaultAddress() {
    if (addresses.count(0))
        return addresses[0];
    lastDiversifier = 0;
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
    std::string prefix = "r_generation";
    hasher.Write(reinterpret_cast<const unsigned char*>(prefix.c_str()), prefix.size());
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

std::vector<CSparkMintMeta> CSparkWallet::ListSparkMints(bool fUnusedOnly, bool fMatureOnly) const {
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

spark::Coin CSparkWallet::getCoinFromMeta(const CSparkMintMeta& meta) const {
    const spark::Params* params = spark::Params::get_default();
    spark::Address address(viewKey, meta.i);
    // type we are passing 0; as we don't care about type now
    char type = 0;
    return spark::Coin(params, type, meta.k, address, meta.v, meta.memo, meta.serial_context);
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
void CSparkWallet::addOrUpdate(const CSparkMintMeta& mint, const uint256& lTagHash, CWalletDB& walletdb) {
    if (mint.i > lastDiversifier) {
        lastDiversifier = mint.i;
        walletdb.writeDiversifier(lastDiversifier);
    }
    coinMeta[lTagHash] = mint;
    walletdb.WriteSparkMint(lTagHash, mint);
}

CSparkMintMeta CSparkWallet::getMintMeta(const uint256& hash) {
    if (coinMeta.count(hash))
        return coinMeta[hash];
    return CSparkMintMeta();
}

void CSparkWallet::UpdateSpendStateFromMempool(const std::vector<GroupElement>& lTags) {
  //TODO levon
}

void CSparkWallet::UpdateMintStateFromMempool(const std::vector<spark::Coin>& coins) {
    //TODO levon
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
        throw std::runtime_error("Spark mit output number should be equal to required number.");

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
        const std::vector<spark::MintedCoinData>&  outputs,
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
                            spark::MintedCoinData  mintedCoinData;
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

                        recipients = CSparkWallet::CreateSparkMintRecipients(singleTxOutputs, std::vector<unsigned char>(serial_context.begin(), serial_context.end()), true);

                        size_t i = 0;
                        for (auto& recipient : recipients) {
                            CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                            LogPrintf("txout: %s\n", txout.ToString());
                            while (i < tx.vout.size() - 1) {
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

                if(skipCoin)
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
                if(!autoMintAll) {
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

std::list<std::pair<spark::Coin, CSparkMintMeta>> CSparkWallet::GetAvailableSparkCoins(CWalletDB& walletdb, const CCoinControl *coinControl) const {
    std::list<std::pair<spark::Coin, CSparkMintMeta>> coins;
    // get all unsued coins from spark wallet
    std::vector<CSparkMintMeta> vecMints = this->ListSparkMints(true, true);
    for (const auto& mint : vecMints) {
        if(mint.v == 0) // ignore 0 mints which where created to increase privacy
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

        // ignore if coin is locked
        if(lockedCoins.count(outPoint) > 0){
            return true;
        }

        // if we are using coincontrol, filter out unselected coins
        if(coinControl != NULL){
            if(coinControl->HasSelected()){
                if(!coinControl->IsSelected(outPoint)){
                    return true;
                }
            }
        }

        return false;
    });

    return coins;
}