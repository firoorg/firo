// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiondesc.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "transactionrecord.h"

#include "base58.h"
#include "consensus/consensus.h"
#include "validation.h"
#include "script/script.h"
#include "timedata.h"
#include "util.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "bip47/bip47utils.h"
#include "../spark/sparkwallet.h"

#include <stdint.h>
#include <string>

QString TransactionDesc::FormatTxStatus(const CWalletTx& wtx)
{
    AssertLockHeld(cs_main);
    if (!CheckFinalTx(wtx))
    {
        if (wtx.tx->nLockTime < LOCKTIME_THRESHOLD)
            return tr("Open for %n more block(s)", "", wtx.tx->nLockTime - chainActive.Height());
        else
            return tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx.tx->nLockTime));
    }
    else
    {
        QString strTxStatus;
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < 0)
            strTxStatus = tr("conflicted with a transaction with %1 confirmations").arg(-nDepth);
        else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
            strTxStatus =  tr("%1/offline").arg(nDepth);
        else if (nDepth == 0) {
            if (wtx.InMempool()) {
                strTxStatus = "0/unconfirmed, in memory pool" +
                    (wtx.isAbandoned() ? ", "+tr("abandoned") : "");
            } else if (wtx.InStempool()) {
                strTxStatus = "0/unconfirmed, in dandelion stem pool"+
                    (wtx.isAbandoned() ? ", "+tr("abandoned") : "");
            } else {
                strTxStatus = "0/unconfirmed, not in memory pool" +
                    (wtx.isAbandoned() ? ", "+tr("abandoned") : "");
            }
        }
        else if (nDepth < TransactionRecord::RecommendedNumConfirmations)
            strTxStatus = tr("%1/unconfirmed").arg(nDepth);
        else
            strTxStatus = tr("%1 confirmations").arg(nDepth);

        if (wtx.IsChainLocked()) {
            strTxStatus += " (" + tr("locked via LLMQ based ChainLocks") + ")";
        }

        if (wtx.IsLockedByLLMQInstantSend()) {
            strTxStatus += " (" + tr("verified via LLMQ based InstantSend") + ")";
        }
        return strTxStatus;
    }
}

QString TransactionDesc::toHTML(CWallet *wallet, CWalletTx &wtx, TransactionRecord *rec, int unit)
{
    QString strHTML;

    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return strHTML;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return strHTML;
    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    int64_t nTime = wtx.GetTxTime();
    CAmount nCredit = wtx.GetCredit(ISMINE_ALL);
    CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(wtx);
    int nRequests = wtx.GetRequestCount();
    if (nRequests != -1)
    {
        if (nRequests == 0)
            strHTML += tr(", has not been successfully broadcast yet");
        else if (nRequests > 0)
            strHTML += tr(", broadcast through %n node(s)", "", nRequests);
    }
    strHTML += "<br>";

    strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";

    //
    // From
    //
    if (wtx.IsCoinBase() ||  wtx.tx->IsZerocoinSpend() || wtx.tx->IsSigmaSpend() || wtx.tx->IsZerocoinRemint())
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    }
    else if (wtx.mapValue.count("from") && !wtx.mapValue["from"].empty())
    {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.mapValue["from"]) + "<br>";
    }
    else
    {
        // Offline transaction
        if (nNet > 0)
        {
            // Credit
            strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
            strHTML += "<b>" + tr("To") + ":</b> ";
            strHTML += GUIUtil::HtmlEscape(rec->address);
            if (CBitcoinAddress(rec->address).IsValid())
            {
                CTxDestination address = CBitcoinAddress(rec->address).Get();
                if (wallet->mapAddressBook.count(address))
                {
                    QString addressOwned = (::IsMine(*wallet, address) == ISMINE_SPENDABLE) ? tr("own address") : tr("watch-only");
                    if (!wallet->mapAddressBook[address].name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                }
            } else if(wallet->validateSparkAddress(rec->address)) {
                if (wallet->mapSparkAddressBook.count(rec->address))
                {
                    QString addressOwned = wallet->IsSparkAddressMine(rec->address) ? tr("own address") : tr("watch-only");
                    if (!wallet->mapSparkAddressBook[rec->address].name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapSparkAddressBook[rec->address].name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                }
            }
            strHTML += "<br>";
        }
    }

    //
    // To
    //
    if (wtx.mapValue.count("to") && !wtx.mapValue["to"].empty())
    {
        // Online transaction
        std::string strAddress = wtx.mapValue["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        if (wallet->mapAddressBook.count(dest) && !wallet->mapAddressBook[dest].name.empty())
            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[dest].name) + " ";
        strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
    }

    //
    // Amount
    //
    if ((wtx.IsCoinBase() ||  wtx.tx->IsZerocoinSpend() || wtx.tx->IsSigmaSpend() || wtx.tx->IsZerocoinRemint()) && nCredit == 0)
    {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            nUnmatured += wallet->GetCredit(txout, ISMINE_ALL);
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (wtx.IsInMainChain())
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured)+ " (" + tr("matures in %n more block(s)", "", wtx.GetBlocksToMaturity()) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    }
    else if (nNet > 0)
    {
        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    }
    else
    {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
        {
            isminetype mine = wallet->IsMine(txin, *wtx.tx);
            if(fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            isminetype mine = wallet->IsMine(txout);
            if(fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMe)
        {
            if(fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            {
                // Ignore change
                isminetype toSelf = wallet->IsMine(txout);
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;
                CSparkOutputTx sparkOutput;
                if (!wtx.mapValue.count("to") || wtx.mapValue["to"].empty())
                {
                    // Offline transaction
                    CTxDestination address;
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    if (ExtractDestination(txout.scriptPubKey, address))
                    {
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += GUIUtil::HtmlEscape(CBitcoinAddress(address).ToString());
                    } else if(wallet->GetSparkOutputTx(txout.scriptPubKey, sparkOutput)) {
                        if (wallet->mapSparkAddressBook.count(sparkOutput.address) && !wallet->mapSparkAddressBook[sparkOutput.address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapSparkAddressBook[sparkOutput.address].name) + " ";
                        strHTML += GUIUtil::HtmlEscape(sparkOutput.address);
                    }
                    if(toSelf == ISMINE_SPENDABLE)
                        strHTML += " (own address)";
                    else if(toSelf & ISMINE_WATCH_ONLY)
                        strHTML += " (watch-only)";
                    strHTML += "<br>";
                }
                if(wtx.tx->IsSparkSpend() && wallet->validateSparkAddress(sparkOutput.address)) {
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -sparkOutput.amount) + "<br>";
                } else {
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                }

                if(toSelf) {
                    if(wtx.tx->IsSparkSpend() && wallet->validateSparkAddress(sparkOutput.address)) {
                        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, sparkOutput.amount) + "<br>";
                    } else {
                        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
                    }
                }
            }

            if (fAllToMe)
            {
                if (wtx.tx->IsLelantusJoinSplit()) {
                    strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wtx.tx->GetValueOut()) + "<br>";
                    strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wtx.tx->GetValueOut()) + "<br>";
                } else {
                    // Payment to self
                    CAmount nChange = wtx.GetChange();
                    CAmount nValue = nCredit - nChange;
                    strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nValue) + "<br>";
                    strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nValue) + "<br>";
                }
            }

            CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

            if (wtx.tx->IsLelantusJoinSplit() && wtx.tx->vin.size() > 0) {
                try {
                    nTxFee = lelantus::ParseLelantusJoinSplit(*wtx.tx)->getFee();
                }
                catch (const std::exception &) {
                    //do nothing
                }
            }

            if (wtx.tx->IsSparkSpend() && wtx.tx->vin.size() > 0) {
                try {
                    nTxFee = spark::GetSparkFee(*wtx.tx);
                }
                catch (...) {
                    //do nothing
                }
            }

            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        else
        {
            //
            // Mixed debit transaction
            //
            BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
                if (wallet->IsMine(txin, *wtx.tx))
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, *wtx.tx, ISMINE_ALL)) + "<br>";
            BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
                if (wallet->IsMine(txout))
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";

    //
    // Message
    //
    if (wtx.mapValue.count("message") && !wtx.mapValue["message"].empty())
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["message"], true) + "<br>";
    if (wtx.mapValue.count("comment") && !wtx.mapValue["comment"].empty())
        strHTML += "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxID() + "<br>";
    strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
    strHTML += "<b>" + tr("Output index") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";

    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool foundSparkOutput = false;

    for (const CTxIn& txin : wtx.tx->vin) {
        isminetype mine = wallet->IsMine(txin, *wtx.tx);
        fAllFromMe = std::min(fAllFromMe, mine);
    }

    bool firstMessage = true;
    if (fAllFromMe) {
        for (const CTxOut& txout : wtx.tx->vout) {
            if (wtx.IsChange(txout)) continue;

            CSparkOutputTx sparkOutput;
            if (wallet->GetSparkOutputTx(txout.scriptPubKey, sparkOutput)) {
                if (!sparkOutput.memo.empty()) {
                    foundSparkOutput = true;
                    if (firstMessage) {
                        strHTML += "<hr><b>" + tr("Messages") + ":</b><br>";
                        firstMessage = false;
                    }
                    strHTML += "• " + GUIUtil::HtmlEscape(sparkOutput.memo, true) + "<br>";
                }
            }
        }
    }

    if (!foundSparkOutput && wallet->sparkWallet) {
        for (const auto& [id, meta] : wallet->sparkWallet->getMintMap()) {
            if (meta.txid == rec->hash && !meta.memo.empty()) {
                if (firstMessage) {
                    strHTML += "<hr><b>" + tr("Messages") + ":</b><br>";
                    firstMessage = false;
                }
                strHTML += "• " + GUIUtil::HtmlEscape(meta.memo, true) + "<br>";
            }
        }
    }

    if (wtx.IsCoinBase())
    {
        quint32 numBlocksToMaturity = COINBASE_MATURITY +  1;
        strHTML += "<br>" + tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(numBlocksToMaturity)) + "<br>";
    }

    //
    // Check if it is a BIP47 tx
    //
    BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
    {
        bool isFromMe = wallet->IsFromMe(*wtx.tx);
        CTxDestination address;
        if (ExtractDestination(txout.scriptPubKey, address))
        {
            boost::optional<bip47::CPaymentCodeDescription> pcode = wallet->FindPcode(address);
            if (pcode)
            {
                if (!isFromMe)
                    strHTML += "<b>" + tr("Received with RAP address") + ":</b> " + GUIUtil::HtmlEscape(std::get<2>(*pcode));
                else
                    strHTML += "<b>" + tr("Sent to RAP address") + ":</b> " + bip47::utils::ShortenPcode(std::get<1>(*pcode)).c_str();
            }
            strHTML += "<br>" ;
        }
    }

    //
    // Debug view
    //
    if (fDebug)
    {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
            if(wallet->IsMine(txin, *wtx.tx))
                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, *wtx.tx, ISMINE_ALL)) + "<br>";
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            if(wallet->IsMine(txout))
                strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        strHTML += GUIUtil::HtmlEscape(wtx.tx->ToString(), true);

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
        {
            COutPoint prevout = txin.prevout;

            Coin prev;
            if(pcoinsTip->GetCoin(prevout, prev))
            {
                {
                    strHTML += "<li>";
                    const CTxOut &vout = prev.out;
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += QString::fromStdString(CBitcoinAddress(address).ToString());
                    }
                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet->IsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false")) + "</li>";
                    strHTML = strHTML + " IsWatchOnly=" + (wallet->IsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) + "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
