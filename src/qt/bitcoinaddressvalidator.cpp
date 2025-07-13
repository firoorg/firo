// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinaddressvalidator.h"

#include "base58.h"
#include "bip47/paymentcode.h"

/* Base58 characters are:
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  This is:
  - All numbers except for '0'
  - All upper-case letters except for 'I' and 'O'
  - All lower-case letters except for 'l'
*/

BitcoinAddressEntryValidator::BitcoinAddressEntryValidator(QObject *parent) :
    QValidator(parent)
{
}

QValidator::State BitcoinAddressEntryValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);

    // Empty address is "intermediate" input
    if (input.isEmpty())
        return QValidator::Intermediate;

    // Correction
    for (int idx = 0; idx < input.size();)
    {
        bool removeChar = false;
        QChar ch = input.at(idx);
        // Corrections made are very conservative on purpose, to avoid
        // users unexpectedly getting away with typos that would normally
        // be detected, and thus sending to the wrong address.
        switch(ch.unicode())
        {
        // Qt categorizes these as "Other_Format" not "Separator_Space"
        case 0x200B: // ZERO WIDTH SPACE
        case 0xFEFF: // ZERO WIDTH NO-BREAK SPACE
            removeChar = true;
            break;
        default:
            break;
        }

        // Remove whitespace
        if (ch.isSpace())
            removeChar = true;

        // To next character
        if (removeChar)
            input.remove(idx, 1);
        else
            ++idx;
    }

    // Validation
    QValidator::State state = QValidator::Acceptable;
    for (int idx = 0; idx < input.size(); ++idx)
    {
        int ch = input.at(idx).unicode();

        if (((ch >= '0' && ch<='9') ||
            (ch >= 'a' && ch<='z') ||
            (ch >= 'A' && ch<='Z')) ||
            // allow spark name notation
            (ch == '@' && idx == 0) ||
            (input.at(0).unicode() == '@' && (ch == '.' || ch == '-' || ch == '_')))
        {
            // Alphanumeric and not a 'forbidden' character
        }
        else
        {
            state = QValidator::Invalid;
        }
    }

    return state;
}

BitcoinAddressCheckValidator::BitcoinAddressCheckValidator(QObject *parent) :
    QValidator(parent)
{
}

QValidator::State BitcoinAddressCheckValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    // Validate the passed Bitcoin address
    CBitcoinAddress addr(input.toStdString());
    if (addr.IsValid())
        return QValidator::Acceptable;

    if (bip47::CPaymentCode::validate(input.toStdString()))
        return QValidator::Acceptable;

    if (validateSparkAddress(input.toStdString()))
        return QValidator::Acceptable;

    return QValidator::Invalid;
}

bool BitcoinAddressCheckValidator::validateSparkAddress(const std::string& address) const
{
    // check for spark name
    if (address[0] == '@' && address.size() <= CSparkNameManager::maximumSparkNameLength + 1)
        return true;

    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    unsigned char coinNetwork;
    spark::Address addr(params);
    try {
        coinNetwork = addr.decode(address);
    } catch (const std::invalid_argument &) {
        return false;
    }
    return network == coinNetwork;
}