// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rosenbridge.h"

#include "script/script.h"

#include <array>
#include <utility>

#include <QByteArray>
#include <QObject>
#include <QRegularExpression>

namespace RosenBridge
{
namespace
{

static constexpr std::size_t HEADER_SIZE = 18;

// This order is the payment-URI contract used by the Rosen UI that generates
// Firo bridge requests.
static const std::array<const char*, 8> CHAIN_NAMES{{
    "Ergo",
    "Cardano",
    "Bitcoin",
    "Ethereum",
    "Binance",
    "Doge",
    "Bitcoin Runes",
    "Firo",
}};

bool SetError(QString* error, const QString& message)
{
    if (error) {
        *error = message;
    }
    return false;
}

uint64_t ReadUint64BE(const std::vector<unsigned char>& data, std::size_t offset)
{
    uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | data[offset + i];
    }
    return value;
}

} // namespace

bool Parse(const std::vector<unsigned char>& data, Metadata* metadata, QString* error)
{
    if (data.size() > MAX_PAYLOAD_SIZE) {
        return SetError(error, QObject::tr("OP_RETURN metadata exceeds the 80-byte Rosen limit."));
    }
    if (data.size() < HEADER_SIZE + 1) {
        return SetError(error, QObject::tr("Rosen metadata is too short."));
    }

    const uint8_t toChain = data[0];
    if (toChain >= CHAIN_NAMES.size()) {
        return SetError(error, QObject::tr("Rosen metadata contains an unknown destination chain."));
    }

    const std::size_t addressLength = data[17];
    if (addressLength == 0) {
        return SetError(error, QObject::tr("Rosen metadata contains an empty destination address."));
    }
    if (data.size() != HEADER_SIZE + addressLength) {
        return SetError(error, QObject::tr("Rosen metadata destination-address length is inconsistent."));
    }

    if (metadata) {
        metadata->toChain = toChain;
        metadata->chainName = QString::fromLatin1(CHAIN_NAMES[toChain]);
        metadata->bridgeFee = ReadUint64BE(data, 1);
        metadata->networkFee = ReadUint64BE(data, 9);
        metadata->address.assign(data.begin() + HEADER_SIZE, data.end());
    }
    return true;
}

bool ParseHex(const QString& hex, std::vector<unsigned char>* data, Metadata* metadata, QString* error)
{
    static const QRegularExpression HEX_PATTERN(QStringLiteral("\\A[0-9A-Fa-f]+\\z"));

    if (hex.isEmpty()) {
        return SetError(error, QObject::tr("OP_RETURN metadata is empty."));
    }
    if ((hex.size() % 2) != 0 || !HEX_PATTERN.match(hex).hasMatch()) {
        return SetError(error, QObject::tr("OP_RETURN metadata must be an even-length hexadecimal string."));
    }
    if (static_cast<std::size_t>(hex.size() / 2) > MAX_PAYLOAD_SIZE) {
        return SetError(error, QObject::tr("OP_RETURN metadata exceeds the 80-byte Rosen limit."));
    }

    const QByteArray decoded = QByteArray::fromHex(hex.toLatin1());
    const auto* begin = reinterpret_cast<const unsigned char*>(decoded.constData());
    std::vector<unsigned char> parsed(begin, begin + decoded.size());
    Metadata parsedMetadata;
    if (!Parse(parsed, metadata ? &parsedMetadata : nullptr, error)) {
        return false;
    }

    if (data) {
        *data = std::move(parsed);
    }
    if (metadata) {
        *metadata = std::move(parsedMetadata);
    }
    return true;
}

CScript BuildOpReturnScript(const std::vector<unsigned char>& data)
{
    return CScript() << OP_RETURN << data;
}

std::size_t SerializedOutputSize(const std::vector<unsigned char>& data)
{
    // The largest supported script is 83 bytes, so its CompactSize is one byte.
    return 8 + 1 + BuildOpReturnScript(data).size();
}

QString FormatDetails(const Metadata& metadata)
{
    return QObject::tr("Destination chain: %1\nBridge fee: %2 atomic units\nNetwork fee: %3 atomic units\nDestination address (hex): %4")
        .arg(metadata.chainName,
            QString::number(static_cast<qulonglong>(metadata.bridgeFee)),
            QString::number(static_cast<qulonglong>(metadata.networkFee)),
            HexStr(metadata.address));
}

QString HexStr(const std::vector<unsigned char>& data)
{
    if (data.empty()) {
        return QString();
    }
    const QByteArray bytes(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()));
    return QString::fromLatin1(bytes.toHex());
}

} // namespace RosenBridge
