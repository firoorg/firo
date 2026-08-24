// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_QT_ROSENBRIDGE_H
#define FIRO_QT_ROSENBRIDGE_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include <QString>

class CScript;

namespace RosenBridge
{

static constexpr std::size_t MAX_PAYLOAD_SIZE = 80;

struct Metadata {
    uint8_t toChain{0};
    QString chainName;
    uint64_t bridgeFee{0};
    uint64_t networkFee{0};
    std::vector<unsigned char> address;
};

bool Parse(const std::vector<unsigned char>& data, Metadata* metadata = nullptr, QString* error = nullptr);
bool ParseHex(const QString& hex, std::vector<unsigned char>* data, Metadata* metadata = nullptr, QString* error = nullptr);

CScript BuildOpReturnScript(const std::vector<unsigned char>& data);
std::size_t SerializedOutputSize(const std::vector<unsigned char>& data);
QString FormatDetails(const Metadata& metadata);
QString HexStr(const std::vector<unsigned char>& data);

} // namespace RosenBridge

#endif // FIRO_QT_ROSENBRIDGE_H
