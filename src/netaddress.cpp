// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include "config/bitcoin-config.h"
#endif

#include "netaddress.h"
#include "hash.h"
#include "utilstrencodings.h"
#include "tinyformat.h"
#include "span.h"
#include "crypto/sha3.h"

#include <algorithm>

// RFC6052 (IPv4-Embedded IPv6 Address Prefix)
static constexpr std::array<uint8_t, 12> ADDR_RFC6052_PREFIX = {0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0};
// RFC4862 (IPv6 Stateless Address Autoconfiguration)
static constexpr std::array<uint8_t, 8> ADDR_RFC4862_PREFIX = {0xFE, 0x80, 0, 0, 0, 0, 0, 0};
// RFC6145 (IP/ICMP Translation Algorithm)
static constexpr std::array<uint8_t, 12> ADDR_RFC6145_PREFIX = {0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0};

constexpr size_t CNetAddr::V1_SERIALIZATION_SIZE;

namespace torv3 {
// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
static constexpr size_t CHECKSUM_LEN = 2;
static const unsigned char VERSION[] = {3};
static constexpr size_t TOTAL_LEN = ADDR_TORV3_SIZE + CHECKSUM_LEN + sizeof(VERSION);

static void Checksum(Span<const uint8_t> addr_pubkey, uint8_t (&checksum)[CHECKSUM_LEN])
{
    // TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    static const unsigned char prefix[] = ".onion checksum";
    static constexpr size_t prefix_len = 15;

    SHA3_256 hasher;
    hasher.Write(MakeSpan(prefix).first(prefix_len));
    hasher.Write(addr_pubkey);
    hasher.Write(VERSION);

    uint8_t checksum_full[SHA3_256::OUTPUT_SIZE];
    hasher.Finalize(checksum_full);

    memcpy(checksum, checksum_full, sizeof(checksum));
}

}; // namespace torv3

/**
 * Construct an unspecified IPv6 network address (::/128).
 *
 * @note This address is considered invalid by CNetAddr::IsValid()
 */
CNetAddr::CNetAddr() {}

void CNetAddr::SetIP(const CNetAddr& ipIn)
{
    // Size check.
    switch (ipIn.m_net) {
    case NET_IPV4:
        assert(ipIn.m_addr.size() == ADDR_IPV4_SIZE);
        break;
    case NET_IPV6:
        assert(ipIn.m_addr.size() == ADDR_IPV6_SIZE);
        break;
    case NET_ONION:
        assert(ipIn.m_addr.size() == ADDR_TORV2_SIZE || ipIn.m_addr.size() == ADDR_TORV3_SIZE);
        break;
    case NET_I2P:
        assert(ipIn.m_addr.size() == ADDR_I2P_SIZE);
        break;
    case NET_CJDNS:
        assert(ipIn.m_addr.size() == ADDR_CJDNS_SIZE);
        break;
    case NET_INTERNAL:
        assert(ipIn.m_addr.size() == ADDR_INTERNAL_SIZE);
        break;
    case NET_UNROUTABLE:
    case NET_MAX:
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    m_net = ipIn.m_net;
    m_addr = ipIn.m_addr;
}

void CNetAddr::SetLegacyIPv6(Span<const uint8_t> ipv6)
{
    assert(ipv6.size() == ADDR_IPV6_SIZE);

    size_t skip{0};

    if (HasPrefix(ipv6, IPV4_IN_IPV6_PREFIX)) {
        // IPv4-in-IPv6
        m_net = NET_IPV4;
        skip = sizeof(IPV4_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6, TORV2_IN_IPV6_PREFIX)) {
        // TORv2-in-IPv6
        m_net = NET_ONION;
        skip = sizeof(TORV2_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6, INTERNAL_IN_IPV6_PREFIX)) {
        // Internal-in-IPv6
        m_net = NET_INTERNAL;
        skip = sizeof(INTERNAL_IN_IPV6_PREFIX);
    } else {
        // CJDNS addresses start with 0xfc (fc00::/8)
        if (ipv6[0] == 0xfc) {
            m_net = NET_CJDNS;
        } else {
            // IPv6
            m_net = NET_IPV6;
        }
    }

    m_addr.assign(ipv6.begin() + skip, ipv6.end());
}

/**
 * Create an "internal" address that represents a name or FQDN. CAddrMan uses
 * these fake addresses to keep track of which DNS seeds were used.
 * @returns Whether or not the operation was successful.
 * @see NET_INTERNAL, INTERNAL_IN_IPV6_PREFIX, CNetAddr::IsInternal(), CNetAddr::IsRFC4193()
 */
bool CNetAddr::SetInternal(const std::string &name)
{
    if (name.empty()) {
        return false;
    }
    m_net = NET_INTERNAL;
    unsigned char hash[32] = {};
    CSHA256().Write((const unsigned char*)name.data(), name.size()).Finalize(hash);
    m_addr.assign(hash, hash + ADDR_INTERNAL_SIZE);
    return true;
}

/**
 * Parse a TOR address and set this object to it.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsTor()
 */
bool CNetAddr::SetSpecial(const std::string& str)
{
    // Check for embedded null characters (security check)
    if (str.size() != strlen(str.c_str())) {
        return false;
    }

    // Handle .onion (TOR) addresses
    {
        static const char* suffix{".onion"};
        static constexpr size_t suffix_len{6};

        if (str.size() > suffix_len && str.substr(str.size() - suffix_len) == suffix) {
            bool invalid;
            const auto& input = DecodeBase32(str.substr(0, str.size() - suffix_len).c_str(), &invalid);

            if (invalid) {
                return false;
            }

            switch (input.size()) {
            case ADDR_TORV2_SIZE:
                m_net = NET_ONION;
                m_addr.assign(input.begin(), input.end());
                return true;
            case torv3::TOTAL_LEN: {
                Span<const uint8_t> input_pubkey{input.data(), ADDR_TORV3_SIZE};
                Span<const uint8_t> input_checksum{input.data() + ADDR_TORV3_SIZE, torv3::CHECKSUM_LEN};
                Span<const uint8_t> input_version{input.data() + ADDR_TORV3_SIZE + torv3::CHECKSUM_LEN, sizeof(torv3::VERSION)};

                uint8_t calculated_checksum[torv3::CHECKSUM_LEN];
                torv3::Checksum(input_pubkey, calculated_checksum);

                if (input_checksum != calculated_checksum || input_version != torv3::VERSION) {
                    return false;
                }

                m_net = NET_ONION;
                m_addr.assign(input_pubkey.begin(), input_pubkey.end());
                return true;
            }
            }

            return false;
        }
    }

    // Handle .b32.i2p (I2P) addresses
    {
        static const char* suffix{".b32.i2p"};
        static constexpr size_t suffix_len{8};

        if (str.size() > suffix_len && str.substr(str.size() - suffix_len) == suffix) {
            bool invalid;
            const auto& input = DecodeBase32(str.substr(0, str.size() - suffix_len).c_str(), &invalid);

            if (invalid) {
                return false;
            }

            if (input.size() == ADDR_I2P_SIZE) {
                m_net = NET_I2P;
                m_addr.assign(input.begin(), input.end());
                return true;
            }

            return false;
        }
    }

    return false;
}

CNetAddr::CNetAddr(const struct in_addr& ipv4Addr)
{
    m_net = NET_IPV4;
    m_addr.assign((const uint8_t*)&ipv4Addr, (const uint8_t*)&ipv4Addr + sizeof(ipv4Addr));
}

CNetAddr::CNetAddr(const struct in6_addr& ipv6Addr, const uint32_t scope)
{
    SetLegacyIPv6(ipv6Addr.s6_addr);
    scopeId = scope;
}

bool CNetAddr::IsBindAny() const
{
    if (!IsIPv4() && !IsIPv6()) {
        return false;
    }
    return std::all_of(m_addr.begin(), m_addr.end(), [](uint8_t b) { return b == 0; });
}

bool CNetAddr::IsIPv4() const
{
    return m_net == NET_IPV4;
}

bool CNetAddr::IsIPv6() const
{
    return m_net == NET_IPV6;
}

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() && (
        m_addr[0] == 10 ||
        (m_addr[0] == 192 && m_addr[1] == 168) ||
        (m_addr[0] == 172 && m_addr[1] >= 16 && m_addr[1] <= 31));
}

bool CNetAddr::IsRFC2544() const
{
    return IsIPv4() && m_addr[0] == 198 && (m_addr[1] == 18 || m_addr[1] == 19);
}

bool CNetAddr::IsRFC3927() const
{
    return IsIPv4() && m_addr[0] == 169 && m_addr[1] == 254;
}

bool CNetAddr::IsRFC6598() const
{
    return IsIPv4() && m_addr[0] == 100 && m_addr[1] >= 64 && m_addr[1] <= 127;
}

bool CNetAddr::IsRFC5737() const
{
    return IsIPv4() && (
        (m_addr[0] == 192 && m_addr[1] == 0 && m_addr[2] == 2) ||
        (m_addr[0] == 198 && m_addr[1] == 51 && m_addr[2] == 100) ||
        (m_addr[0] == 203 && m_addr[1] == 0 && m_addr[2] == 113));
}

bool CNetAddr::IsRFC3849() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x0D && m_addr[3] == 0xB8;
}

bool CNetAddr::IsRFC3964() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x02;
}

bool CNetAddr::IsRFC6052() const
{
    return IsIPv6() && HasPrefix(m_addr, ADDR_RFC6052_PREFIX);
}

bool CNetAddr::IsRFC4380() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x01 && m_addr[2] == 0 && m_addr[3] == 0;
}

bool CNetAddr::IsRFC4862() const
{
    return IsIPv6() && HasPrefix(m_addr, ADDR_RFC4862_PREFIX);
}

bool CNetAddr::IsRFC4193() const
{
    return IsIPv6() && (m_addr[0] & 0xFE) == 0xFC;
}

bool CNetAddr::IsRFC6145() const
{
    return IsIPv6() && HasPrefix(m_addr, ADDR_RFC6145_PREFIX);
}

bool CNetAddr::IsRFC4843() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x00 && (m_addr[3] & 0xF0) == 0x10;
}

bool CNetAddr::IsRFC7343() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x00 && (m_addr[3] & 0xF0) == 0x20;
}

bool CNetAddr::IsHeNet() const
{
    return IsIPv6() && m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x04 && m_addr[3] == 0x70;
}

bool CNetAddr::IsTor() const
{
    return m_net == NET_ONION;
}

bool CNetAddr::IsI2P() const
{
    return m_net == NET_I2P;
}

bool CNetAddr::IsCJDNS() const
{
    return m_net == NET_CJDNS;
}

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback (127.0.0.0/8 or 0.0.0.0/8)
    if (IsIPv4() && (m_addr[0] == 127 || m_addr[0] == 0)) {
        return true;
    }

    // IPv6 loopback (::1/128)
    if (IsIPv6()) {
        static constexpr uint8_t pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (m_addr.size() == 16 && std::equal(pchLocal, pchLocal + 16, m_addr.begin())) {
            return true;
        }
    }

    return false;
}



bool CNetAddr::IsValid() const
{
    // unspecified IPv6 address (::/128)
    if (IsIPv6() && std::all_of(m_addr.begin(), m_addr.end(), [](uint8_t b) { return b == 0; })) {
        return false;
    }

    // documentation IPv6 address
    if (IsRFC3849())
        return false;

    // INTERNAL addresses are not valid for external use
    if (IsInternal())
        return false;

    if (IsIPv4()) {
        // INADDR_NONE
        uint32_t ipNone = INADDR_NONE;
        if (m_addr.size() == ADDR_IPV4_SIZE && std::equal(m_addr.begin(), m_addr.end(), (uint8_t*)&ipNone)) {
            return false;
        }

        // 0
        if (std::all_of(m_addr.begin(), m_addr.end(), [](uint8_t b) { return b == 0; })) {
            return false;
        }
    }

    return true;
}

bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || 
                          IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsInternal()) || 
                          IsRFC4843() || IsLocal() || IsInternal());
}

bool CNetAddr::IsInternal() const
{
    return m_net == NET_INTERNAL;
}

enum Network CNetAddr::GetNetwork() const
{
    if (IsInternal())
        return NET_INTERNAL;

    if (!IsRoutable())
        return NET_UNROUTABLE;

    return m_net;
}

CNetAddr::BIP155Network CNetAddr::GetBIP155Network() const
{
    assert(!IsInternal());
    switch (m_net) {
    case NET_IPV4:
        return BIP155Network::IPV4;
    case NET_IPV6:
        return BIP155Network::IPV6;
    case NET_ONION:
        if (m_addr.size() == ADDR_TORV3_SIZE) {
            return BIP155Network::TORV3;
        } else if (m_addr.size() == ADDR_TORV2_SIZE) {
            return BIP155Network::TORV2;
        } else {
            assert(false);
        }
    case NET_I2P:
        return BIP155Network::I2P;
    case NET_CJDNS:
        return BIP155Network::CJDNS;
    case NET_INTERNAL:   // should have been handled before calling this function
    case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
    case NET_MAX:        // m_net is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

bool CNetAddr::SetNetFromBIP155Network(uint8_t possible_bip155_net, size_t address_size)
{
    switch (possible_bip155_net) {
    case BIP155Network::IPV4:
        if (address_size == ADDR_IPV4_SIZE) {
            m_net = NET_IPV4;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv4 address with length %u (should be %u)", address_size,
                      ADDR_IPV4_SIZE));
    case BIP155Network::IPV6:
        if (address_size == ADDR_IPV6_SIZE) {
            m_net = NET_IPV6;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv6 address with length %u (should be %u)", address_size,
                      ADDR_IPV6_SIZE));
    case BIP155Network::TORV2:
        if (address_size == ADDR_TORV2_SIZE) {
            m_net = NET_ONION;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv2 address with length %u (should be %u)", address_size,
                      ADDR_TORV2_SIZE));
    case BIP155Network::TORV3:
        if (address_size == ADDR_TORV3_SIZE) {
            m_net = NET_ONION;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv3 address with length %u (should be %u)", address_size,
                      ADDR_TORV3_SIZE));
    case BIP155Network::I2P:
        if (address_size == ADDR_I2P_SIZE) {
            m_net = NET_I2P;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 I2P address with length %u (should be %u)", address_size,
                      ADDR_I2P_SIZE));
    case BIP155Network::CJDNS:
        if (address_size == ADDR_CJDNS_SIZE) {
            m_net = NET_CJDNS;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 CJDNS address with length %u (should be %u)", address_size,
                      ADDR_CJDNS_SIZE));
    }

    // Don't throw on addresses with unknown network ids (maybe from the future).
    // Instead silently drop them and have the unserialization code consume
    // subsequent ones which may be known to us.
    return false;
}

// Return an IPv6 address text representation with zero compression as described in RFC 5952
// ("A Recommendation for IPv6 Address Text Representation").
static std::string IPv6ToString(Span<const uint8_t> a)
{
    assert(a.size() == ADDR_IPV6_SIZE);
    const std::array<uint16_t, 8> groups{
        ReadBE16(&a[0]),
        ReadBE16(&a[2]),
        ReadBE16(&a[4]),
        ReadBE16(&a[6]),
        ReadBE16(&a[8]),
        ReadBE16(&a[10]),
        ReadBE16(&a[12]),
        ReadBE16(&a[14]),
    };

    struct ZeroSpan {
        size_t start_index{0};
        size_t len{0};
    };

    // Find longest sequence of consecutive all-zero fields. Use first zero sequence if two or more
    // zero sequences of equal length are found.
    ZeroSpan longest, current;
    for (size_t i{0}; i < groups.size(); ++i) {
        if (groups[i] != 0) {
            current = {i + 1, 0};
            continue;
        }
        current.len += 1;
        if (current.len > longest.len) {
            longest = current;
        }
    }

    std::string r;
    r.reserve(39);
    for (size_t i{0}; i < groups.size(); ++i) {
        // Replace the longest sequence of consecutive all-zero fields with two colons ("::").
        if (longest.len >= 2 && i >= longest.start_index && i < longest.start_index + longest.len) {
            if (i == longest.start_index) {
                r += "::";
            }
            continue;
        }
        r += strprintf("%s%x", ((!r.empty() && r.back() != ':') ? ":" : ""), groups[i]);
    }

    return r;
}

std::string CNetAddr::ToStringIP() const
{
    switch (m_net) {
    case NET_IPV4:
        return strprintf("%u.%u.%u.%u", m_addr[0], m_addr[1], m_addr[2], m_addr[3]);
    case NET_IPV6:
        return IPv6ToString(m_addr);
    case NET_ONION:
        switch (m_addr.size()) {
        case ADDR_TORV2_SIZE:
            return EncodeBase32(m_addr) + ".onion";
        case ADDR_TORV3_SIZE: {
            uint8_t checksum[torv3::CHECKSUM_LEN];
            torv3::Checksum(m_addr, checksum);

            // TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
            prevector<torv3::TOTAL_LEN, uint8_t> address{m_addr.begin(), m_addr.end()};
            address.insert(address.end(), checksum, checksum + torv3::CHECKSUM_LEN);
            address.insert(address.end(), torv3::VERSION, torv3::VERSION + sizeof(torv3::VERSION));

            return EncodeBase32(address) + ".onion";
        }
        default:
            assert(false);
        }
    case NET_I2P:
        return EncodeBase32(m_addr, false /* don't pad with = */) + ".b32.i2p";
    case NET_CJDNS:
        return IPv6ToString(m_addr);
    case NET_INTERNAL:
        return EncodeBase32(m_addr) + ".internal";
    case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
    case NET_MAX:        // m_net is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool CNetAddr::IsAddrV1Compatible() const
{
    switch (m_net) {
    case NET_IPV4:
    case NET_IPV6:
    case NET_INTERNAL:
        return true;
    case NET_ONION:
        return m_addr.size() == ADDR_TORV2_SIZE;
    case NET_I2P:
    case NET_CJDNS:
        return false;
    case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
    case NET_MAX:        // m_net is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

std::vector<uint8_t> CNetAddr::GetAddrBytes() const
{
    if (IsAddrV1Compatible()) {
        uint8_t serialized[V1_SERIALIZATION_SIZE];
        SerializeV1Array(serialized);
        return std::vector<uint8_t>(std::begin(serialized), std::end(serialized));
    }
    return std::vector<uint8_t>(m_addr.begin(), m_addr.end());
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return a.m_net == b.m_net && a.m_addr == b.m_addr;
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    return std::tie(a.m_net, a.m_addr) < std::tie(b.m_net, b.m_addr);
}

bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
{
    if (!IsIPv4())
        return false;
    assert(m_addr.size() == ADDR_IPV4_SIZE);
    memcpy(pipv4Addr, m_addr.data(), 4);
    return true;
}

bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
{
    if (!IsIPv6() && !IsCJDNS())
        return false;
    assert(m_addr.size() == ADDR_IPV6_SIZE || m_addr.size() == ADDR_CJDNS_SIZE);
    memcpy(pipv6Addr, m_addr.data(), 16);
    return true;
}

bool CNetAddr::HasLinkedIPv4() const
{
    return IsRoutable() && (IsIPv4() || IsRFC6145() || IsRFC6052() || IsRFC3964() || IsRFC4380());
}

uint32_t CNetAddr::GetLinkedIPv4() const
{
    if (IsIPv4()) {
        return ReadBE32(m_addr.data());
    } else if (IsRFC6052() || IsRFC6145()) {
        // mapped IPv4, SIIT translated IPv4: the IPv4 address is the last 4 bytes of the address
        return ReadBE32(MakeSpan(m_addr).last(ADDR_IPV4_SIZE).data());
    } else if (IsRFC3964()) {
        // 6to4 tunneled IPv4: the IPv4 address is in bytes 2-6
        return ReadBE32(MakeSpan(m_addr).subspan(2, ADDR_IPV4_SIZE).data());
    } else if (IsRFC4380()) {
        // Teredo tunneled IPv4: the IPv4 address is in the last 4 bytes of the address, but bitflipped
        return ~ReadBE32(MakeSpan(m_addr).last(ADDR_IPV4_SIZE).data());
    }
    assert(false);
}

uint32_t CNetAddr::GetNetClass() const
{
    // Make sure that if we return NET_IPV6, then IsIPv6() is true. The callers expect that.

    // Check for "internal" first because such addresses are also !IsRoutable()
    // and we don't want to return NET_UNROUTABLE in that case.
    if (IsInternal()) {
        return NET_INTERNAL;
    }
    if (!IsRoutable()) {
        return NET_UNROUTABLE;
    }
    if (HasLinkedIPv4()) {
        return NET_IPV4;
    }
    return m_net;
}

uint32_t CNetAddr::GetMappedAS(const std::vector<bool> &asmap) const {
    // ASN (Autonomous System Number) mapping for advanced Sybil attack resistance.
    // 
    // This function would map IP addresses to their ASN using BGP routing data from an asmap file.
    // ASNs identify network operators (ISPs, datacenters, cloud providers), allowing Bitcoin to
    // group addresses by their actual network infrastructure rather than just IP prefixes.
    //
    // Benefits:
    // - Makes Sybil attacks much more expensive (attacker needs IPs from many different ASNs)
    // - Better than /16 IPv4 or /32 IPv6 grouping (cloud providers can have many /16 blocks)
    // - Example: All AWS IPs map to AS16509, so 1000 AWS VPS = 1 connection slot
    //
    // Implementation requirements:
    // - util/asmap.h: ASMap loading, validation, and Interpret() function
    // - asmap.dat: Compressed BGP routing table (needs periodic updates)
    // - Generation tools: Scripts to create asmap from BGP dumps
    //
    // For now, return 0 to indicate "no ASN mapping available" and fall back to IP prefix grouping.
    // When implemented, GetGroup() will use ASN-based bucketing for IPv4/IPv6 addresses.
    return 0; // AS0 is reserved per RFC7607, safe sentinel value
}

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
std::vector<unsigned char> CNetAddr::GetGroup(const std::vector<bool> &asmap) const
{
    // STEP 1: Try ASN mapping first (if asmap provided and address is mappable)
    
    std::vector<unsigned char> vchRet;
    uint32_t net_class = GetNetClass();
    // If non-empty asmap is supplied and the address is IPv4/IPv6,
    // return ASN to be used for bucketing.
    // Note: GetMappedAS currently returns 0 (ASN support not yet implemented)
    uint32_t asn = GetMappedAS(asmap);
    if (asn != 0) { // Either asmap was empty, or address has non-asmappable net class (e.g. TOR).
        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN should be in the same bucket
        for (int i = 0; i < 4; i++) {
            vchRet.push_back((asn >> (8 * i)) & 0xFF);
        }
        return vchRet;
    }

    // STEP 2: Fallback to manual grouping (asn == 0)
    // This happens when:
    // - asmap is empty, OR
    // - Address type is not ASN-mappable (TOR, I2P, Internal, etc.)
    
    vchRet.push_back(net_class);
    int nBits{0};

    if (IsLocal()) {
        // all local addresses belong to the same group
    } else if (IsInternal()) {
        // all internal-usage addresses get their own group
        nBits = ADDR_INTERNAL_SIZE * 8;
    } else if (!IsRoutable()) {
        // all other unroutable addresses belong to the same group
    } else if (HasLinkedIPv4()) {
        // IPv4 addresses (and mapped IPv4 addresses) use /16 groups
        uint32_t ipv4 = GetLinkedIPv4();
        vchRet.push_back((ipv4 >> 24) & 0xFF);
        vchRet.push_back((ipv4 >> 16) & 0xFF);
        return vchRet;
    } else if (IsTor() || IsI2P() || IsCJDNS()) {
        nBits = 4;
    } else if (IsHeNet()) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    // Push our address onto vchRet.
    const size_t num_bytes = nBits / 8;
    vchRet.insert(vchRet.end(), m_addr.begin(), m_addr.begin() + num_bytes);
    nBits %= 8;
    // ...for the last byte, push nBits and for the rest of the byte push 1's
    if (nBits > 0) {
        assert(num_bytes < m_addr.size());
        vchRet.push_back(m_addr[num_bytes] | ((1 << (8 - nBits)) - 1));
    }

    return vchRet;
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(m_addr.begin(), m_addr.end());
    uint64_t nRet;
    memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == NULL)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable() || IsInternal())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch(theirNet) {
    case NET_IPV4:
        switch(ourNet) {
        default:       return REACH_DEFAULT;
        case NET_IPV4: return REACH_IPV4;
        }
    case NET_IPV6:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_TEREDO: return REACH_TEREDO;
        case NET_IPV4:   return REACH_IPV4;
        case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_ONION:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_ONION:    return REACH_PRIVATE;
        }
    case NET_I2P:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_I2P:    return REACH_PRIVATE;
        }
    case NET_CJDNS:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_CJDNS:  return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case NET_UNROUTABLE:
    default:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        case NET_ONION:     return REACH_PRIVATE; // either from Tor, or don't care about our address
        case NET_I2P:       return REACH_PRIVATE;
        case NET_CJDNS:     return REACH_PRIVATE;
        }
    }
}

CService::CService() : port(0)
{
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

CService::CService(const struct in_addr& ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn)
{
}

CService::CService(const struct in6_addr& ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn)
{
}

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr, addr.sin6_scope_id), port(ntohs(addr.sin6_port))
{
   assert(addr.sin6_family == AF_INET6);
}

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in*)paddr);
        return true;
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6*)paddr);
        return true;
    default:
        return false;
    }
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return (CNetAddr)a == (CNetAddr)b && a.port == b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
}

bool CService::GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
    if (IsIPv6()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_scope_id = scopeId;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
    return false;
}

std::vector<unsigned char> CService::GetKey() const
{
    std::vector<unsigned char> vKey;
    vKey.resize(m_addr.size() + 2);
    memcpy(vKey.data(), m_addr.data(), m_addr.size());
    vKey[m_addr.size()] = port / 0x100;  // port MSB
    vKey[m_addr.size() + 1] = port & 0x0FF;  // port LSB
    return vKey;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

CSubNet::CSubNet():
    valid(false)
{
    memset(netmask, 0, sizeof(netmask));
}

CSubNet::CSubNet(const CNetAddr &addr, uint8_t mask)
{
    valid = (addr.IsIPv4() && mask <= ADDR_IPV4_SIZE * 8) ||
            (addr.IsIPv6() && mask <= ADDR_IPV6_SIZE * 8);
    if (!valid) {
        return;
    }

    network = addr;
    // Default to /32 (IPv4) or /128 (IPv6), i.e. match single address
    memset(netmask, 255, sizeof(netmask));

    // IPv4 addresses start at offset 12 in legacy representation
    const int astartofs = network.IsIPv4() ? 12 : 0;

    // byte-level clearing with bit precision
    for (int32_t i = astartofs; i < 16; i++) {
        uint8_t bits = (i - astartofs) * 8;
        if (bits >= mask) {
            netmask[i] = 0;
        } else {
            uint8_t remainingBits = mask - bits;
            netmask[i] = (remainingBits >= 8) ? 0xFF : (0xFF << (8 - remainingBits));
        }
    }

    // Normalize network according to netmask
    std::vector<uint8_t> addr_bytes = network.GetAddrBytes();
    // For backward compatibility, compute normalized address in legacy format
    uint8_t ip_legacy[16];
    if (network.IsIPv4()) {
        // addr_bytes is already 16 bytes with IPv4-in-IPv6 format
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else if (network.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        // For other network types, just use zeroes
        memset(ip_legacy, 0, 16);
    }
    
    for(int x=0; x<16; ++x)
        ip_legacy[x] &= netmask[x];
    
    // Convert back to CNetAddr using SetLegacyIPv6
    network.SetLegacyIPv6(Span<const uint8_t>(ip_legacy, 16));
}

CSubNet::CSubNet(const CNetAddr &addr, const CNetAddr &mask)
{
    valid = (addr.IsIPv4() && mask.IsIPv4()) || (addr.IsIPv6() && mask.IsIPv6());
    if (!valid) {
        return;
    }
    network = addr;
    // Default to /32 (IPv4) or /128 (IPv6), i.e. match single address
    memset(netmask, 255, sizeof(netmask));

    // Convert mask to legacy format for computation
    std::vector<uint8_t> mask_bytes = mask.GetAddrBytes();
    if (mask.IsIPv4()) {
        // mask_bytes is 16 bytes with IPv4 at offset 12
        memcpy(netmask + 12, mask_bytes.data() + 12, 4);
    } else if (mask.IsIPv6()) {
        memcpy(netmask, mask_bytes.data(), 16);
    }

    // Validate netmask - all 1 bits must be contiguous on the left
    // e.g., 255.0.255.255, 255.255.255.129 are not valid
    //       255.255.255.0, 255.255.255.192 are valid
    bool zeros_found = false;
    for (size_t i = 0; i < 16; i++) {
        uint8_t x = netmask[i];
        for (int bit = 0; bit < 8; bit++) {
            bool bit_set = (x & 0x80) != 0;
            if (!bit_set) {
                zeros_found = true;
            } else if (zeros_found) {
                // Found a 1 bit after a 0 bit -> invalid
                valid = false;
                return;
            }
            x <<= 1;
        }
    }

    // Normalize network according to netmask
    std::vector<uint8_t> addr_bytes = network.GetAddrBytes();
    uint8_t ip_legacy[16];
    if (network.IsIPv4()) {
        // addr_bytes is already 16 bytes with IPv4-in-IPv6 format
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else if (network.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        memset(ip_legacy, 0, 16);
    }
    
    for(int x=0; x<16; ++x)
        ip_legacy[x] &= netmask[x];
    
    // Convert back to CNetAddr using SetLegacyIPv6
    network.SetLegacyIPv6(Span<const uint8_t>(ip_legacy, 16));
}

CSubNet::CSubNet(const CNetAddr &addr):
    valid(addr.IsValid())
{
    memset(netmask, 255, sizeof(netmask));
    network = addr;
}

bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid())
        return false;
    
    // Convert addr to legacy format for comparison
    std::vector<uint8_t> addr_bytes = addr.GetAddrBytes();
    uint8_t ip_legacy[16];
    if (addr.IsIPv4()) {
        // addr_bytes is already 16 bytes with IPv4-in-IPv6 format
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else if (addr.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        return false;
    }
    
    // Get network bytes in legacy format
    std::vector<uint8_t> net_bytes = network.GetAddrBytes();
    uint8_t net_legacy[16];
    if (network.IsIPv4()) {
        // net_bytes is already 16 bytes with IPv4-in-IPv6 format
        memcpy(net_legacy, net_bytes.data(), 16);
    } else if (network.IsIPv6()) {
        memcpy(net_legacy, net_bytes.data(), 16);
    } else {
        return false;
    }
    
    for(int x=0; x<16; ++x) {
        if ((ip_legacy[x] & netmask[x]) != net_legacy[x])
            return false;
    }
    return true;
}

static inline int NetmaskBits(uint8_t x)
{
    switch(x) {
    case 0x00: return 0; break;
    case 0x80: return 1; break;
    case 0xc0: return 2; break;
    case 0xe0: return 3; break;
    case 0xf0: return 4; break;
    case 0xf8: return 5; break;
    case 0xfc: return 6; break;
    case 0xfe: return 7; break;
    case 0xff: return 8; break;
    default: return -1; break;
    }
}

std::string CSubNet::ToString() const
{
    /* Parse binary 1{n}0{N-n} to see if mask can be represented as /n */
    int cidr = 0;
    bool valid_cidr = true;
    int n = network.IsIPv4() ? 12 : 0;
    for (; n < 16 && netmask[n] == 0xff; ++n)
        cidr += 8;
    if (n < 16) {
        int bits = NetmaskBits(netmask[n]);
        if (bits < 0)
            valid_cidr = false;
        else
            cidr += bits;
        ++n;
    }
    for (; n < 16 && valid_cidr; ++n)
        if (netmask[n] != 0x00)
            valid_cidr = false;

    /* Format output */
    std::string strNetmask;
    if (valid_cidr) {
        strNetmask = strprintf("%u", cidr);
    } else {
        if (network.IsIPv4())
            strNetmask = strprintf("%u.%u.%u.%u", netmask[12], netmask[13], netmask[14], netmask[15]);
        else
            strNetmask = strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                             netmask[0] << 8 | netmask[1], netmask[2] << 8 | netmask[3],
                             netmask[4] << 8 | netmask[5], netmask[6] << 8 | netmask[7],
                             netmask[8] << 8 | netmask[9], netmask[10] << 8 | netmask[11],
                             netmask[12] << 8 | netmask[13], netmask[14] << 8 | netmask[15]);
    }

    return network.ToString() + "/" + strNetmask;
}

bool CSubNet::IsValid() const
{
    return valid;
}

bool operator==(const CSubNet& a, const CSubNet& b)
{
    return a.valid == b.valid && a.network == b.network && !memcmp(a.netmask, b.netmask, 16);
}

bool operator<(const CSubNet& a, const CSubNet& b)
{
    return (a.network < b.network || (a.network == b.network && memcmp(a.netmask, b.netmask, 16) < 0));
}
