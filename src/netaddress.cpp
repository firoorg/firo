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

#include <algorithm>

// RFC6052 (IPv4-Embedded IPv6 Address Prefix)
static constexpr std::array<uint8_t, 12> ADDR_RFC6052_PREFIX = {0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0};
// RFC4862 (IPv6 Stateless Address Autoconfiguration)
static constexpr std::array<uint8_t, 8> ADDR_RFC4862_PREFIX = {0xFE, 0x80, 0, 0, 0, 0, 0, 0};
// RFC6145 (IP/ICMP Translation Algorithm)
static constexpr std::array<uint8_t, 12> ADDR_RFC6145_PREFIX = {0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0};

constexpr size_t CNetAddr::V1_SERIALIZATION_SIZE;

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
        assert(ipIn.m_addr.size() == ADDR_TORV2_SIZE);
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

template <typename T1, size_t PREFIX_LEN>
inline bool HasPrefix(const T1& obj, const std::array<uint8_t, PREFIX_LEN>& prefix)
{
    return obj.size() >= PREFIX_LEN &&
           std::equal(std::begin(prefix), std::end(prefix), std::begin(obj));
}

void CNetAddr::SetLegacyIPv6(const uint8_t ipv6[16])
{
    size_t skip{0};

    std::vector<uint8_t> ipv6_vec(ipv6, ipv6 + 16);

    if (HasPrefix(ipv6_vec, IPV4_IN_IPV6_PREFIX)) {
        // IPv4-in-IPv6
        m_net = NET_IPV4;
        skip = sizeof(IPV4_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6_vec, TORV2_IN_IPV6_PREFIX)) {
        // TORv2-in-IPv6
        m_net = NET_ONION;
        skip = sizeof(TORV2_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6_vec, INTERNAL_IN_IPV6_PREFIX)) {
        // Internal-in-IPv6
        m_net = NET_INTERNAL;
        skip = sizeof(INTERNAL_IN_IPV6_PREFIX);
    } else {
        // IPv6
        m_net = NET_IPV6;
    }

    m_addr.assign(ipv6 + skip, ipv6 + 16);
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
 * Parse a TORv2 address and set this object to it.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsTor()
 */
bool CNetAddr::SetSpecial(const std::string &strName)
{
    if (strName.size() > 6 && strName.substr(strName.size() - 6, 6) == ".onion") {
        std::vector<unsigned char> vchAddr = DecodeBase32(strName.substr(0, strName.size() - 6).c_str());
        if (vchAddr.size() != ADDR_TORV2_SIZE) {
            return false;
        }
        m_net = NET_ONION;
        m_addr.assign(vchAddr.begin(), vchAddr.end());
        return true;
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

bool CNetAddr::IsTor() const
{
    return m_net == NET_ONION;
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

std::string CNetAddr::ToStringIP() const
{
    if (IsTor()) {
        return EncodeBase32(m_addr.data(), m_addr.size()) + ".onion";
    }
    if (IsInternal()) {
        return EncodeBase32(m_addr.data(), m_addr.size()) + ".internal";
    }
    if (IsIPv4()) {
        return strprintf("%u.%u.%u.%u", m_addr[0], m_addr[1], m_addr[2], m_addr[3]);
    }
    if (IsIPv6()) {
        CService serv(*this, 0);
        struct sockaddr_storage sockaddr;
        socklen_t socklen = sizeof(sockaddr);
        if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
            char name[1025] = "";
            if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name, sizeof(name), NULL, 0, NI_NUMERICHOST))
                return std::string(name);
        }
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         m_addr[0] << 8 | m_addr[1], m_addr[2] << 8 | m_addr[3],
                         m_addr[4] << 8 | m_addr[5], m_addr[6] << 8 | m_addr[7],
                         m_addr[8] << 8 | m_addr[9], m_addr[10] << 8 | m_addr[11],
                         m_addr[12] << 8 | m_addr[13], m_addr[14] << 8 | m_addr[15]);
    }
    // Should be unreachable, but use EncodeBase32 for anything else
    return EncodeBase32(m_addr.data(), m_addr.size());
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

std::vector<uint8_t> CNetAddr::GetAddrBytes() const
{
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
    if (!IsIPv6())
        return false;
    assert(m_addr.size() == ADDR_IPV6_SIZE);
    memcpy(pipv6Addr, m_addr.data(), 16);
    return true;
}

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
std::vector<unsigned char> CNetAddr::GetGroup(const std::vector<bool> &asmap) const
{
    std::vector<unsigned char> vchRet;
    int nStartByte = 0;
    int nBits = 16;

    // all unroutable addresses belong to the same group
    if (!IsRoutable()) {
        vchRet.push_back(NET_UNROUTABLE);
        return vchRet;
    }

    // all internal addresses belong to the same group
    if (IsInternal()) {
        vchRet.push_back(NET_INTERNAL);
        return vchRet;
    }

    // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
    // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
    if (IsIPv4()) {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(m_addr[0]); // ipv4 addr is stored in m_addr[0..3]
        vchRet.push_back(m_addr[1]);
        return vchRet;
    }
    
    if (IsRFC6145() || IsRFC6052()) {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(m_addr[12]); // ipv4 is embedded at bytes 12-15 in the ipv6 address
        vchRet.push_back(m_addr[13]);
        return vchRet;
    }

    // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
    if (IsRFC3964()) {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(m_addr[2]);
        vchRet.push_back(m_addr[3]);
        return vchRet;
    }

    // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
    if (IsRFC4380()) {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(m_addr[12] ^ 0xFF);
        vchRet.push_back(m_addr[13] ^ 0xFF);
        return vchRet;
    }

    if (IsTor()) {
        vchRet.push_back(NET_ONION);
        nStartByte = 0;
        nBits = 4;
    } else if (IsIPv6()) {
        vchRet.push_back(NET_IPV6);
        // for he.net, use /36 groups
        if (m_addr[0] == 0x20 && m_addr[1] == 0x01 && m_addr[2] == 0x04 && m_addr[3] == 0x70) {
            nBits = 36;
        } else {
            // for the rest of the IPv6 network, use /32 groups
            nBits = 32;
        }
    }

    while (nBits >= 8) {
        vchRet.push_back(m_addr[nStartByte]);
        nStartByte++;
        nBits -= 8;
    }
    if (nBits > 0) {
        vchRet.push_back(m_addr[nStartByte] | ((1 << (8 - nBits)) - 1));
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

    if (!IsRoutable())
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
        return "[" + ToStringIP() + "]" + ToStringPort();
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
        memcpy(ip_legacy, IPV4_IN_IPV6_PREFIX.data(), sizeof(IPV4_IN_IPV6_PREFIX));
        memcpy(ip_legacy + 12, addr_bytes.data(), 4);
    } else if (network.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        // For other network types, just use zeroes
        memset(ip_legacy, 0, 16);
    }
    
    for(int x=0; x<16; ++x)
        ip_legacy[x] &= netmask[x];
    
    // Convert back to proper network type
    if (network.IsIPv4()) {
        network.m_net = NET_IPV4;
        network.m_addr.assign(ip_legacy + 12, ip_legacy + 16);
    } else if (network.IsIPv6()) {
        network.SetLegacyIPv6(ip_legacy);
    }
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
        memcpy(netmask + 12, mask_bytes.data(), 4);
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
        memcpy(ip_legacy, IPV4_IN_IPV6_PREFIX.data(), sizeof(IPV4_IN_IPV6_PREFIX));
        memcpy(ip_legacy + 12, addr_bytes.data(), 4);
    } else if (network.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        memset(ip_legacy, 0, 16);
    }
    
    for(int x=0; x<16; ++x)
        ip_legacy[x] &= netmask[x];
    
    // Convert back
    if (network.IsIPv4()) {
        network.m_net = NET_IPV4;
        network.m_addr.assign(ip_legacy + 12, ip_legacy + 16);
    } else if (network.IsIPv6()) {
        network.SetLegacyIPv6(ip_legacy);
    }
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
        memcpy(ip_legacy, IPV4_IN_IPV6_PREFIX.data(), sizeof(IPV4_IN_IPV6_PREFIX));
        memcpy(ip_legacy + 12, addr_bytes.data(), 4);
    } else if (addr.IsIPv6()) {
        memcpy(ip_legacy, addr_bytes.data(), 16);
    } else {
        return false;
    }
    
    for(int x=0; x<16; ++x) {
        // Get network bytes in legacy format
        std::vector<uint8_t> net_bytes = network.GetAddrBytes();
        uint8_t net_legacy[16];
        if (network.IsIPv4()) {
            memcpy(net_legacy, IPV4_IN_IPV6_PREFIX.data(), sizeof(IPV4_IN_IPV6_PREFIX));
            memcpy(net_legacy + 12, net_bytes.data(), 4);
        } else if (network.IsIPv6()) {
            memcpy(net_legacy, net_bytes.data(), 16);
        } else {
            return false;
        }
        
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
