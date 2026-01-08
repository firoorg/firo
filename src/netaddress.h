// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETADDRESS_H
#define BITCOIN_NETADDRESS_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "compat.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <array>

enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_ONION,  // Tor v3

    NET_MAX,
};

// For backward compatibility
static const Network NET_TOR = NET_ONION;

/// Size of Tor v3 address (in bytes)
static constexpr size_t ADDR_TORV3_SIZE = 32;

/// Size of IPv4 address (in bytes)
static constexpr size_t ADDR_IPV4_SIZE = 4;

/// Size of IPv6 address (in bytes)
static constexpr size_t ADDR_IPV6_SIZE = 16;

/** IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96), or Tor v3) */
class CNetAddr
{
    protected:
        /**
         * Raw representation of the network address.
         * For IPv4 and IPv6, this is stored in the legacy format (16 bytes, IPv4 mapped to IPv6).
         * For Tor v3, this contains the 32-byte public key.
         */
        unsigned char m_addr[ADDR_TORV3_SIZE]; // large enough for any address type
        uint32_t scopeId; // for scoped/link-local ipv6 addresses
        Network m_net;    // network type

    public:
        CNetAddr();
        CNetAddr(const struct in_addr& ipv4Addr);
        void Init();
        void SetIP(const CNetAddr& ip);

        /**
         * Set raw IPv4 or IPv6 address (in network byte order)
         * @note Only NET_IPV4 and NET_IPV6 are allowed for network.
         */
        void SetRaw(Network network, const uint8_t *data);

        /**
         * Parse a Tor v3 address and set this object to it.
         * @param[in] addr Address to parse (56 character base32 string ending in .onion)
         * @return true if successfully parsed
         */
        bool SetSpecial(const std::string &strName); // for Tor v3 addresses
        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor)
        bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
        bool IsRFC2544() const; // IPv4 inter-network communications (192.18.0.0/15)
        bool IsRFC6598() const; // IPv4 ISP-level NAT (100.64.0.0/10)
        bool IsRFC5737() const; // IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
        bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
        bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
        bool IsRFC4193() const; // IPv6 unique local (FC00::/7)
        bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
        bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
        bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
        bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
        bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
        bool IsTor() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        enum Network GetNetwork() const;
        std::string ToString() const;
        std::string ToStringIP(bool fUseGetnameinfo = true) const;
        unsigned int GetByte(int n) const;
        uint64_t GetHash() const;
        bool GetInAddr(struct in_addr* pipv4Addr) const;
        std::vector<unsigned char> GetGroup() const;
        int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;

        CNetAddr(const struct in6_addr& pipv6Addr, const uint32_t scope = 0);
        bool GetIn6Addr(struct in6_addr* pipv6Addr) const;

        friend bool operator==(const CNetAddr& a, const CNetAddr& b);
        friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
        friend bool operator<(const CNetAddr& a, const CNetAddr& b);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            // For network serialization, we use a legacy-compatible 16-byte format.
            // IPv4/IPv6 addresses are serialized as 16-byte IPv6 (IPv4 mapped).
            // Tor v3 addresses are serialized as 16-byte OnionCat prefix + first 10 bytes
            // of the public key. This is lossy (Tor v3 requires 32 bytes) but maintains
            // backward compatibility with peers.dat and network messages from older nodes.
            //
            // NOTE: We intentionally do NOT read extra bytes based on OnionCat prefix
            // detection, because legacy Tor v2 addresses also used this prefix but only
            // occupy 16 bytes. Reading extra bytes would corrupt the deserialization
            // stream when processing old data.
            unsigned char ip_legacy[16];

            if (!ser_action.ForRead()) {
                if (m_net == NET_ONION) {
                    // Serialize Tor v3: OnionCat prefix + first 10 bytes of public key
                    // This is lossy but backward compatible (only 16 bytes written)
                    static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};
                    memcpy(ip_legacy, pchOnionCat, sizeof(pchOnionCat));
                    memcpy(ip_legacy + sizeof(pchOnionCat), m_addr, 10);
                } else {
                    memcpy(ip_legacy, m_addr, 16);
                }
            }
            READWRITE(FLATDATA(ip_legacy));
            if (ser_action.ForRead()) {
                // Copy the 16-byte legacy address and determine network type.
                // OnionCat prefix addresses (both legacy Tor v2 and truncated Tor v3)
                // are treated as IPv6 for backward compatibility. Full Tor v3 support
                // requires a versioned serialization format (e.g., ADDRv2/BIP 155).
                memcpy(m_addr, ip_legacy, 16);
                memset(m_addr + 16, 0, sizeof(m_addr) - 16); // Clear remaining bytes
                static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                if (memcmp(m_addr, pchIPv4, sizeof(pchIPv4)) == 0) {
                    m_net = NET_IPV4;
                } else {
                    m_net = NET_IPV6;
                }
            }
        }

        friend class CSubNet;
};

class CSubNet
{
    protected:
        /// Network (base) address
        CNetAddr network;
        /// Netmask, in network byte order
        uint8_t netmask[16];
        /// Is this value valid? (only used to signal parse errors)
        bool valid;

    public:
        CSubNet();
        CSubNet(const CNetAddr &addr, int32_t mask);
        CSubNet(const CNetAddr &addr, const CNetAddr &mask);

        //constructor for single ip subnet (<ipv4>/32 or <ipv6>/128)
        explicit CSubNet(const CNetAddr &addr);

        bool Match(const CNetAddr &addr) const;

        std::string ToString() const;
        bool IsValid() const;

        friend bool operator==(const CSubNet& a, const CSubNet& b);
        friend bool operator!=(const CSubNet& a, const CSubNet& b);
        friend bool operator<(const CSubNet& a, const CSubNet& b);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(network);
            READWRITE(FLATDATA(netmask));
            READWRITE(FLATDATA(valid));
        }
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
    protected:
        unsigned short port; // host order

    public:
        CService();
        CService(const CNetAddr& ip, unsigned short port);
        CService(const struct in_addr& ipv4Addr, unsigned short port);
        CService(const struct sockaddr_in& addr);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        bool GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const;
        bool SetSockAddr(const struct sockaddr* paddr);
        friend bool operator==(const CService& a, const CService& b);
        friend bool operator!=(const CService& a, const CService& b);
        friend bool operator<(const CService& a, const CService& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString(bool fUseGetnameinfo = true) const;
        std::string ToStringPort() const;
        std::string ToStringIPPort(bool fUseGetnameinfo = true) const;

        CService(const struct in6_addr& ipv6Addr, unsigned short port);
        CService(const struct sockaddr_in6& addr);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            // Serialize the CNetAddr portion (handles IPv4/IPv6 and Tor v3)
            // For legacy wire format, we serialize as 16-byte IPv6 address.
            // Tor v3 addresses are serialized as 16-byte OnionCat prefix + first 10 bytes
            // of the public key. This is lossy (Tor v3 requires 32 bytes) but maintains
            // backward compatibility with peers.dat and network messages from older nodes.
            //
            // NOTE: We intentionally do NOT read extra bytes based on OnionCat prefix
            // detection, because legacy Tor v2 addresses also used this prefix but only
            // occupy 16 bytes. Reading extra bytes would corrupt the deserialization
            // stream when processing old data.
            unsigned char ip_legacy[16];

            if (!ser_action.ForRead()) {
                if (m_net == NET_ONION) {
                    // Serialize Tor v3: OnionCat prefix + first 10 bytes of public key
                    // This is lossy but backward compatible (only 16 bytes written)
                    static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};
                    memcpy(ip_legacy, pchOnionCat, sizeof(pchOnionCat));
                    memcpy(ip_legacy + sizeof(pchOnionCat), m_addr, 10);
                } else {
                    memcpy(ip_legacy, m_addr, 16);
                }
            }
            READWRITE(FLATDATA(ip_legacy));
            if (ser_action.ForRead()) {
                // Copy the 16-byte legacy address and determine network type.
                // OnionCat prefix addresses (both legacy Tor v2 and truncated Tor v3)
                // are treated as IPv6 for backward compatibility. Full Tor v3 support
                // requires a versioned serialization format (e.g., ADDRv2/BIP 155).
                memcpy(m_addr, ip_legacy, 16);
                memset(m_addr + 16, 0, sizeof(m_addr) - 16); // Clear remaining bytes
                static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                if (memcmp(m_addr, pchIPv4, sizeof(pchIPv4)) == 0) {
                    m_net = NET_IPV4;
                } else {
                    m_net = NET_IPV6;
                }
            }
            unsigned short portN = htons(port);
            READWRITE(FLATDATA(portN));
            if (ser_action.ForRead())
                 port = ntohs(portN);
        }
};

#endif // BITCOIN_NETADDRESS_H
