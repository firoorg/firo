// Copyright (c) 2020-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "i2p.h"

#include "compat.h"
#include "crypto/sha256.h"
#include "netaddress.h"
#include "netbase.h"
#include "random.h"
#include "support/cleanse.h"
#include "sync.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/string.hpp>

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#endif

namespace i2p {

/**
 * Swap Standard Base64 <-> I2P Base64.
 * Standard Base64 uses `+` and `/` as last two characters of its alphabet.
 * I2P Base64 uses `-` and `~` respectively.
 * So it is easy to detect in which one is the input and convert to the other.
 * @param[in] from Input to convert.
 * @return converted `from`
 */
static std::string SwapBase64(const std::string& from)
{
    std::string to;
    to.resize(from.size());
    for (size_t i = 0; i < from.size(); ++i) {
        switch (from[i]) {
        case '-':
            to[i] = '+';
            break;
        case '~':
            to[i] = '/';
            break;
        case '+':
            to[i] = '-';
            break;
        case '/':
            to[i] = '~';
            break;
        default:
            to[i] = from[i];
            break;
        }
    }
    return to;
}

/**
 * Decode an I2P-style Base64 string.
 * @param[in] i2p_b64 I2P-style Base64 string.
 * @param[in] is_sensitive If true, the input contains sensitive data (like private keys)
 *                         and should not be included in error messages.
 * @return decoded `i2p_b64`
 * @throw std::runtime_error if decoding fails
 */
static Binary DecodeI2PBase64(const std::string& i2p_b64, bool is_sensitive = false)
{
    const std::string& std_b64 = SwapBase64(i2p_b64);
    bool invalid = false;
    std::vector<unsigned char> decoded = DecodeBase64(std_b64.c_str(), &invalid);
    if (invalid) {
        if (is_sensitive) {
            // Don't include the actual value in the error message to prevent private key leakage
            throw std::runtime_error("Cannot decode Base64 (sensitive data redacted)");
        } else {
            throw std::runtime_error(strprintf("Cannot decode Base64: \"%s\"", i2p_b64));
        }
    }
    return decoded;
}

/**
 * Derive the .b32.i2p address of an I2P destination (binary).
 * @param[in] dest I2P destination.
 * @return the address that corresponds to `dest`
 * @throw std::runtime_error if conversion fails
 */
static CNetAddr DestBinToAddr(const Binary& dest)
{
    CSHA256 hasher;
    hasher.Write(dest.data(), dest.size());
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);

    CNetAddr addr;
    const std::string addr_str = EncodeBase32(hash, hash + CSHA256::OUTPUT_SIZE, false) + ".b32.i2p";
    if (!addr.SetSpecial(addr_str)) {
        throw std::runtime_error(strprintf("Cannot parse I2P address: \"%s\"", addr_str));
    }

    return addr;
}

/**
 * Derive the .b32.i2p address of an I2P destination (I2P-style Base64).
 * @param[in] dest I2P destination.
 * @return the address that corresponds to `dest`
 * @throw std::runtime_error if conversion fails
 */
static CNetAddr DestB64ToAddr(const std::string& dest)
{
    const Binary& decoded = DecodeI2PBase64(dest);
    return DestBinToAddr(decoded);
}

/**
 * Check if a string is safe to use in SAM protocol commands.
 * Rejects strings containing control characters (including newlines) that could
 * be used to inject additional SAM commands.
 * @param[in] s The string to validate.
 * @return true if safe, false if contains dangerous characters.
 */
static bool IsSafeSAMValue(const std::string& s)
{
    for (char c : s) {
        // Reject control characters (0x00-0x1F) and DEL (0x7F)
        // This prevents newline injection attacks
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) {
            return false;
        }
        // Also reject spaces as they delimit SAM protocol tokens
        if (c == ' ') {
            return false;
        }
    }
    return true;
}

namespace sam {

Session::Session(const boost::filesystem::path& private_key_file,
                 const CService& control_host,
                 CThreadInterrupt* interrupt)
    : m_private_key_file(private_key_file),
      m_control_host(control_host),
      m_interrupt(interrupt),
      m_control_sock(INVALID_SOCKET),
      m_transient(false)
{
}

Session::Session(const CService& control_host, CThreadInterrupt* interrupt)
    : m_control_host(control_host),
      m_interrupt(interrupt),
      m_control_sock(INVALID_SOCKET),
      m_transient(true)
{
}

Session::~Session()
{
    LOCK(m_mutex);
    Disconnect();
    
    // Securely clear the private key from memory
    if (!m_private_key.empty()) {
        memory_cleanse(m_private_key.data(), m_private_key.size());
        m_private_key.clear();
    }
}

bool Session::Listen(Connection& conn)
{
    try {
        LOCK(m_mutex);
        CreateIfNotCreatedAlready();
        conn.me = m_my_addr;
        conn.sock = StreamAccept();
        return true;
    } catch (const std::runtime_error& e) {
        LogPrintf("I2P: Couldn't listen: %s\n", e.what());
        CheckControlSock();
    }
    return false;
}

bool Session::Accept(Connection& conn)
{
    AssertLockNotHeld(m_mutex);

    std::string errmsg;
    bool disconnect = false;

    while (!(*m_interrupt)) {
        if (!Wait(conn.sock, MAX_WAIT_FOR_IO, true)) {
            // Timeout, no incoming connections or errors within MAX_WAIT_FOR_IO.
            continue;
        }

        std::string peer_dest;
        try {
            peer_dest = RecvUntilTerminator(conn.sock, '\n', MAX_WAIT_FOR_IO, MAX_MSG_SIZE);
        } catch (const std::runtime_error& e) {
            errmsg = e.what();
            break;
        }

        CNetAddr peer_addr;
        try {
            peer_addr = DestB64ToAddr(peer_dest);
        } catch (const std::runtime_error& e) {
            // The I2P router is expected to send the Base64 of the connecting peer,
            // but it may happen that something like this is sent instead:
            // STREAM STATUS RESULT=I2P_ERROR MESSAGE="Session was closed"
            // In that case consider the session damaged and close it right away,
            // even if the control socket is alive.
            if (peer_dest.find("RESULT=I2P_ERROR") != std::string::npos) {
                errmsg = strprintf("unexpected reply that hints the session is unusable: %s", peer_dest);
                disconnect = true;
            } else {
                errmsg = e.what();
            }
            break;
        }

        conn.peer = CService(peer_addr, I2P_SAM31_PORT);

        return true;
    }

    if (*m_interrupt) {
        LogPrint("i2p", "I2P: Accept was interrupted\n");
    } else {
        LogPrint("i2p", "I2P: Error accepting%s: %s\n", disconnect ? " (will close the session)" : "", errmsg);
    }
    if (disconnect) {
        LOCK(m_mutex);
        Disconnect();
    } else {
        CheckControlSock();
    }
    return false;
}

bool Session::Connect(const CService& to, Connection& conn, bool& proxy_error)
{
    // Refuse connecting to arbitrary ports. We don't specify any destination port to the SAM proxy
    // when connecting (SAM 3.1 does not use ports) and it forces/defaults it to I2P_SAM31_PORT.
    if (to.GetPort() != I2P_SAM31_PORT) {
        LogPrint("i2p", "I2P: Error connecting to %s, connection refused due to arbitrary port %u\n", to.ToString(), to.GetPort());
        proxy_error = false;
        return false;
    }

    proxy_error = true;

    std::string session_id;
    SOCKET sock = INVALID_SOCKET;
    conn.peer = to;

    try {
        {
            LOCK(m_mutex);
            CreateIfNotCreatedAlready();
            session_id = m_session_id;
            conn.me = m_my_addr;
            sock = Hello();
        }

        const Reply& lookup_reply =
            SendRequestAndGetReply(sock, strprintf("NAMING LOOKUP NAME=%s", to.ToStringIP()));

        const std::string& dest = lookup_reply.Get("VALUE");
        
        // Validate the destination to prevent SAM command injection attacks
        if (!IsSafeSAMValue(dest)) {
            throw std::runtime_error("SAM proxy returned invalid destination (contains control characters)");
        }

        const Reply& connect_reply = SendRequestAndGetReply(
            sock, strprintf("STREAM CONNECT ID=%s DESTINATION=%s SILENT=false", session_id, dest),
            false);

        const std::string& result = connect_reply.Get("RESULT");

        if (result == "OK") {
            conn.sock = sock;
            return true;
        }

        if (result == "INVALID_ID") {
            LOCK(m_mutex);
            Disconnect();
            throw std::runtime_error("Invalid session id");
        }

        if (result == "CANT_REACH_PEER" || result == "TIMEOUT") {
            proxy_error = false;
        }

        throw std::runtime_error(strprintf("\"%s\"", connect_reply.full));
    } catch (const std::runtime_error& e) {
        LogPrint("i2p", "I2P: Error connecting to %s: %s\n", to.ToString(), e.what());
        CheckControlSock();
        if (sock != INVALID_SOCKET) {
            CloseSocket(sock);
        }
        return false;
    }
}

// Private methods

std::string Session::Reply::Get(const std::string& key) const
{
    auto pos = keys.find(key);
    if (pos == keys.end() || !pos->second) {
        throw std::runtime_error(
            strprintf("Missing %s= in the reply to \"%s\": \"%s\"", key, request, full));
    }
    return pos->second.get();
}

Session::Reply Session::SendRequestAndGetReply(SOCKET sock,
                                               const std::string& request,
                                               bool check_result_ok) const
{
    SendComplete(sock, request + "\n", MAX_WAIT_FOR_IO);

    Reply reply;

    // Don't log the full "SESSION CREATE ..." because it contains our private key.
    reply.request = (request.substr(0, 14) == "SESSION CREATE") ? "SESSION CREATE ..." : request;

    // It could take a few minutes for the I2P router to reply as it is querying the I2P network
    // (when doing name lookup, for example).
    static const int64_t recv_timeout = 3 * 60 * 1000; // 3 minutes

    reply.full = RecvUntilTerminator(sock, '\n', recv_timeout, MAX_MSG_SIZE);

    // Parse the reply
    std::vector<std::string> tokens;
    boost::split(tokens, reply.full, boost::is_any_of(" "));
    for (const auto& token : tokens) {
        size_t eq_pos = token.find('=');
        if (eq_pos != std::string::npos) {
            reply.keys[token.substr(0, eq_pos)] = token.substr(eq_pos + 1);
        } else {
            reply.keys[token] = boost::none;
        }
    }

    if (check_result_ok && reply.Get("RESULT") != "OK") {
        throw std::runtime_error(
            strprintf("Unexpected reply to \"%s\": \"%s\"", reply.request, reply.full));
    }

    return reply;
}

SOCKET Session::Hello() const
{
    SOCKET sock = INVALID_SOCKET;

    // Connect to the SAM proxy
    if (!ConnectSocketDirectly(m_control_host, sock, nConnectTimeout)) {
        throw std::runtime_error(strprintf("Cannot connect to %s", m_control_host.ToString()));
    }

    try {
        SendRequestAndGetReply(sock, "HELLO VERSION MIN=3.1 MAX=3.1");
    } catch (...) {
        CloseSocket(sock);
        throw;
    }

    return sock;
}

void Session::CheckControlSock()
{
    LOCK(m_mutex);

    std::string errmsg;
    if (m_control_sock != INVALID_SOCKET && !IsConnected(m_control_sock, errmsg)) {
        LogPrint("i2p", "I2P: Control socket error: %s\n", errmsg);
        Disconnect();
    }
}

void Session::DestGenerate(SOCKET sock)
{
    // https://geti2p.net/spec/common-structures#key-certificates
    // "7" or "EdDSA_SHA512_Ed25519" - "Recent Router Identities and Destinations".
    // Use "7" because i2pd <2.24.0 does not recognize the textual form.
    // If SIGNATURE_TYPE is not specified, then the default one is DSA_SHA1.
    const Reply& reply = SendRequestAndGetReply(sock, "DEST GENERATE SIGNATURE_TYPE=7", false);

    // Mark as sensitive to prevent private key from being logged in case of decode failure
    m_private_key = DecodeI2PBase64(reply.Get("PRIV"), true /* is_sensitive */);
}

void Session::GenerateAndSavePrivateKey(SOCKET sock)
{
    DestGenerate(sock);

    // Save the private key to disk with restrictive permissions
    // The private key file must be readable only by the owner (0600)
#ifndef WIN32
    // Create file with restrictive permissions on Unix-like systems
    int fd = open(m_private_key_file.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        throw std::runtime_error(
            strprintf("Cannot save I2P private key to %s: %s", m_private_key_file.string(), strerror(errno)));
    }
    ssize_t written = write(fd, m_private_key.data(), m_private_key.size());
    close(fd);
    if (written != static_cast<ssize_t>(m_private_key.size())) {
        throw std::runtime_error(
            strprintf("Failed to write I2P private key to %s", m_private_key_file.string()));
    }
#else
    // On Windows, use boost::filesystem with default permissions
    // Windows has different permission model; the data directory is already protected
    boost::filesystem::ofstream file(m_private_key_file, std::ios::binary | std::ios::out);
    if (!file) {
        throw std::runtime_error(
            strprintf("Cannot save I2P private key to %s", m_private_key_file.string()));
    }
    file.write(reinterpret_cast<const char*>(m_private_key.data()), m_private_key.size());
    file.close();
#endif
}

Binary Session::MyDestination() const
{
    // From https://geti2p.net/spec/common-structures#destination:
    // "They are 387 bytes plus the certificate length specified at bytes 385-386, which may be
    // non-zero"
    static constexpr size_t DEST_LEN_BASE = 387;
    static constexpr size_t CERT_LEN_POS = 385;

    if (m_private_key.size() < CERT_LEN_POS + 2) {
        throw std::runtime_error(strprintf("The private key is too short (%d < %d)",
                                           m_private_key.size(),
                                           CERT_LEN_POS + 2));
    }

    // Read certificate length in big-endian format
    const uint16_t cert_len = (static_cast<uint16_t>(m_private_key[CERT_LEN_POS]) << 8) | 
                               static_cast<uint16_t>(m_private_key[CERT_LEN_POS + 1]);

    const size_t dest_len = DEST_LEN_BASE + cert_len;

    if (dest_len > m_private_key.size()) {
        throw std::runtime_error(strprintf("Certificate length (%d) designates that the private key should "
                                           "be %d bytes, but it is only %d bytes",
                                           cert_len,
                                           dest_len,
                                           m_private_key.size()));
    }

    return Binary(m_private_key.begin(), m_private_key.begin() + dest_len);
}

void Session::CreateIfNotCreatedAlready()
{
    std::string errmsg;
    if (m_control_sock != INVALID_SOCKET && IsConnected(m_control_sock, errmsg)) {
        return;
    }

    const char* session_type = m_transient ? "transient" : "persistent";
    const std::string session_id = GetRandHash().GetHex().substr(0, 10);

    LogPrint("i2p", "I2P: Creating %s SAM session %s with %s\n", session_type, session_id, m_control_host.ToString());

    SOCKET sock = Hello();

    try {
        if (m_transient) {
            // The destination (private key) is generated upon session creation and returned
            // in the reply in DESTINATION=.
            const Reply& reply = SendRequestAndGetReply(
                sock,
                strprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=TRANSIENT SIGNATURE_TYPE=7 "
                          "i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1",
                          session_id));

            // Mark as sensitive to prevent private key from being logged in case of decode failure
            m_private_key = DecodeI2PBase64(reply.Get("DESTINATION"), true /* is_sensitive */);
        } else {
            // Read our persistent destination (private key) from disk or generate
            // one and save it to disk. Then use it when creating the session.
            if (boost::filesystem::exists(m_private_key_file)) {
                boost::filesystem::ifstream file(m_private_key_file, std::ios::binary | std::ios::in);
                if (file) {
                    m_private_key.clear();
                    m_private_key.insert(m_private_key.begin(),
                                        std::istreambuf_iterator<char>(file),
                                        std::istreambuf_iterator<char>());
                    file.close();
                    
                    // Validate the private key file is not empty or corrupted
                    if (m_private_key.empty()) {
                        LogPrintf("I2P: Private key file %s is empty, regenerating\n", m_private_key_file.string());
                        GenerateAndSavePrivateKey(sock);
                    }
                } else {
                    GenerateAndSavePrivateKey(sock);
                }
            } else {
                GenerateAndSavePrivateKey(sock);
            }

            const std::string& private_key_b64 = SwapBase64(EncodeBase64(m_private_key.data(), m_private_key.size()));

            SendRequestAndGetReply(sock,
                                   strprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s "
                                             "i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3",
                                             session_id,
                                             private_key_b64));
        }

        m_my_addr = CService(DestBinToAddr(MyDestination()), I2P_SAM31_PORT);
        m_session_id = session_id;
        m_control_sock = sock;

        LogPrintf("I2P: %s SAM session %s created, my address=%s\n",
            session_type,
            m_session_id,
            m_my_addr.ToString());
    } catch (...) {
        CloseSocket(sock);
        throw;
    }
}

SOCKET Session::StreamAccept()
{
    SOCKET sock = Hello();

    try {
        const Reply& reply = SendRequestAndGetReply(
            sock, strprintf("STREAM ACCEPT ID=%s SILENT=false", m_session_id), false);

        const std::string& result = reply.Get("RESULT");

        if (result == "OK") {
            return sock;
        }

        if (result == "INVALID_ID") {
            // If our session id is invalid, then force session re-creation on next usage.
            Disconnect();
        }

        throw std::runtime_error(strprintf("\"%s\"", reply.full));
    } catch (...) {
        CloseSocket(sock);
        throw;
    }
}

void Session::Disconnect()
{
    if (m_control_sock != INVALID_SOCKET) {
        if (m_session_id.empty()) {
            LogPrintf("I2P: Destroying incomplete SAM session\n");
        } else {
            LogPrintf("I2P: Destroying SAM session %s\n", m_session_id);
        }
        CloseSocket(m_control_sock);
        m_control_sock = INVALID_SOCKET;
    }
    m_session_id.clear();
}

std::string Session::RecvUntilTerminator(SOCKET sock, char terminator, int64_t timeout_ms, size_t max_size) const
{
    std::string result;
    result.reserve(256);

    int64_t start_time = GetTimeMillis();
    int64_t remaining_time = timeout_ms;

    while (result.size() < max_size) {
        if (*m_interrupt) {
            throw std::runtime_error("Interrupted");
        }

        if (!Wait(sock, std::min(remaining_time, (int64_t)1000), true)) {
            int64_t elapsed = GetTimeMillis() - start_time;
            remaining_time = timeout_ms - elapsed;
            if (remaining_time <= 0) {
                throw std::runtime_error("Timeout reading from socket");
            }
            continue;
        }

        char c;
        ssize_t ret = recv(sock, &c, 1, 0);
        if (ret == 0) {
            throw std::runtime_error("Connection closed");
        }
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) {
                continue;
            }
            throw std::runtime_error(strprintf("Error reading from socket: %s", NetworkErrorString(err)));
        }

        if (c == terminator) {
            return result;
        }
        result.push_back(c);
    }

    throw std::runtime_error(strprintf("Maximum message size (%d) exceeded", max_size));
}

void Session::SendComplete(SOCKET sock, const std::string& data, int64_t timeout_ms) const
{
    size_t sent = 0;
    int64_t start_time = GetTimeMillis();

    while (sent < data.size()) {
        if (*m_interrupt) {
            throw std::runtime_error("Interrupted");
        }

        int64_t elapsed = GetTimeMillis() - start_time;
        if (elapsed >= timeout_ms) {
            throw std::runtime_error("Timeout sending to socket");
        }

        if (!Wait(sock, std::min(timeout_ms - elapsed, (int64_t)1000), false)) {
            continue;
        }

        ssize_t ret = send(sock, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) {
                continue;
            }
            throw std::runtime_error(strprintf("Error sending to socket: %s", NetworkErrorString(err)));
        }
        sent += ret;
    }
}

bool Session::Wait(SOCKET sock, int64_t timeout_ms, bool for_recv) const
{
    if (!IsSelectableSocket(sock)) {
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    int ret;
    if (for_recv) {
        ret = select(sock + 1, &fdset, NULL, NULL, &timeout);
    } else {
        ret = select(sock + 1, NULL, &fdset, NULL, &timeout);
    }

    return ret > 0;
}

bool Session::IsConnected(SOCKET sock, std::string& errmsg) const
{
    if (sock == INVALID_SOCKET) {
        errmsg = "Socket is invalid";
        return false;
    }

    // Check for errors
    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len) != 0) {
        errmsg = strprintf("getsockopt failed: %s", NetworkErrorString(WSAGetLastError()));
        return false;
    }
    if (err != 0) {
        errmsg = NetworkErrorString(err);
        return false;
    }

    // Check if socket is still readable (not closed)
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int ret = select(sock + 1, &fdset, NULL, NULL, &timeout);
    if (ret < 0) {
        errmsg = strprintf("select failed: %s", NetworkErrorString(WSAGetLastError()));
        return false;
    }

    if (ret > 0 && FD_ISSET(sock, &fdset)) {
        // Socket is readable, check if there's an EOF
        char buf;
        ssize_t n = recv(sock, &buf, 1, MSG_PEEK);
        if (n == 0) {
            errmsg = "Connection closed by peer";
            return false;
        }
        if (n < 0) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                errmsg = strprintf("recv failed: %s", NetworkErrorString(err));
                return false;
            }
        }
    }

    return true;
}

// Helper function to connect socket directly (similar to ConnectSocketDirectly in netbase.cpp)
bool ConnectSocketDirectly(const CService& addrConnect, SOCKET& hSocketRet, int nTimeout)
{
    hSocketRet = INVALID_SOCKET;

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("I2P: Cannot connect to %s: unsupported network\n", addrConnect.ToString());
        return false;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET) {
        return false;
    }

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true)) {
        CloseSocket(hSocket);
        return false;
    }

    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR) {
        int nErr = WSAGetLastError();
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL) {
            struct timeval timeout;
            timeout.tv_sec = nTimeout / 1000;
            timeout.tv_usec = (nTimeout % 1000) * 1000;

            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);

            int nRet = select(hSocket + 1, NULL, &fdset, NULL, &timeout);
            if (nRet == 0) {
                LogPrint("i2p", "I2P: Connection to %s timeout\n", addrConnect.ToString());
                CloseSocket(hSocket);
                return false;
            }
            if (nRet == SOCKET_ERROR) {
                LogPrintf("I2P: select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }

            socklen_t nRetSize = sizeof(nRet);
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)&nRet, &nRetSize) == SOCKET_ERROR) {
                LogPrintf("I2P: getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }
            if (nRet != 0) {
                LogPrintf("I2P: connect() to %s failed after select(): %s\n", addrConnect.ToString(), NetworkErrorString(nRet));
                CloseSocket(hSocket);
                return false;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            LogPrintf("I2P: connect() to %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            CloseSocket(hSocket);
            return false;
        }
    }

    hSocketRet = hSocket;
    return true;
}

} // namespace sam
} // namespace i2p
