// Copyright (c) 2020-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_I2P_H
#define BITCOIN_I2P_H

#include "compat.h"
#include "netaddress.h"
#include "netbase.h"
#include "sync.h"
#include "threadinterrupt.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/filesystem/path.hpp>
#include <boost/optional.hpp>

namespace i2p {

/**
 * Binary data.
 */
using Binary = std::vector<uint8_t>;

/**
 * I2P SAM 3.1 uses port 0 as the standard port.
 */
static constexpr uint16_t I2P_SAM31_PORT = 0;

/**
 * An established connection with another peer.
 */
struct Connection {
    /** Connected socket. */
    SOCKET sock;

    /** Our I2P address. */
    CService me;

    /** The peer's I2P address. */
    CService peer;

    Connection() : sock(INVALID_SOCKET) {}
};

namespace sam {

/**
 * The maximum size of an incoming message from the I2P SAM proxy (in bytes).
 * Used to avoid a runaway proxy from sending us an "unlimited" amount of data without a terminator.
 * The longest known message is ~1400 bytes, so this is high enough not to be triggered during
 * normal operation, yet low enough to avoid a malicious proxy from filling our memory.
 */
static constexpr size_t MAX_MSG_SIZE = 65536;

/**
 * Maximum time to wait for I2P operations.
 */
static constexpr int64_t MAX_WAIT_FOR_IO = 10000; // 10 seconds in milliseconds

/**
 * I2P SAM session.
 */
class Session
{
public:
    /**
     * Construct a session. This will not initiate any IO, the session will be lazily created
     * later when first used.
     * @param[in] private_key_file Path to a private key file. If the file does not exist then the
     * private key will be generated and saved into the file.
     * @param[in] control_host Location of the SAM proxy.
     * @param[in,out] interrupt If this is signaled then all operations are canceled as soon as
     * possible and executing methods throw an exception.
     */
    Session(const boost::filesystem::path& private_key_file,
            const CService& control_host,
            CThreadInterrupt* interrupt);

    /**
     * Construct a transient session which will generate its own I2P private key
     * rather than read the one from disk (it will not be saved on disk either and
     * will be lost once this object is destroyed). This will not initiate any IO,
     * the session will be lazily created later when first used.
     * @param[in] control_host Location of the SAM proxy.
     * @param[in,out] interrupt If this is signaled then all operations are canceled as soon as
     * possible and executing methods throw an exception.
     */
    Session(const CService& control_host, CThreadInterrupt* interrupt);

    /**
     * Destroy the session, closing the internally used sockets. The sockets that have been
     * returned by `Accept()` or `Connect()` will not be closed, but they will be closed by
     * the SAM proxy because the session is destroyed. So they will return an error next time
     * we try to read or write to them.
     */
    ~Session();

    /**
     * Start listening for an incoming connection.
     * @param[out] conn Upon successful completion the `sock` and `me` members will be set
     * to the listening socket and address.
     * @return true on success
     */
    bool Listen(Connection& conn);

    /**
     * Wait for and accept a new incoming connection.
     * @param[in,out] conn The `sock` member is used for waiting and accepting. Upon successful
     * completion the `peer` member will be set to the address of the incoming peer.
     * @return true on success
     */
    bool Accept(Connection& conn);

    /**
     * Connect to an I2P peer.
     * @param[in] to Peer to connect to.
     * @param[out] conn Established connection. Only set if `true` is returned.
     * @param[out] proxy_error If an error occurs due to proxy or general network failure, then
     * this is set to `true`. If an error occurs due to unreachable peer (likely peer is down), then
     * it is set to `false`. Only set if `false` is returned.
     * @return true on success
     */
    bool Connect(const CService& to, Connection& conn, bool& proxy_error);

private:
    /**
     * A reply from the SAM proxy.
     */
    struct Reply {
        /**
         * Full, unparsed reply.
         */
        std::string full;

        /**
         * Request, used for detailed error reporting.
         */
        std::string request;

        /**
         * A map of keywords from the parsed reply.
         * For example, if the reply is "A=X B C=YZ", then the map will be
         * keys["A"] == "X"
         * keys["B"] == (empty boost::optional)
         * keys["C"] == "YZ"
         */
        std::unordered_map<std::string, boost::optional<std::string>> keys;

        /**
         * Get the value of a given key.
         * For example if the reply is "A=X B" then:
         * Get("A") -> "X"
         * Get("B") -> throws
         * Get("C") -> throws
         * @param[in] key Key whose value to retrieve
         * @returns the key's value
         * @throws std::runtime_error if the key is not present or if it has no value
         */
        std::string Get(const std::string& key) const;
    };

    /**
     * Send request and get a reply from the SAM proxy.
     * @param[in] sock A socket that is connected to the SAM proxy.
     * @param[in] request Raw request to send, a newline terminator is appended to it.
     * @param[in] check_result_ok If true then after receiving the reply a check is made
     * whether it contains "RESULT=OK" and an exception is thrown if it does not.
     * @throws std::runtime_error if an error occurs
     */
    Reply SendRequestAndGetReply(SOCKET sock,
                                 const std::string& request,
                                 bool check_result_ok = true) const;

    /**
     * Open a new connection to the SAM proxy.
     * @return a connected socket
     * @throws std::runtime_error if an error occurs
     */
    SOCKET Hello() const;

    /**
     * Check the control socket for errors and possibly disconnect.
     */
    void CheckControlSock();

    /**
     * Generate a new destination with the SAM proxy and set `m_private_key` to it.
     * @param[in] sock Socket to use for talking to the SAM proxy.
     * @throws std::runtime_error if an error occurs
     */
    void DestGenerate(SOCKET sock);

    /**
     * Generate a new destination with the SAM proxy, set `m_private_key` to it and save
     * it on disk to `m_private_key_file`.
     * @param[in] sock Socket to use for talking to the SAM proxy.
     * @throws std::runtime_error if an error occurs
     */
    void GenerateAndSavePrivateKey(SOCKET sock);

    /**
     * Derive own destination from `m_private_key`.
     * @see https://geti2p.net/spec/common-structures#destination
     * @return an I2P destination
     */
    Binary MyDestination() const;

    /**
     * Create the session if not already created. Reads the private key file and connects to the
     * SAM proxy.
     * @throws std::runtime_error if an error occurs
     */
    void CreateIfNotCreatedAlready();

    /**
     * Open a new connection to the SAM proxy and issue "STREAM ACCEPT" request using the existing
     * session id.
     * @return the idle socket that is waiting for a peer to connect to us
     * @throws std::runtime_error if an error occurs
     */
    SOCKET StreamAccept();

    /**
     * Destroy the session, closing the internally used sockets.
     */
    void Disconnect();

    /**
     * Receive data from socket until a terminator character is found.
     * @param[in] sock Socket to receive from.
     * @param[in] terminator The character to look for.
     * @param[in] timeout_ms Timeout in milliseconds.
     * @param[in] max_size Maximum number of bytes to receive.
     * @return Received data, not including the terminator.
     * @throws std::runtime_error if an error occurs
     */
    std::string RecvUntilTerminator(SOCKET sock, char terminator, int64_t timeout_ms, size_t max_size) const;

    /**
     * Send data to socket.
     * @param[in] sock Socket to send to.
     * @param[in] data Data to send.
     * @param[in] timeout_ms Timeout in milliseconds.
     * @throws std::runtime_error if an error occurs
     */
    void SendComplete(SOCKET sock, const std::string& data, int64_t timeout_ms) const;

    /**
     * Wait for socket to be ready for reading or writing.
     * @param[in] sock Socket to wait on.
     * @param[in] timeout_ms Timeout in milliseconds.
     * @param[in] for_recv If true, wait for read readiness; otherwise wait for write readiness.
     * @return true if socket is ready, false on timeout or error.
     */
    bool Wait(SOCKET sock, int64_t timeout_ms, bool for_recv) const;

    /**
     * Check if socket is connected.
     * @param[in] sock Socket to check.
     * @param[out] errmsg Error message if not connected.
     * @return true if connected.
     */
    bool IsConnected(SOCKET sock, std::string& errmsg) const;

    /**
     * The name of the file where this peer's private key is stored (in binary).
     */
    const boost::filesystem::path m_private_key_file;

    /**
     * The SAM control service address.
     */
    const CService m_control_host;

    /**
     * Cease network activity when this is signaled.
     */
    CThreadInterrupt* const m_interrupt;

    /**
     * Mutex protecting the members that can be concurrently accessed.
     */
    mutable CCriticalSection m_mutex;

    /**
     * The private key of this peer.
     * @see The reply to the "DEST GENERATE" command in https://geti2p.net/en/docs/api/samv3
     */
    Binary m_private_key GUARDED_BY(m_mutex);

    /**
     * SAM control socket.
     * Used to connect to the I2P SAM service and create a session
     * ("SESSION CREATE"). With the established session id we later open
     * other connections to the SAM service to accept incoming I2P
     * connections and make outgoing ones.
     * If not connected then this is INVALID_SOCKET.
     * See https://geti2p.net/en/docs/api/samv3
     */
    SOCKET m_control_sock GUARDED_BY(m_mutex);

    /**
     * Our .b32.i2p address.
     * Derived from `m_private_key`.
     */
    CService m_my_addr GUARDED_BY(m_mutex);

    /**
     * SAM session id.
     */
    std::string m_session_id GUARDED_BY(m_mutex);

    /**
     * Whether this is a transient session (the I2P private key will not be
     * read or written to disk).
     */
    const bool m_transient;
};

} // namespace sam
} // namespace i2p

#endif // BITCOIN_I2P_H
