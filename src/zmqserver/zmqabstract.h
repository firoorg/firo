// Copyright (c) 2018 Tadhg Riordan, Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQABSTRACT_H
#define BITCOIN_ZMQ_ZMQABSTRACT_H

#include "zmqconfig.h"

class CBlockIndex;
class CZMQAbstract;

typedef CZMQAbstract* (*CZMQFactory)();

class CZMQAbstract
{
public:
    enum KeyType {
        Server,
        Client
    };

    static const bool DEV_AUTH = true;

    CZMQAbstract() : psocket(0),pcontext(0) { }
    virtual ~CZMQAbstract();


    template <typename T>
    static CZMQAbstract* Create()
    {
        return new T();
    }

    std::string GetType() const { return type; }
    void SetType(const std::string &t) { type = t; }
    std::string GetPort() const { return port; }
    void SetPort(const std::string &p) { port = p; }
    std::string GetAddress() const { return address; }
    void SetAddress(const std::string &a) { address = a; }
    // address + port combination
    std::string GetAuthority() const { return authority; }
    void SetAuthority(const std::string &a) { authority = a; }

    /* static certificate handling */
    static vector<string> ReadCert(KeyType type);
    static bool WriteCert(string publicKey, string privateKey, KeyType type, bool reset=false);
    static bool CreateCerts(bool reset=false);
    static std::string GetAuthType(KeyType type);

    /* define pure virtual functions (implemented by every derived instance) */ 
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;

    /* virtual functions to be implemented by publisher (defined here to allow access by notifiers) */ 
    virtual bool NotifyBlock(const CBlockIndex *pindex);
    virtual bool NotifyTransaction(const CTransaction &transaction);
    virtual bool NotifyConnections();
    virtual bool NotifyStatus();
    virtual bool NotifyAPIStatus();
    virtual bool NotifyZnodeUpdate(CZnode &znode);
    virtual bool NotifyMintStatusUpdate(std::string update);
    virtual bool NotifySettingsUpdate(std::string update);

    /* send message with or without topic value. */
    bool SendMessage();

private:
    /* Internal function to send multipart message - 1 to N messages */
    bool SendMultipart(const void* data, size_t size, ...);

protected:
    void *psocket;
    void *pcontext;
    std::string type;
    std::string address;
    std::string port;
    std::string authority;
    std::string topic;
    std::string message;
    uint32_t nSequence; //!< upcounting per message sequence number
};

#endif // BITCOIN_ZMQ_ZMQABSTRACT_H
