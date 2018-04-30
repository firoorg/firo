#include <string>
#include <univalue.h>
#include <map>
#include <vector>

#ifndef BITCOIN_ZMQAPI_SERVER_H
#define BITCOIN_ZMQAPI_SERVER_H

typedef UniValue(*zmqfn_type)(const UniValue& params, bool fHelp);

class CZMQCommand;

bool IsZMQRunning();

class CZMQCommand
{
public:
    std::string category;
    std::string name;
    zmqfn_type actor;
    // bool okSafeMode;
};

class CZMQTable
{
private:
    std::map<std::string, const CZMQCommand*> mapCommands;
public:
    CZMQTable();
    const CZMQCommand* operator[](const std::string& name) const;
    std::string help(const std::string& name) const; // TODO

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   UniValue Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const std::string &method, const UniValue &params) const;

    /**
    * Returns a list of registered commands
    * @returns List of registered commands.
    */
    std::vector<std::string> listCommands() const; // TODO


    /**
     * Appends a CRPCCommand to the dispatch table.
     * Returns false if RPC server is already running (dump concurrency protection).
     * Commands cannot be overwritten (returns false).
     */
    bool appendCommand(const std::string& name, const CZMQCommand* pcmd); // TODO
};

extern CZMQTable tableZMQ;

#endif // BITCOIN_ZMQAPI_SERVER_H
