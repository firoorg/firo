#include <string>
#include <univalue.h>
#include <map>
#include <vector>

#ifndef BITCOIN_API_SERVER_H
#define BITCOIN_API_SERVER_H

typedef UniValue(*apifn_type)(const UniValue& params, bool fHelp);

class CAPICommand;

bool IsAPIRunning();

class CAPICommand
{
public:
    std::string category;
    std::string name;
    apifn_type actor;
    // bool okSafeMode;
};

class CAPITable
{
private:
    std::map<std::string, const CAPICommand*> mapCommands;
public:
    CAPITable();
    const CAPICommand* operator[](const std::string& name) const;
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
     * Appends a CAPICommand to the dispatch table.
     * Returns false if API server is already running (dump concurrency protection).
     * Commands cannot be overwritten (returns false).
     */
    bool appendCommand(const std::string& name, const CAPICommand* pcmd); // TODO
};

extern CAPITable tableAPI;

#endif // BITCOIN_APIAPI_SERVER_H
