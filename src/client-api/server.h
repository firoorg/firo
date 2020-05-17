#include "univalue.h"

using namespace std;

#ifndef ZCOIN_API_SERVER_H
#define ZCOIN_API_SERVER_H



class CAPICommand;

bool IsAPIRunning();
bool StartAPI();
void InterruptAPI();
void StopAPI();
void SetAPIWarmupStatus(const std::string& newStatus);
void SetAPIWarmupFinished();
bool APIIsInWarmup(std::string *outStatus);
bool APIIsInWarmup();

enum Type {
   None,
   Initial,
   Get,
   Create,
   Update,
   Delete 
};

class APIJSONRequest
{
public:
    char* raw;

    Type type;
    std::string collection;
    UniValue data;
    UniValue auth;

    APIJSONRequest() {}
    void parse(const UniValue& valRequest);
    void parseType(std::string typeRequest);
};

typedef UniValue(*apifn_type)(Type type, const UniValue& data, const UniValue& auth, bool fHelp);

class CAPICommand
{
public:
    std::string category;   // command category
    std::string collection; // function name
    apifn_type actor;       // pointer to function
    bool authPort;          // command can only be called through authenticated port
    bool authPassphrase;    // command requires unlocking before being ran.
    bool warmupOk;          // command can be executed during program warmup.
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
    UniValue execute(APIJSONRequest request, const bool authPort) const;

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

#endif // ZCOIN_APIAPI_SERVER_H
