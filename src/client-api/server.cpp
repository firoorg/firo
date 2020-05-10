#include "client-api/server.h"
#include "client-api/protocol.h"
#include "util.h"
#include "main.h"
#include "init.h"
#include "wallet/wallet.h"
#include "univalue.h"
#include <boost/signals2/signal.hpp>

static bool fAPIRunning = false;
static bool fAPIInWarmup = true;
static bool fAPIIsOpen = true;
static std::string apiWarmupStatus("API server started");
static CCriticalSection cs_apiWarmup;

static struct CAPISignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CAPICommand&)> PreCommand;
    boost::signals2::signal<void (const CAPICommand&)> PostCommand;
} g_apiSignals;

bool IsAPIRunning() {
    return fAPIRunning;
}

bool StartAPI()
{
    LogPrintf("API: Starting\n");
    fAPIRunning = true;
    g_apiSignals.Started();
    return true;
}

void InterruptAPI()
{
    LogPrintf("API: Interrupting\n");
    // Interrupt e.g. running longpolls
    fAPIRunning = false;
}

void StopAPI()
{
    LogPrintf("API: Stopping\n");
    g_apiSignals.Stopped();
}

void SetAPIWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_apiWarmup);
    apiWarmupStatus = newStatus;
}

void SetAPIWarmupFinished()
{
    LOCK(cs_apiWarmup);
    fAPIInWarmup = false;
}

bool APIIsInWarmup()
{
    LOCK(cs_apiWarmup);
    return fAPIInWarmup;
}

bool APIIsOpen()
{
    return fAPIIsOpen;
}

void SetAPIOpenStatus(const bool& newStatus)
{
    fAPIIsOpen = newStatus;
}

CAPITable::CAPITable(){}

const CAPICommand *CAPITable::operator[](const std::string &name) const
{
    std::map<std::string, const CAPICommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool CAPITable::appendCommand(const std::string& name, const CAPICommand* pcmd)
{
    if (IsAPIRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CAPICommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

void APIJSONRequest::parseType(std::string typeRequest)
{
    if(typeRequest=="none"){
        type = None;
    }
    else if(typeRequest=="initial"){
        type = Initial;
    }
    else if(typeRequest=="get"){
        type = Get;
    }
    else if(typeRequest=="create"){
        type = Create;
    }
    else if(typeRequest=="update"){
        type = Update;
    }
    else if(typeRequest=="delete"){
        type = Delete;
    }
    else {
       throw JSONAPIError(API_INVALID_REQUEST, "Invalid Type request string"); 
    }
}

void APIJSONRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONAPIError(API_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse type
    UniValue valType = find_value(request, "type");
    if (valType.isNull()){
        type = None;
    }
    else {
        if (!valType.isStr())
            throw JSONAPIError(API_INVALID_REQUEST, "type must be a string");
        parseType(valType.get_str());
    }

    // Parse collection
    UniValue valCollection = find_value(request, "collection");
    if (valCollection.isNull())
        throw JSONAPIError(API_INVALID_REQUEST, "Missing collection in JSON request");
    if (!valCollection.isStr())
        throw JSONAPIError(API_INVALID_REQUEST, "collection must be a string");
    collection = valCollection.get_str();

    // Parse auth
    UniValue valAuth = find_value(request, "auth");
    if (valAuth.isObject()){
        auth = valAuth.get_obj();
    }
    else if (valAuth.isNull())
        auth = UniValue(UniValue::VARR);
    else
        throw JSONAPIError(API_INVALID_REQUEST, "auth must be an object");

    // Parse data
    UniValue valData = find_value(request, "data");
    if (valData.isObject()){
        data = valData.get_obj();
    }
    else if (valData.isNull())
        data = UniValue(UniValue::VARR);
    else
        throw JSONAPIError(API_INVALID_REQUEST, "data must be an object");


}

UniValue CAPITable::execute(APIJSONRequest request, const bool authPort) const
{
    SetAPIOpenStatus(false);
    if(request.collection!="apiStatus")
        LogPrintf("executing method %s\n",  request.collection);
    
    const CAPICommand *pcmd = tableAPI[request.collection];
    if (!pcmd){
        throw JSONAPIError(API_METHOD_NOT_FOUND, "Method \"" + request.collection + "\" not found");
    }

    // Block if in safe mode
    string strWarning = GetWarnings("api");
    if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) && request.collection != "apiStatus")
        throw JSONAPIError(API_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    // Return if in warmup
    { 
        LOCK(cs_apiWarmup);
        if (fAPIInWarmup && !pcmd->warmupOk)
            throw JSONAPIError(API_IN_WARMUP, apiWarmupStatus);
    }

    // If on open port, fail if trying to execute an authenticated method.
    if(!authPort && pcmd->authPort){
        throw JSONAPIError(API_NOT_AUTHENTICATED, "Not authenticated for this method");
    }

    const CAPICommand *walletlock = tableAPI["lockWallet"];
    g_apiSignals.PreCommand (*pcmd);
    try
    {
        // If this method requires passphrase, lock and unlock the wallet accordingly
        if(pcmd->authPassphrase && (pwalletMain && pwalletMain->IsCrypted())){
            if(request.auth.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Missing auth field");
            }

            // execute wallet unlock, call method, relock following call. 
            const CAPICommand *walletunlock = tableAPI["unlockWallet"];
            UniValue lock = walletunlock->actor(request.type, NullUniValue, request.auth, false);
            if(lock.isNull()){
                throw JSONAPIError(API_MISC_ERROR, "wallet could not be unlocked.");
            }
            UniValue result = pcmd->actor(request.type, request.data, NullUniValue, false);
            walletlock->actor(request.type, NullUniValue, NullUniValue, false);
            return result;

        }
        return pcmd->actor(request.type, request.data, request.auth, false);
    }
    catch (const std::exception& e)
    {
        //walletlock->actor(request.type, NullUniValue, NullUniValue, false); //ensure to relock should an error occur
        throw JSONAPIError(API_MISC_ERROR, e.what());
    }

    g_apiSignals.PostCommand(*pcmd);
    SetAPIOpenStatus(true);
}

CAPITable tableAPI;
