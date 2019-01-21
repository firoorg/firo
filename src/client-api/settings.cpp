// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "client-api/server.h"
#include "client-api/settings.h"
#include "client-api/protocol.h"
#include "util.h"
#include "univalue.h"
#include <fstream>
#include "utilstrencodings.h"
#include <boost/foreach.hpp>
#include <validationinterface.h>

namespace fs = boost::filesystem;
using namespace std;

UniValue settings(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    return data;
}

bool ReadAPISetting(UniValue& data, UniValue& setting, string name, string program){
    UniValue programUni(UniValue::VOBJ);
    programUni = find_value(data, program);
    if(programUni.isNull()){
        return false;
    }

    setting = find_value(programUni, name);
    if(!setting.isNull()){
        return true;
    }
    return false;
}

bool WriteAPISetting(UniValue& data, UniValue& setting, string program){
    UniValue programUni(UniValue::VOBJ);
    programUni = find_value(data, program);
    if(programUni.isNull()){
        programUni.setObject();
    }

    string name = find_value(setting, "name").get_str();
    string value = find_value(setting, "data").get_str();
    bool restartRequired = find_value(setting, "restartRequired").get_bool();

    UniValue settingUni(UniValue::VOBJ);
    settingUni = find_value(programUni, name);
    if(!settingUni.isNull()){
        settingUni.replace("data", value);
        settingUni.replace("changed", true);
    }else{
        settingUni.setObject();
        settingUni.replace("data", value);
        settingUni.replace("changed", false);
        settingUni.replace("restartRequired", restartRequired);
    }
    programUni.replace(name, settingUni);
    data.replace(program, programUni);
    return true;
}

bool WriteDaemonSettings(){
    UniValue settingsData(UniValue::VOBJ);
    settingsData = ReadSettingsData();

    string name;
    string value;

    for(std::map<std::string, std::string>:: iterator it = mapArgs.begin(); it != mapArgs.end(); it++){
        name = (*it).first;
        value = (*it).second;
        UniValue setting(UniValue::VOBJ);
        setting.push_back(Pair("data", value));
        setting.push_back(Pair("restartRequired", true));
        setting.push_back(Pair("name", name));

        WriteAPISetting(settingsData, setting, "daemon");
    }

    WriteSettingsData(settingsData);

    return true;
}


bool WriteClientSettings(){
    // read from table defined below
    return true;
}

bool WriteSettingsData(UniValue& data){
    fs::path path;
    UniValue SettingsUni(UniValue::VOBJ);
    GetSettings(SettingsUni, path);

    SettingsUni.replace("data", data);

    //write back UniValue
    std::ofstream SettingsOut(path.string());

    SettingsOut << SettingsUni.write(4,0) << endl;

    return true;
}

bool GetSettings(UniValue& settings, fs::path& path){
    path = CreateSettingsFile();

    // get data as ifstream
    std::ifstream SettingsIn(path.string());

    // parse as std::string
    std::string SettingsStr((std::istreambuf_iterator<char>(SettingsIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    settings.read(SettingsStr);

    return true;
}

UniValue ReadSettingsData(){
    UniValue SettingsUni(UniValue::VOBJ);
    fs::path path;
    GetSettings(SettingsUni, path);

    UniValue SettingsData(UniValue::VOBJ);
    if(!SettingsUni["data"].isNull()){
        SettingsData = SettingsUni["data"];
    }

    return SettingsData;
}

// called at startup to initialize data.
// - clears data in daemon sub univalue
// - sets "changed" value to false for all client univalue
// - sets restartNow = false
bool SettingsStartup(){

    UniValue data(UniValue::VOBJ);
    UniValue client(UniValue::VOBJ);
    UniValue daemon(UniValue::VOBJ);

    data = ReadSettingsData();

    client = find_value(data, "client");
    daemon = find_value(data, "daemon");

    if(!daemon.isNull()){
        data.replace("daemon", NullUniValue);
    }

    if(!client.isNull()){
        vector<string> names = client.getKeys();
        UniValue settingUni(UniValue::VOBJ);
        string name;
        for (vector<string>::iterator it = names.begin(); it != names.end(); it++) {
            name = *(it);
            settingUni = find_value(client, name);
            settingUni.replace("changed", false);
            client.replace(name, settingUni);
        }
        data.replace("client", client);
    }

    data.replace("restartNow", false);

    WriteSettingsData(data);

    WriteDaemonSettings();

    GetMainSignals().UpdatedSettings(ReadSettingsData().write());

    return true;
}

// get Client or Daemon settings
bool GetSettingsProgram(UniValue data, string name, string& program){
    UniValue client = find_value(data, "client");
    UniValue daemon = find_value(data, "daemon");
    if(!find_value(client, name).isNull()){
        program = "client";
        return true;
    }
    if(!find_value(daemon, name).isNull()){
        program = "daemon";
        return true;
    }
    return false;
}

bool CheckSettingLayout(UniValue& setting){
    if( find_value(setting,            "data").isNull()
      ||find_value(setting, "restartRequired").isNull()){
        return false;
    }
    if(setting.getKeys().size()!=2){
        return false;
    }
    return true;
}

bool SetRestartNow(UniValue& data){
    UniValue client = find_value(data, "client");
    UniValue daemon = find_value(data, "daemon");

    vector<string> names;
    UniValue setting(UniValue::VOBJ);

    for(int i=0; i<=1;i++){
        names = (i==0) ? client.getKeys() : daemon.getKeys();
        for (vector<string>::iterator it = names.begin(); it != names.end(); it++) {
            string name = (*it);
            setting = find_value((i==0) ? client : daemon, name);
            if(find_value(setting, "restartRequired").get_bool()==true &&
               find_value(setting,         "changed").get_bool()==true){
                data.replace("restartNow", true);
                break;
            }
        }
    }
    return true;
}

UniValue readsettings(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    return data;
}

UniValue setting(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue settingsData = ReadSettingsData();
    vector<UniValue> settings;
    UniValue setting(UniValue::VOBJ);
    string name;
    string program;
    bool writeBack = false;

    switch(type){
        case Initial: {
            return settingsData;
            break;   
        }
        case Create: {
            vector<string> names = data.getKeys();
            BOOST_FOREACH(const std::string& name, names)
            {
                // fail out if the setting already exists
                if(GetSettingsProgram(settingsData, name, program)){
                   throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                setting = find_value(data, name);
                // check the setting has the correct layout
                if(!CheckSettingLayout(setting)){
                    throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                setting.push_back(Pair("name", name));
                setting.push_back(Pair("changed", false));
                WriteAPISetting(settingsData, setting, "client");
            }

            writeBack = true;
            break;             
        }
        case Delete: {
            // can only delete client data, not daemon..
            UniValue client(UniValue::VOBJ);
            client = find_value(settingsData, "client");

            UniValue names(UniValue::VARR);
            names = find_value(data, "settings").get_array();
            for(size_t index=0; index<names.size();index++){
                string name = names[index].get_str();
                setting = find_value(client, name);
                if(setting.isNull()){
                    throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                client.erase(name);
            }

            settingsData.replace("client", client);
            writeBack = true;
            break;
        }
        case Update: {
            vector<string> names = data.getKeys();
            //for (vector<string>::iterator it = names.begin(); it != names.end(); it++) {
            BOOST_FOREACH(const std::string& name, names){
                // fail out if setting not found
                if(!GetSettingsProgram(settingsData, name, program)){
                   throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                setting = find_value(data, name);
                // Do not permit updating daemon "restartRequired" entry
                if(program=="daemon" && !find_value(setting,"restartRequired").isNull()){
                    throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                setting.push_back(Pair("name", name));    
                WriteAPISetting(settingsData, setting, program);   
            }
                
            SetRestartNow(settingsData); 
            writeBack = true;
            break;   
        }
        case Get: {
            UniValue result(UniValue::VOBJ);
            UniValue names(UniValue::VARR);
            names = find_value(data, "settings").get_array();
            for(size_t index=0; index<names.size();index++){
                string name = names[index].get_str();
                if(!GetSettingsProgram(settingsData, name, program)){
                    throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                UniValue setting(UniValue::VOBJ);
                if(!ReadAPISetting(settingsData, setting, name, program)){
                    throw JSONRPCError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                result.push_back(Pair(name,setting));
            }

            return result;
            break;
        }
        default: {

        }
    }

    if(writeBack){
        WriteSettingsData(settingsData);
        GetMainSignals().UpdatedSettings(ReadSettingsData().write());
    }

    return true;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          --------   --------------   --------
    { "wallet",             "setting",         &setting,                 true,      false,           false  },
    { "wallet",             "readSettings",    &readsettings,            true,      false,           false  }
};

void RegisterSettingsAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
