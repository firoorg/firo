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

std::set<std::string> guiSettings = { "-torsetup" };

UniValue settings(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    return data;
}

bool ReadAPISetting(UniValue& data, UniValue& setting, string name){
    setting = find_value(data, name);
    if(!setting.isNull()){
        return true;
    }
    return false;
}

bool WriteAPISetting(UniValue& data, string name, UniValue& setting){
    UniValue settingUni(UniValue::VOBJ);
    settingUni = find_value(data, name);
    if(settingUni.isNull()){
        settingUni.setObject();
    }
    data.replace(name, setting);
    return true;
}

bool WriteSettingsToFS(UniValue& data){
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

bool SettingExists(UniValue data, string name){
    if(!find_value(data, name).isNull()){
        return true;
    }
    return false;
}

bool CheckSettingLayout(UniValue& setting){
    if(find_value(setting, "data").isNull()){
        return false;
    }
    if(setting.getKeys().size()!=1){
        return false;
    }
    return true;
}

bool SetRestartNow(UniValue& data){
    vector<string> names;
    UniValue setting(UniValue::VOBJ);

    names = data.getKeys();
    for (vector<string>::iterator it = names.begin(); it != names.end(); it++) {
        string name = (*it);
        setting = find_value(data, name);
        if(name != "restartNow" && 
           find_value(setting, "changed").get_bool()==true){
            data.replace("restartNow", true);
            break;
        }
    }
    return true;
}

/* Read daemon settings stored in settings.json into mapArgs.
 * It is on the lowest end of the hierarchy: ie cli -> conf file -> settings.json.

   - mapArgs is the final data structure with values.
   - if setting is in both conf and settings.json, conf takes precedence.
     meaning do not update mapArgs, and set "disabled: true" for this setting in settings.json
   - if cli/conf, but not settings.json:
     Add to settings.json
   - if settings.json, but not cli/conf:
     update mapArgs to use this setting.
     else, remove it (if not just added from mapArgs)
 */
void ReadAPISettingsFile()
{
    UniValue settingsData(UniValue::VOBJ);
    settingsData = ReadSettingsData();

    settingsData.erase("restartNow");

    UniValue setting(UniValue::VOBJ);

    for(std::map<std::string, std::string>:: iterator it = mapArgs.begin(); it != mapArgs.end(); it++){
        string name = (*it).first;
        string value = (*it).second;
        setting.setObject();
        setting.replace("data", value);
        setting.replace("changed", false);
        setting.replace("disabled", true);
        settingsData.replace(name, setting);
    }

    vector<string> keys = settingsData.getKeys();
    BOOST_FOREACH(const std::string& strKey, keys)
    {
        setting.setObject();
        setting = find_value(settingsData, strKey);
        if(guiSettings.count(strKey)){
            if(!mapArgs.count(strKey)){
                string value = find_value(setting, "data").get_str();
                mapArgs[strKey] = value;
                setting.replace("changed", false);
                setting.replace("disabled", false);
                settingsData.replace(strKey, setting);
            }
        }else{
            if(!mapArgs.count(strKey)){
                settingsData.erase(strKey);
            }
        }
    }

    // write back to FS
    settingsData.replace("restartNow", false);
    WriteSettingsToFS(settingsData);
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
                if(SettingExists(settingsData, name)){
                   throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                setting = find_value(data, name);
                setting.replace("disabled", false);
                setting.replace("changed", true);
                WriteAPISetting(settingsData, name, setting);
            }

            writeBack = true;
            break;             
        }
        case Update: {
            vector<string> names = data.getKeys();
            BOOST_FOREACH(const std::string& name, names){
                // fail out if setting not found
                if(!SettingExists(settingsData, name)){
                   throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                bool disabled = find_value(find_value(settingsData, name), "disabled").get_bool();
                setting = find_value(data, name);
                setting.replace("changed", true);
                setting.replace("disabled", disabled);
                WriteAPISetting(settingsData, name, setting);
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
                if(!SettingExists(settingsData, name)){
                    throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
                }
                UniValue setting(UniValue::VOBJ);
                if(!ReadAPISetting(settingsData, setting, name)){
                    throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
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
        WriteSettingsToFS(settingsData);
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
