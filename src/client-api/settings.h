// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
namespace fs = boost::filesystem;

void ReadAPISettingsFile();

bool WriteAPISetting(UniValue& data, string name, UniValue& setting);

bool GetSettings(UniValue& settings, fs::path& path);

UniValue ReadSettingsData();

bool WriteSettingsToFS(UniValue& data);



