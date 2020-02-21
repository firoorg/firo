#include "elysium/notifications.h"

#include "elysium/log.h"
#include "elysium/exodus.h"
#include "elysium/rules.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/version.h"

#include "main.h"
#include "util.h"
#include "ui_interface.h"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <stdint.h>
#include <string>
#include <vector>

namespace exodus
{

//! Vector of currently active Exodus alerts
std::vector<AlertData> currentExodusAlerts;

/**
 * Deletes previously broadcast alerts from sender from the alerts vector
 *
 * Note cannot be used to delete alerts from other addresses, nor to delete system generated feature alerts
 */
void DeleteAlerts(const std::string& sender)
{
    for (std::vector<AlertData>::iterator it = currentExodusAlerts.begin(); it != currentExodusAlerts.end(); ) {
        AlertData alert = *it;
        if (sender == alert.alert_sender) {
            PrintToLog("Removing deleted alert (from:%s type:%d expiry:%d message:%s)\n", alert.alert_sender,
                alert.alert_type, alert.alert_expiry, alert.alert_message);
            it = currentExodusAlerts.erase(it);
            uiInterface.ElysiumStateChanged();
        } else {
            it++;
        }
    }
}

/**
 * Removes all active alerts.
 *
 * A signal is fired to notify the UI about the status update.
 */
void ClearAlerts()
{
    currentExodusAlerts.clear();
    uiInterface.ElysiumStateChanged();
}

/**
 * Adds a new alert to the alerts vector
 *
 */
void AddAlert(const std::string& sender, uint16_t alertType, uint32_t alertExpiry, const std::string& alertMessage)
{
    AlertData newAlert;
    newAlert.alert_sender = sender;
    newAlert.alert_type = alertType;
    newAlert.alert_expiry = alertExpiry;
    newAlert.alert_message = alertMessage;

    // very basic sanity checks for broadcast alerts to catch malformed packets
    if (sender != "exodus" && (alertType < ALERT_BLOCK_EXPIRY || alertType > ALERT_CLIENT_VERSION_EXPIRY)) {
        PrintToLog("New alert REJECTED (alert type not recognized): %s, %d, %d, %s\n", sender, alertType, alertExpiry, alertMessage);
        return;
    }

    currentExodusAlerts.push_back(newAlert);
    PrintToLog("New alert added: %s, %d, %d, %s\n", sender, alertType, alertExpiry, alertMessage);
}

/**
 * Determines whether the sender is an authorized source for Exodus Core alerts.
 *
 * The option "-elysiumalertallowsender=source" can be used to whitelist additional sources,
 * and the option "-elysiumalertignoresender=source" can be used to ignore a source.
 *
 * To consider any alert as authorized, "-elysiumalertallowsender=any" can be used. This
 * should only be done for testing purposes!
 */
bool CheckAlertAuthorization(const std::string& sender)
{
    std::set<std::string> whitelisted;

    // Mainnet
    whitelisted.insert("48UM25xTXCxPRwnv36YjjJNaAK4whKR8Rd"); // Poramin Insom   <poramin@zcoin.io>

    // Testnet / Regtest
    // use -elysiumalertallowsender for testing

    // Add manually whitelisted sources
    if (mapArgs.count("-elysiumalertallowsender")) {
        const std::vector<std::string>& sources = mapMultiArgs["-elysiumalertallowsender"];

        for (std::vector<std::string>::const_iterator it = sources.begin(); it != sources.end(); ++it) {
            whitelisted.insert(*it);
        }
    }

    // Remove manually ignored sources
    if (mapArgs.count("-elysiumalertignoresender")) {
        const std::vector<std::string>& sources = mapMultiArgs["-elysiumalertignoresender"];

        for (std::vector<std::string>::const_iterator it = sources.begin(); it != sources.end(); ++it) {
            whitelisted.erase(*it);
        }
    }

    bool fAuthorized = (whitelisted.count(sender) ||
                        whitelisted.count("any"));

    return fAuthorized;
}

/**
 * Alerts including meta data.
 */
std::vector<AlertData> GetExodusAlerts()
{
    return currentExodusAlerts;
}

/**
 * Human readable alert messages.
 */
std::vector<std::string> GetExodusAlertMessages()
{
    std::vector<std::string> vstr;
    for (std::vector<AlertData>::iterator it = currentExodusAlerts.begin(); it != currentExodusAlerts.end(); it++) {
        vstr.push_back((*it).alert_message);
    }
    return vstr;
}

/**
 * Expires any alerts that need expiring.
 */
bool CheckExpiredAlerts(unsigned int curBlock, uint64_t curTime)
{
    for (std::vector<AlertData>::iterator it = currentExodusAlerts.begin(); it != currentExodusAlerts.end(); ) {
        AlertData alert = *it;
        switch (alert.alert_type) {
            case ALERT_BLOCK_EXPIRY:
                if (curBlock >= alert.alert_expiry) {
                    PrintToLog("Expiring alert (from %s: type:%d expiry:%d message:%s)\n", alert.alert_sender,
                        alert.alert_type, alert.alert_expiry, alert.alert_message);
                    it = currentExodusAlerts.erase(it);
                    uiInterface.ElysiumStateChanged();
                } else {
                    it++;
                }
            break;
            case ALERT_BLOCKTIME_EXPIRY:
                if (curTime > alert.alert_expiry) {
                    PrintToLog("Expiring alert (from %s: type:%d expiry:%d message:%s)\n", alert.alert_sender,
                        alert.alert_type, alert.alert_expiry, alert.alert_message);
                    it = currentExodusAlerts.erase(it);
                    uiInterface.ElysiumStateChanged();
                } else {
                    it++;
                }
            break;
            case ALERT_CLIENT_VERSION_EXPIRY:
                if (ELYSIUM_VERSION > alert.alert_expiry) {
                    PrintToLog("Expiring alert (form: %s type:%d expiry:%d message:%s)\n", alert.alert_sender,
                        alert.alert_type, alert.alert_expiry, alert.alert_message);
                    it = currentExodusAlerts.erase(it);
                    uiInterface.ElysiumStateChanged();
                } else {
                    it++;
                }
            break;
            default: // unrecognized alert type
                    PrintToLog("Removing invalid alert (from:%s type:%d expiry:%d message:%s)\n", alert.alert_sender,
                        alert.alert_type, alert.alert_expiry, alert.alert_message);
                    it = currentExodusAlerts.erase(it);
                    uiInterface.ElysiumStateChanged();
            break;
        }
    }
    return true;
}

} // namespace exodus
