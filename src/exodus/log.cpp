#include "exodus/log.h"

#include "chainparamsbase.h"
#include "util.h"
#include "utiltime.h"

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/once.hpp>

#include <assert.h>
#include <stdio.h>
#include <atomic>
#include <string>
#include <vector>

// Default log files
const std::string LOG_FILENAME    = "exodus.log";

// Options
static const long LOG_BUFFERSIZE  =  8000000; //  8 MB
static const long LOG_SHRINKSIZE  = 50000000; // 50 MB

// Debug flags
bool exodus_debug_parser_data        = 0;
bool exodus_debug_parser_readonly    = 0;
//! Print information to potential DEx payments and outputs
bool exodus_debug_parser_dex         = 1;
bool exodus_debug_parser             = 0;
bool exodus_debug_verbose            = 0;
bool exodus_debug_verbose2           = 0;
bool exodus_debug_verbose3           = 0;
bool exodus_debug_vin                = 0;
bool exodus_debug_script             = 0;
bool exodus_debug_dex                = 1;
bool exodus_debug_send               = 1;
bool exodus_debug_tokens             = 0;
//! Print information about payloads with non-sequential sequence number
bool exodus_debug_spec               = 0;
bool exodus_debug_exo                = 0;
bool exodus_debug_tally              = 1;
bool exodus_debug_sp                 = 1;
bool exodus_debug_sto                = 1;
bool exodus_debug_txdb               = 0;
bool exodus_debug_tradedb            = 1;
bool exodus_debug_persistence        = 0;
bool exodus_debug_ui                 = 0;
bool exodus_debug_pending            = 1;
bool exodus_debug_metadex1           = 0;
bool exodus_debug_metadex2           = 0;
//! Print orderbook before and after each trade
bool exodus_debug_metadex3           = 0;
//! Print transaction fields, when interpreting packets
bool exodus_debug_packets            = 1;
//! Print transaction fields, when interpreting packets (in RPC mode)
bool exodus_debug_packets_readonly   = 0;
bool exodus_debug_walletcache        = 0;
//! Print each line added to consensus hash
bool exodus_debug_consensus_hash     = 0;
//! Print consensus hashes for each block when parsing
bool exodus_debug_consensus_hash_every_block = 0;
//! Print extra info on alert processing
bool exodus_debug_alerts             = 1;
//! Print consensus hashes for each transaction when parsing
bool exodus_debug_consensus_hash_every_transaction = 0;
//! Debug fees
bool exodus_debug_fees               = 1;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */
static boost::once_flag debugLogInitFlag = BOOST_ONCE_INIT;
/**
 * We use boost::call_once() to make sure these are initialized
 * in a thread-safe manner the first time called:
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
/** Flag to indicate, whether the Exodus log file should be reopened. */
extern std::atomic<bool> fReopenExodusLog;
/**
 * Returns path for debug log file.
 *
 * The log file can be specified via startup option "--omnilogfile=/path/to/exodus.log",
 * and if none is provided, then the client's datadir is used as default location.
 */
static boost::filesystem::path GetLogPath()
{
    boost::filesystem::path pathLogFile;
    std::string strLogPath = GetArg("-omnilogfile", "");

    if (!strLogPath.empty()) {
        pathLogFile = boost::filesystem::path(strLogPath);
        TryCreateDirectory(pathLogFile.parent_path());
    } else {
        pathLogFile = GetDataDir() / LOG_FILENAME;
    }

    return pathLogFile;
}

/**
 * Opens debug log file.
 */
static void DebugLogInit()
{
    assert(fileout == NULL);
    assert(mutexDebugLog == NULL);

    boost::filesystem::path pathDebug = GetLogPath();
    fileout = fopen(pathDebug.string().c_str(), "a");

    if (fileout) {
        setbuf(fileout, NULL); // Unbuffered
    } else {
        PrintToConsole("Failed to open debug log file: %s\n", pathDebug.string());
    }

    mutexDebugLog = new boost::mutex();
}

/**
 * @return The current timestamp in the format: 2009-01-03 18:15:05
 */
static std::string GetTimestamp()
{
    return DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime());
}

/**
 * Prints to log file.
 *
 * The configuration options "-logtimestamps" can be used to indicate, whether
 * the message to log should be prepended with a timestamp.
 *
 * If "-printtoconsole" is enabled, then the message is written to the standard
 * output, usually the console, instead of a log file.
 *
 * @param str[in]  The message to log
 * @return The total number of characters written
 */
int LogFilePrint(const std::string& str)
{
    int ret = 0; // Number of characters written
    if (fPrintToConsole) {
        // Print to console
        ret = ConsolePrint(str);
    }
    else if (fPrintToDebugLog && AreBaseParamsConfigured()) {
        static bool fStartedNewLine = true;
        boost::call_once(&DebugLogInit, debugLogInitFlag);

        if (fileout == NULL) {
            return ret;
        }
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // Reopen the log file, if requested
        if (fReopenExodusLog) {
        	fReopenExodusLog = false;
            boost::filesystem::path pathDebug = GetLogPath();
            if (freopen(pathDebug.string().c_str(), "a", fileout) != NULL) {
                setbuf(fileout, NULL); // Unbuffered
            }
        }

        // Printing log timestamps can be useful for profiling
        if (fLogTimestamps && fStartedNewLine) {
            ret += fprintf(fileout, "%s ", GetTimestamp().c_str());
        }
        if (!str.empty() && str[str.size()-1] == '\n') {
            fStartedNewLine = true;
        } else {
            fStartedNewLine = false;
        }
        ret += fwrite(str.data(), 1, str.size(), fileout);
    }

    return ret;
}

/**
 * Prints to the standard output, usually the console.
 *
 * The configuration option "-logtimestamps" can be used to indicate, whether
 * the message should be prepended with a timestamp.
 *
 * @param str[in]  The message to print
 * @return The total number of characters written
 */
int ConsolePrint(const std::string& str)
{
    int ret = 0; // Number of characters written
    static bool fStartedNewLine = true;

    if (fLogTimestamps && fStartedNewLine) {
        ret = fprintf(stdout, "%s %s", GetTimestamp().c_str(), str.c_str());
    } else {
        ret = fwrite(str.data(), 1, str.size(), stdout);
    }
    if (!str.empty() && str[str.size()-1] == '\n') {
        fStartedNewLine = true;
    } else {
        fStartedNewLine = false;
    }
    fflush(stdout);

    return ret;
}

/**
 * Determine whether to override compiled debug levels via enumerating startup option --exodusdebug.
 *
 * Example usage (granular categories)    : --exodusdebug=parser --exodusdebug=metadex1 --exodusdebug=ui
 * Example usage (enable all categories)  : --exodusdebug=all
 * Example usage (disable all debugging)  : --exodusdebug=none
 * Example usage (disable all except XYZ) : --exodusdebug=none --omnidebug=parser --exodusdebug=sto
 */
void InitDebugLogLevels()
{
    if (!mapArgs.count("-exodusdebug")) {
        return;
    }

    const std::vector<std::string>& debugLevels = mapMultiArgs["-exodusdebug"];

    for (std::vector<std::string>::const_iterator it = debugLevels.begin(); it != debugLevels.end(); ++it) {
        if (*it == "parser_data") exodus_debug_parser_data = true;
        if (*it == "parser_readonly") exodus_debug_parser_readonly = true;
        if (*it == "parser_dex") exodus_debug_parser_dex = true;
        if (*it == "parser") exodus_debug_parser = true;
        if (*it == "verbose") exodus_debug_verbose = true;
        if (*it == "verbose2") exodus_debug_verbose2 = true;
        if (*it == "verbose3") exodus_debug_verbose3 = true;
        if (*it == "vin") exodus_debug_vin = true;
        if (*it == "script") exodus_debug_script = true;
        if (*it == "dex") exodus_debug_dex = true;
        if (*it == "send") exodus_debug_send = true;
        if (*it == "tokens") exodus_debug_tokens = true;
        if (*it == "spec") exodus_debug_spec = true;
        if (*it == "exo") exodus_debug_exo = true;
        if (*it == "tally") exodus_debug_tally = true;
        if (*it == "sp") exodus_debug_sp = true;
        if (*it == "sto") exodus_debug_sto = true;
        if (*it == "txdb") exodus_debug_txdb = true;
        if (*it == "tradedb") exodus_debug_tradedb = true;
        if (*it == "persistence") exodus_debug_persistence = true;
        if (*it == "ui") exodus_debug_ui = true;
        if (*it == "pending") exodus_debug_pending = true;
        if (*it == "metadex1") exodus_debug_metadex1 = true;
        if (*it == "metadex2") exodus_debug_metadex2 = true;
        if (*it == "metadex3") exodus_debug_metadex3 = true;
        if (*it == "packets") exodus_debug_packets = true;
        if (*it == "packets_readonly") exodus_debug_packets_readonly = true;
        if (*it == "walletcache") exodus_debug_walletcache = true;
        if (*it == "consensus_hash") exodus_debug_consensus_hash = true;
        if (*it == "consensus_hash_every_block") exodus_debug_consensus_hash_every_block = true;
        if (*it == "alerts") exodus_debug_alerts = true;
        if (*it == "consensus_hash_every_transaction") exodus_debug_consensus_hash_every_transaction = true;
        if (*it == "fees") exodus_debug_fees = true;
        if (*it == "none" || *it == "all") {
            bool allDebugState = false;
            if (*it == "all") allDebugState = true;
            exodus_debug_parser_data = allDebugState;
            exodus_debug_parser_readonly = allDebugState;
            exodus_debug_parser_dex = allDebugState;
            exodus_debug_parser = allDebugState;
            exodus_debug_verbose = allDebugState;
            exodus_debug_verbose2 = allDebugState;
            exodus_debug_verbose3 = allDebugState;
            exodus_debug_vin = allDebugState;
            exodus_debug_script = allDebugState;
            exodus_debug_dex = allDebugState;
            exodus_debug_send = allDebugState;
            exodus_debug_tokens = allDebugState;
            exodus_debug_spec = allDebugState;
            exodus_debug_exo = allDebugState;
            exodus_debug_tally = allDebugState;
            exodus_debug_sp = allDebugState;
            exodus_debug_sto = allDebugState;
            exodus_debug_txdb = allDebugState;
            exodus_debug_tradedb = allDebugState;
            exodus_debug_persistence = allDebugState;
            exodus_debug_ui = allDebugState;
            exodus_debug_pending = allDebugState;
            exodus_debug_metadex1 = allDebugState;
            exodus_debug_metadex2 = allDebugState;
            exodus_debug_metadex3 = allDebugState;
            exodus_debug_packets =  allDebugState;
            exodus_debug_packets_readonly =  allDebugState;
            exodus_debug_walletcache = allDebugState;
            exodus_debug_consensus_hash = allDebugState;
            exodus_debug_consensus_hash_every_block = allDebugState;
            exodus_debug_alerts = allDebugState;
            exodus_debug_consensus_hash_every_transaction = allDebugState;
            exodus_debug_fees = allDebugState;
        }
    }
}

/**
 * Scrolls debug log, if it's getting too big.
 */
void ShrinkDebugLog()
{
    boost::filesystem::path pathLog = GetLogPath();
    FILE* file = fopen(pathLog.string().c_str(), "r");

    if (file && boost::filesystem::file_size(pathLog) > LOG_SHRINKSIZE) {
        // Restart the file with some of the end
        char* pch = new char[LOG_BUFFERSIZE];
        if (NULL != pch) {
            fseek(file, -LOG_BUFFERSIZE, SEEK_END);
            int nBytes = fread(pch, 1, LOG_BUFFERSIZE, file);
            fclose(file);
            file = NULL;

            file = fopen(pathLog.string().c_str(), "w");
            if (file) {
                fwrite(pch, 1, nBytes, file);
                fclose(file);
                file = NULL;
            }
            delete[] pch;
        }
    } else if (NULL != file) {
        fclose(file);
        file = NULL;
    }
}

