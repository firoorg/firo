// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "util.h"

#include "support/allocators/secure.h"
#include "chainparamsbase.h"
#include "ctpl.h"
#include "random.h"
#include "serialize.h"
#include "stacktraces.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "univalue.h"

#ifdef ENABLE_CLIENTAPI
#include "minizip/zip.h"
#include <zlib.h>
#include <fstream>
#endif

#include "warnings.h"
#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

// znode fZnode
bool fMasternodeMode = false;
bool fLiteMode = false;
int nWalletBackups = 10;

const char * const BITCOIN_CONF_FILENAME = "firo.conf";
const char * const BITCOIN_PID_FILENAME = "firod.pid";

CCriticalSection cs_args;
map<string, string> mapArgs;
static map<string, vector<string> > _mapMultiArgs;
const map<string, vector<string> >& mapMultiArgs = _mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
bool fServer = false;
bool fApi = false;

bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;


std::atomic<bool> fReopenDebugLog(false);
CTranslationInterface translationInterface;

/** Flag to indicate, whether the Elysium log file should be reopened. */
std::atomic<bool> fReopenElysiumLog(false);

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();

#ifdef WIN32
        // Seed OpenSSL PRNG with current contents of the screen
        RAND_screen();
#endif

        // Seed OpenSSL PRNG with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Securely erase the memory used by the PRNG
        RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

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

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
static list<string> *vMsgsBeforeOpenLog;

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void OpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag);
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

    assert(fileout == NULL);
    assert(vMsgsBeforeOpenLog);
    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) {
        setbuf(fileout, NULL); // unbuffered
        // dump buffered messages from before we opened the log
        while (!vMsgsBeforeOpenLog->empty()) {
            FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
            vMsgsBeforeOpenLog->pop_front();
        }
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = NULL;
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<set<string> > ptrCategory;
        if (ptrCategory.get() == NULL)
        {
            if (mapMultiArgs.count("-debug")) {
                const vector<string>& categories = mapMultiArgs.at("-debug");
                ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
                // thread_specific_ptr automatically deletes the set when the thread ends.
            } else
                ptrCategory.reset(new set<string>());
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string("1")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static std::string LogTimestampStr(const std::string &str, std::atomic_bool *fStartedNewLine)
{
    string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine) {
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000);
        if (fLogTimeMicros)
            strStamped += strprintf(".%06d", nTimeMicros%1000000);
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    static std::atomic_bool fStartedNewLine(true);

    string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    LOCK(cs_args);
    mapArgs.clear();
    _mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos)
        {
            strValue = str.substr(is_index+1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        _mapMultiArgs[str].push_back(strValue);
    }
}

bool IsArgSet(const std::string& strArg)
{
    LOCK(cs_args);
    return mapArgs.count(strArg);
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

boost::optional<bool> GetOptBoolArg(const std::string& strArg)
{
    auto const iter = mapArgs.find(strArg);
    if(iter != mapArgs.end()){
        if(iter->second.empty())
            return boost::optional<bool>(true);
        return boost::optional<bool>(InterpretBool(iter->second));
    }
    return boost::optional<bool>();
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void ForceSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    mapArgs[strArg] = strValue;
}



static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

#ifdef ENABLE_CRASH_HOOKS
static std::string FormatException(const std::exception_ptr pex, const char* pszThread)
{
    return strprintf("EXCEPTION: %s", GetPrettyExceptionStr(pex));
}
#endif

void PrintExceptionContinue(const std::exception_ptr pex, const char* pszThread)
{
#ifdef ENABLE_CRASH_HOOKS
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
#endif
}

boost::filesystem::path GetDefaultDataDirForCoinName(const std::string &coinName)
{
    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\firo
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\firo
    // Mac: ~/Library/Application Support/firo
    // Unix: ~/.firo
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / coinName;
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    return pathRet / "Library/Application Support" / coinName;
#else
    // Unix
    return pathRet / ("." + coinName);
#endif
#endif
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;

    fs::path firoDefaultDir = GetDefaultDataDirForCoinName("firo");
    if (!fs::is_directory(firoDefaultDir)) {
        // try "zcoin" in case we're upgrading from pre-firo version
        fs::path zcoinDefaultDir = GetDefaultDataDirForCoinName("zcoin");
        if (fs::is_directory(zcoinDefaultDir))
            return zcoinDefaultDir;
    }

    return firoDefaultDir;
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static CCriticalSection csPathCached;

static boost::filesystem::path backupsDirCached;
static CCriticalSection csBackupsDirCached;

const boost::filesystem::path &GetBackupsDir()
{
    namespace fs = boost::filesystem;

    LOCK(csBackupsDirCached);

    fs::path &backupsDir = backupsDirCached;

    if (!backupsDir.empty())
        return backupsDir;

    if (mapArgs.count("-walletbackupsdir")) {
        backupsDir = fs::absolute(mapArgs["-walletbackupsdir"]);
        // Path must exist
        if (fs::is_directory(backupsDir)) return backupsDir;
        // Fallback to default path if it doesn't
        LogPrintf("%s: Warning: incorrect parameter -walletbackupsdir, path must exist! Using default path.\n", __func__);
        //SetMiscWarning(_("Warning: incorrect parameter -walletbackupsdir, path must exist! Using default path."));
    }
    // Default path
    backupsDir = GetDataDir() / "backups";

    return backupsDir;
}

const boost::filesystem::path &GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    if (IsArgSet("-datadir")) {
        path = fs::system_complete(GetArg("-datadir", ""));
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

boost::filesystem::path GetPersistentDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path path = GetDataDir(fNetSpecific) / PERSISTENT_FILENAME;

    if(!fs::exists(path)){
        fs::create_directories(path);
    }

    return path;
}

boost::filesystem::path GetJsonDataDir(bool fNetSpecific, const char* filename)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path path = GetPersistentDataDir(fNetSpecific);

    fs::path newpath = path / filename;

    return newpath;
}

void ClearDatadirCache()
{
    LOCK(csPathCached);

    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

boost::filesystem::path GetConfigFile(const std::string& confPath)
{
    boost::filesystem::path pathConfigFile(confPath);
    if (!pathConfigFile.is_complete()) {
        boost::filesystem::path dataDir = GetDataDir(false);

        // upgrade heuristics: if dataDir ends with either "zcoin" or ".zcoin" and confPath is set
        // to default value we use "zcoin.conf" as config file name

        if (confPath == BITCOIN_CONF_FILENAME && (dataDir.filename() == "zcoin" || dataDir.filename() == ".zcoin"))
            pathConfigFile = dataDir / "zcoin.conf";
        else
            pathConfigFile = dataDir / pathConfigFile;
    }

    return pathConfigFile;
}

boost::filesystem::path CreatePaymentRequestFile(bool fNetSpecific)
{
    boost::filesystem::path pathConfigFile = GetJsonDataDir(fNetSpecific,PAYMENT_REQUEST_FILENAME);

    LogPrintf("API: pathConfigFile payment request: %s\n", pathConfigFile.string());
    if(!boost::filesystem::exists(pathConfigFile)){
        LogPrintf("PR does not exist\n");
        UniValue paymentRequestUni(UniValue::VOBJ);
        paymentRequestUni.push_back(Pair("type", "payment_request"));
        paymentRequestUni.push_back(Pair("data", NullUniValue));

        //write back UniValue
        std::ofstream paymentRequestOut(pathConfigFile.string());

        paymentRequestOut << paymentRequestUni.write(4,0) << endl;
    }

    return pathConfigFile;
}

boost::filesystem::path CreateSettingsFile(bool fNetSpecific)
{
    boost::filesystem::path const &pathConfigFile = GetJsonDataDir(fNetSpecific, SETTINGS_FILENAME);
    LogPrintf("API: pathConfigFile settings: %s\n", pathConfigFile.string());
    if(!boost::filesystem::exists(pathConfigFile)){
        LogPrintf("settings does not exist\n");
        UniValue settingsUni(UniValue::VOBJ);
        UniValue dataUni(UniValue::VOBJ);
        settingsUni.push_back(Pair("type", "settings"));
        settingsUni.push_back(Pair("data", dataUni));

        //write back UniValue
        std::ofstream settingsOut(pathConfigFile.string());

        settingsOut << settingsUni.write(4,0) << endl;
    }

    return pathConfigFile;
}

void ReadConfigFile(const std::string& confPath)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile(confPath));
    if (!streamConfig.good())
        return; // No firo.conf file is OK

    {
        LOCK(cs_args);
        set<string> setOptions;
        setOptions.insert("*");

        for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
        {
            // Don't overwrite existing settings so command line settings override bitcoin.conf
            string strKey = string("-") + it->string_key;
            string strValue = it->value[0];
            InterpretNegativeSetting(strKey, strValue);
            if (mapArgs.count(strKey) == 0)
                mapArgs[strKey] = strValue;
            _mapMultiArgs[strKey].push_back(strValue);
        }
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

bool RenameDirectoriesFromZcoinToFiro()
{
    namespace fs = boost::filesystem;

    fs::path zcoinPath = GetDefaultDataDirForCoinName("zcoin");
    fs::path firoPath = GetDefaultDataDirForCoinName("firo");

    // rename is possible only if zcoin directory exists and firo doesn't
    if (fs::exists(firoPath) || !fs::is_directory(zcoinPath))
        return false;

    fs::path zcoinConfFileName = zcoinPath / "zcoin.conf";
    fs::path firoConfFileName = zcoinPath / "firo.conf";
    if (fs::exists(firoConfFileName))
        return false;

    try {
        if (fs::is_regular_file(zcoinConfFileName))
            fs::rename(zcoinConfFileName, firoConfFileName);

        try {
            fs::rename(zcoinPath, firoPath);
        }
        catch (const fs::filesystem_error &) {
            // rename config file back
            fs::rename(firoConfFileName, zcoinConfFileName);
            throw;
        }
    }
    catch (const fs::filesystem_error &) {
        return false;
    }

    ClearDatadirCache();
    return true;
}

boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", BITCOIN_PID_FILENAME));
    if (!pathPidFile.is_complete()) pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}

#ifdef ENABLE_CLIENTAPI
/*
 * Creates a ZIP file -
    after specifying an absolute path to a "root" directory, all filepaths derived from this path are stored in the ZIP file,
    with only files and their paths from the root preserved.
    eg. root path:                 /a/b/c/d/
        filepaths(from root path): e/f.txt
                                   g.dat

    paths to folders (again, from a root) can be provided - in this case the method derives all sub-files and adds to "filePaths".
    eg. folder path:  h/i
        derives files: h/i/j.exe
                       h/i/k.o
                       h/i/l/m.jpeg

    Breaking up the root and derived paths allows for easy unzipping from the same directory - the layout is preserved.
*/
bool CreateZipFile (std::string rootPath, std::vector<string> folderPaths, vector<string> filePaths, std::string destinationPath)
{
    zipFile zf = zipOpen(destinationPath.c_str(), APPEND_STATUS_CREATE);
    if (zf == NULL)
        return false;

    BOOST_FOREACH(std::string folderPath, folderPaths){
        boost::filesystem::directory_iterator end_iter;
        std::string fullFolderPath = rootPath + folderPath;
        for (boost::filesystem::directory_iterator dir_iter(fullFolderPath);
        dir_iter != end_iter;
        ++dir_iter)
        {
            std::string fullFolderFilePath = dir_iter->path().string();
            std::string folderFilePath = fullFolderFilePath.substr(rootPath.length());
            filePaths.push_back(folderFilePath);
        }
    }

    bool failed = false;
    BOOST_FOREACH(string filePath, filePaths)
    {
        if(failed){
            break;
        }
        std::string fullPath = rootPath + filePath;
        std::fstream file(fullPath.c_str(), std::ios::binary | std::ios::in);
        if (file.is_open())
        {
            file.seekg(0, std::ios::end);
            long size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<char> buffer(size);
            if (size == 0 || file.read(&buffer[0], size)){
                zip_fileinfo zfi = { 0 };
                if (ZIP_OK == zipOpenNewFileInZip(zf, filePath.c_str(), &zfi, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_DEFAULT_COMPRESSION))
                {
                    if (ZIP_OK != zipWriteInFileInZip(zf, size == 0 ? "" : &buffer[0], size)){
                        failed = true;
                    }

                    if (ZIP_OK != zipCloseFileInZip(zf)){
                        failed = true;
                    }

                    file.close();
                    continue;
                }
            }
            file.close();
        }
        failed = true;
    }

    zipClose(zf, NULL);

    if (failed){
        return false;
    }

    return true;
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try
    {
        return boost::filesystem::create_directory(p);
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE *file)
{
    fflush(file); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(file));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(file), F_FULLFSYNC, 0);
    #else
    fsync(fileno(file));
    #endif
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes
    if (file && boost::filesystem::file_size(pathLog) > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10))
    {
        // Restart the file with some of the end
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != NULL)
        fclose(file);
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void runCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

std::string GetThreadName()
{
    char name[16];
#if defined(PR_GET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_GET_NAME, name, 0, 0, 0);
#elif defined(MAC_OSX)
    pthread_getname_np(pthread_self(), name, 16);
// #elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
// #else
    // no get_name here
#endif
    return std::string(name);
}

void RenameThreadPool(ctpl::thread_pool& tp, const char* baseName)
{
    auto cond = std::make_shared<std::condition_variable>();
    auto mutex = std::make_shared<std::mutex>();
    std::atomic<int> doneCnt(0);
    std::map<int, std::future<void> > futures;

    for (int i = 0; i < tp.size(); i++) {
        futures[i] = tp.push([baseName, i, cond, mutex, &doneCnt](int threadId) {
            RenameThread(strprintf("%s-%d", baseName, i).c_str());
            std::unique_lock<std::mutex> l(*mutex);
            doneCnt++;
            cond->wait(l);
        });
    }

    do {
        // Always sleep to let all threads acquire locks
        MilliSleep(10);
        // `doneCnt` should be at least `futures.size()` if tp size was increased (for whatever reason),
        // or at least `tp.size()` if tp size was decreased and queue was cleared
        // (which can happen on `stop()` if we were not fast enough to get all jobs to their threads).
    } while (doneCnt < futures.size() && doneCnt < tp.size());

    cond->notify_all();

    // Make sure no one is left behind, just in case
    for (auto& pair : futures) {
        auto& f = pair.second;
        if (f.valid() && f.wait_for(std::chrono::milliseconds(2000)) == std::future_status::timeout) {
            LogPrintf("%s: %s-%d timed out\n", __func__, baseName, pair.first);
            // Notify everyone again
            cond->notify_all();
            break;
        }
    }
}

void SetupEnvironment()
{
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void*) == 4) {
        mallopt(M_ARENA_MAX, 1);
    }
#endif
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // boost::filesystem::path, which is then used to explicitly imbue the path.
    std::locale loc = boost::filesystem::path::imbue(std::locale::classic());
    boost::filesystem::path::imbue(loc);
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

void SetThreadPriority(int nPriority)
{
#ifdef WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // WIN32
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif // PRIO_THREAD
#endif // WIN32
}

int GetNumCores()
{
#if BOOST_VERSION >= 105600
    return boost::thread::physical_concurrency();
#else // Must fall back to hardware_concurrency, which unfortunately counts virtual cores
    return boost::thread::hardware_concurrency();
#endif
}

std::string CopyrightHolders(const std::string& strPrefix)
{
    std::string strCopyrightHolders = strPrefix + strprintf(_(COPYRIGHT_HOLDERS), _(COPYRIGHT_HOLDERS_SUBSTITUTION));

    // Check for untranslated substitution to make sure Bitcoin Core copyright is not removed by accident
    if (strprintf(COPYRIGHT_HOLDERS, COPYRIGHT_HOLDERS_SUBSTITUTION).find("Bitcoin Core") == std::string::npos) {
        strCopyrightHolders
                += '\n' + strPrefix + "The Bitcoin Core developers"
                +  '\n' + strPrefix + "The Firo Core developers";
    }
    return strCopyrightHolders;
}
