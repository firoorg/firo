
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "init.h"

#include "addrman.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "compat/sanity.h"
#include "consensus/validation.h"
#include "exodus/exodus.h"
#include "httpserver.h"
#include "httprpc.h"
#include "key.h"
#include "main.h"
#include "zerocoin.h"
#include "miner.h"
#include "net.h"
#include "policy/policy.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "scheduler.h"
#include "timedata.h"
#include "txdb.h"
#include "txmempool.h"
#include "torcontrol.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "validation.h"
#include "mtpstate.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <string.h>
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <boost/optional.hpp>
#include <boost/thread.hpp>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "activeznode.h"
#include "darksend.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "znodeman.h"
#include "znodeconfig.h"
#include "netfulfilledman.h"
#include "flat-database.h"
#include "instantx.h"
#include "spork.h"

#if ENABLE_ZMQ
#include "zmq/zmqnotificationinterface.h"
#endif


bool fFeeEstimatesInitialized = false;
static const bool DEFAULT_PROXYRANDOMIZE = true;
static const bool DEFAULT_REST_ENABLE = false;
static const bool DEFAULT_DISABLE_SAFEMODE = false;
static const bool DEFAULT_STOPAFTERBLOCKIMPORT = false;


#if ENABLE_ZMQ
static CZMQNotificationInterface* pzmqNotificationInterface = NULL;
#endif

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE = 0,
    BF_EXPLICIT = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST = (1U << 2),
};

static const char *FEE_ESTIMATES_FILENAME = "fee_estimates.dat";

extern CTxMemPool stempool;

namespace fs = boost::filesystem;

extern const char tor_git_revision[];
const char tor_git_revision[] = "";


extern "C" {
    int tor_main(int argc, char *argv[]);
    void tor_cleanup(void);
}


static char *convert_str(const std::string &s) {
    char *pc = new char[s.size()+1];
    std::strcpy(pc, s.c_str());
    return pc;
}

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// fRequestShutdown getting set, and then does the normal Qt
// shutdown thing.
//

std::atomic<bool> fRequestShutdown(false);

void StartShutdown() {
    fRequestShutdown = true;
}

bool ShutdownRequested() {
    return fRequestShutdown;
}

/**
 * This is a minimally invasive approach to shutdown on LevelDB read errors from the
 * chainstate, while keeping user interface out of the common library, which is shared
 * between bitcoind, and bitcoin-qt and non-server tools.
*/
class CCoinsViewErrorCatcher : public CCoinsViewBacked {
public:
    CCoinsViewErrorCatcher(CCoinsView *view) : CCoinsViewBacked(view) {}

    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        try {
            return CCoinsViewBacked::GetCoins(txid, coins);
        } catch (const std::runtime_error &e) {
            uiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "",
                                             CClientUIInterface::MSG_ERROR);
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

static CCoinsViewDB *pcoinsdbview = NULL;
static CCoinsViewErrorCatcher *pcoinscatcher = NULL;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle;

void Interrupt(boost::thread_group &threadGroup) {
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    threadGroup.interrupt_all();
}

void Shutdown() {
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff");
    mempool.AddTransactionsUpdated(1);
    // Changes to mempool should also be made to Dandelion stempool
    stempool.AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(false);
#endif
    GenerateBitcoins(false, 0, Params());
    StopNode();

    CFlatDB<CZnodeMan> flatdb1("zncache.dat", "magicZnodeCache");
    flatdb1.Dump(mnodeman);
    CFlatDB<CZnodePayments> flatdb2("znpayments.dat", "magicZnodePaymentsCache");
    flatdb2.Dump(mnpayments);
    CFlatDB<CNetFulfilledRequestManager> flatdb4("netfulfilled.dat", "magicFulfilledCache");
    flatdb4.Dump(netfulfilledman);

    StopTorControl();
    UnregisterNodeSignals(GetNodeSignals());

    if (fFeeEstimatesInitialized) {
        boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            mempool.WriteFeeEstimates(est_fileout);
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(cs_main);
        if (pcoinsTip != NULL) {
            FlushStateToDisk();
        }
        delete pcoinsTip;
        pcoinsTip = NULL;
        delete pcoinscatcher;
        pcoinscatcher = NULL;
        delete pcoinsdbview;
        pcoinsdbview = NULL;
        delete pblocktree;
        pblocktree = NULL;
    }

    if (isExodusEnabled()) {
        exodus_shutdown();
    }

#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(true);
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = NULL;
    }
#endif

#ifndef WIN32
    try {
        boost::filesystem::remove(GetPidFile());
    } catch (const boost::filesystem::filesystem_error &e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces();
#ifdef ENABLE_WALLET
    delete pwalletMain;
    pwalletMain = NULL;
#endif
    globalVerifyHandle.reset();
    ECC_Stop();
    LogPrintf("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */
void HandleSIGTERM(int) {
    fRequestShutdown = true;
}

void HandleSIGHUP(int) {
    fReopenDebugLog = true;
    fReopenExodusLog = true;
}

bool static Bind(const CService &addr, unsigned int flags) {
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) {
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true;
}

void OnRPCStopped() {
    cvBlockChange.notify_all();
    LogPrint("rpc", "RPC stopped.\n");
}

void OnRPCPreCommand(const CRPCCommand &cmd) {
    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) &&
        !cmd.okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);
}

std::string HelpMessage(HelpMessageMode mode) {
    const bool showDebug = GetBoolArg("-help-debug", false);

    // When adding new options to the categories, please keep and ensure alphabetical ordering.
    // Do not translate _(...) -help-debug options, Many technical terms, and only a very small audience, so is unnecessary stress to translators.
    string strUsage = HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("Print this help message and exit"));
    strUsage += HelpMessageOpt("-version", _("Print version and exit"));
    strUsage += HelpMessageOpt("-alertnotify=<cmd>",
                               _("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-blocknotify=<cmd>",
                               _("Execute command when the best block changes (%s in cmd is replaced by block hash)"));
    if (showDebug)
        strUsage += HelpMessageOpt("-blocksonly", strprintf(_("Whether to operate in a blocks only mode (default: %u)"),
                                                            DEFAULT_BLOCKSONLY));
    strUsage += HelpMessageOpt("-checkblocks=<n>",
                               strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"),
                                         DEFAULT_CHECKBLOCKS));
    strUsage += HelpMessageOpt("-checklevel=<n>",
                               strprintf(_("How thorough the block verification of -checkblocks is (0-4, default: %u)"),
                                         DEFAULT_CHECKLEVEL));
    strUsage += HelpMessageOpt("-conf=<file>",
                               strprintf(_("Specify configuration file (default: %s)"), BITCOIN_CONF_FILENAME));
    if (mode == HMM_BITCOIND) {
#ifndef WIN32
        strUsage += HelpMessageOpt("-daemon", _("Run in the background as a daemon and accept commands"));
#endif
    }
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    strUsage += HelpMessageOpt("-dbcache=<n>",
                               strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), nMinDbCache,
                                         nMaxDbCache, nDefaultDbCache));
    if (showDebug)
        strUsage += HelpMessageOpt("-feefilter", strprintf(
                "Tell other nodes to filter invs to us by our mempool min fee (default: %u)", DEFAULT_FEEFILTER));
    strUsage += HelpMessageOpt("-loadblock=<file>", _("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt("-maxorphantx=<n>",
                               strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"),
                                         DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-maxmempool=<n>",
                               strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"),
                                         DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt("-mempoolexpiry=<n>", strprintf(
            _("Do not keep transactions in the mempool longer than <n> hours (default: %u)"), DEFAULT_MEMPOOL_EXPIRY));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(
            _("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
            -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(_("Specify pid file (default: %s)"), BITCOIN_PID_FILENAME));
#endif
    strUsage += HelpMessageOpt("-prune=<n>", strprintf(
            _("Reduce storage requirements by pruning (deleting) old blocks. This mode is incompatible with -txindex and -rescan. "
                      "Warning: Reverting this setting requires re-downloading the entire blockchain. "
                      "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"),
            MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-reindex-chainstate", _("Rebuild chain state from the currently indexed blocks"));
    strUsage += HelpMessageOpt("-reindex", _("Rebuild chain state and block index from the blk*.dat files on disk"));
#ifndef WIN32
    strUsage += HelpMessageOpt("-sysperms",
                               _("Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)"));
#endif
    strUsage += HelpMessageOpt("-txindex", strprintf(
            _("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"),
            DEFAULT_TXINDEX));
    strUsage += HelpMessageOpt("-addressindex", strprintf(_("Maintain a full address index, used to query for the balance, txids and unspent outputs for addresses (default: %u)"), DEFAULT_ADDRESSINDEX));
    strUsage += HelpMessageOpt("-timestampindex", strprintf(_("Maintain a timestamp index for block hashes, used to query blocks hashes by a range of timestamps (default: %u)"), DEFAULT_TIMESTAMPINDEX));
    strUsage += HelpMessageOpt("-spentindex", strprintf(_("Maintain a full spent index, used to query the spending txid and input index for an outpoint (default: %u)"), DEFAULT_SPENTINDEX));

    strUsage += HelpMessageGroup(_("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", _("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-banscore=<n>",
                               strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"),
                                         DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt("-bantime=<n>", strprintf(
            _("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"),
            DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt("-bind=<addr>",
                               _("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-connect=<ip>", _("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-discover",
                               _("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns", _("Allow DNS lookups for -addnode, -seednode and -connect") + " " +
                                       strprintf(_("(default: %u)"), DEFAULT_NAME_LOOKUP));
    strUsage += HelpMessageOpt("-dnsseed",
                               _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", _("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed",
                               strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"),
                                         DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-listen", _("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt("-listenonion", strprintf(_("Automatically create Tor hidden service (default: %d)"),
                                                         DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-maxconnections=<n>",
                               strprintf(_("Maintain at most <n> connections to peers (default: %u)"),
                                         DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-maxreceivebuffer=<n>",
                               strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"),
                                         DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-maxsendbuffer=<n>",
                               strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"),
                                         DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-maxtimeadjustment", strprintf(
            _("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)"),
            DEFAULT_MAX_TIME_ADJUSTMENT));
    strUsage += HelpMessageOpt("-onion=<ip:port>", strprintf(
            _("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-onlynet=<net>", _("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-permitbaremultisig",
                               strprintf(_("Relay non-P2SH multisig (default: %u)"), DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-peerbloomfilters", strprintf(
            _("Support filtering of blocks and transaction with bloom filters (default: %u)"),
            DEFAULT_PEERBLOOMFILTERS));
    strUsage += HelpMessageOpt("-port=<port>",
                               strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"),
                                         Params(CBaseChainParams::MAIN).GetDefaultPort(),
                                         Params(CBaseChainParams::TESTNET).GetDefaultPort()));
    strUsage += HelpMessageOpt("-proxy=<ip:port>", _("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-proxyrandomize", strprintf(
            _("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"),
            DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-rpcserialversion", strprintf(
            _("Sets the serialization of raw transaction or block hex returned in non-verbose mode, non-segwit(0) or segwit(1) (default: %d)"),
            DEFAULT_RPC_SERIALIZE_VERSION));
    strUsage += HelpMessageOpt("-seednode=<ip>", _("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-timeout=<n>",
                               strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"),
                                         DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-torcontrol=<ip>:<port>",
                               strprintf(_("Tor control port to use if onion listening enabled (default: %s)"),
                                         DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-torpassword=<pass>", _("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += HelpMessageOpt("-upnp", _("Use UPnP to map the listening port (default: 1 when listening and no -proxy)"));
#else
    strUsage += HelpMessageOpt("-upnp", strprintf(_("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
    strUsage += HelpMessageOpt("-whitebind=<addr>",
                               _("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-whitelist=<IP address or network>",
                               _("Whitelist peers connecting from the given IP address (e.g. 1.2.3.4) or CIDR notated network (e.g. 1.2.3.0/24). Can be specified multiple times.") +
                               " " +
                               _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));
    strUsage += HelpMessageOpt("-whitelistrelay", strprintf(
            _("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)"),
            DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt("-whitelistforcerelay", strprintf(
            _("Force relay of transactions from whitelisted peers even if they violate local relay policy (default: %d)"),
            DEFAULT_WHITELISTFORCERELAY));
    strUsage += HelpMessageOpt("-maxuploadtarget=<n>", strprintf(
            _("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"),
            DEFAULT_MAX_UPLOAD_TARGET));

#ifdef ENABLE_WALLET
    strUsage += CWallet::GetWalletHelpString(showDebug);
#endif

#if ENABLE_ZMQ
    strUsage += HelpMessageGroup(_("ZeroMQ notification options:"));
    strUsage += HelpMessageOpt("-zmqpubhashblock=<address>", _("Enable publish hash block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubhashtx=<address>", _("Enable publish hash transaction in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawblock=<address>", _("Enable publish raw block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawtx=<address>", _("Enable publish raw transaction in <address>"));
#endif

    strUsage += HelpMessageGroup(_("Debugging/Testing options:"));
    strUsage += HelpMessageOpt("-uacomment=<cmt>", _("Append comment to the user agent string"));
    if (showDebug) {
        strUsage += HelpMessageOpt("-checkblockindex", strprintf(
                "Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. Also sets -checkmempool (default: %u)",
                Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u)",
                                                                  Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkpoints",
                                   strprintf("Disable expensive verification for known chain history (default: %u)",
                                             DEFAULT_CHECKPOINTS_ENABLED));
        strUsage += HelpMessageOpt("-disablesafemode",
                                   strprintf("Disable safemode, override a real safe mode event (default: %u)",
                                             DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-testsafemode", strprintf("Force safe mode (default: %u)", DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-stopafterblockimport",
                                   strprintf("Stop running after importing blocks from disk (default: %u)",
                                             DEFAULT_STOPAFTERBLOCKIMPORT));
        strUsage += HelpMessageOpt("-limitancestorcount=<n>", strprintf(
                "Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)",
                DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt("-limitancestorsize=<n>", strprintf(
                "Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)",
                DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantcount=<n>", strprintf(
                "Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)",
                DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantsize=<n>", strprintf(
                "Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).",
                DEFAULT_DESCENDANT_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-bip9params=deployment:start:end",
                                   "Use given start/end times for specified bip9 deployment (regtest-only)");
    }
    string debugCategories = "addrman, alert, bench, cmpctblock, coindb, db, http, libevent, lock, mempool, mempoolrej, net, proxy, prune, rand, reindex, rpc, selectcoins, tor, zmq"; // Don't translate these and qt below
    if (mode == HMM_BITCOIN_QT)
        debugCategories += ", qt";
    strUsage += HelpMessageOpt("-debug=<category>", strprintf(
            _("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
                                                    _("If <category> is not supplied or if <category> = 1, output all debugging information.") +
                                                    _("<category> can be:") + " " + debugCategories + ".");
    if (showDebug)
        strUsage += HelpMessageOpt("-nodebug", "Turn off debugging messages, same as -debug=0");
    strUsage += HelpMessageOpt("-gen", strprintf(_("Generate coins (default: %u)"), DEFAULT_GENERATE));
    strUsage += HelpMessageOpt("-genproclimit=<n>", strprintf(
            _("Set the number of threads for coin generation if enabled (-1 = all cores, default: %d)"),
            DEFAULT_GENERATE_THREADS));

    strUsage += HelpMessageOpt("-help-debug", _("Show all debugging options (usage: --help -help-debug)"));
    strUsage += HelpMessageOpt("-logips",
                               strprintf(_("Include IP addresses in debug output (default: %u)"), DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt("-logtimestamps", strprintf(_("Prepend debug output with timestamp (default: %u)"),
                                                           DEFAULT_LOGTIMESTAMPS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-logtimemicros",
                                   strprintf("Add microsecond precision to debug timestamps (default: %u)",
                                             DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)");
        strUsage += HelpMessageOpt("-limitfreerelay=<n>", strprintf(
                "Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)",
                DEFAULT_LIMITFREERELAY));
        strUsage += HelpMessageOpt("-relaypriority", strprintf(
                "Require high priority for relaying free or low-fee transactions (default: %u)",
                DEFAULT_RELAYPRIORITY));
        strUsage += HelpMessageOpt("-maxsigcachesize=<n>",
                                   strprintf("Limit size of signature cache to <n> MiB (default: %u)",
                                             DEFAULT_MAX_SIG_CACHE_SIZE));
        strUsage += HelpMessageOpt("-maxtipage=<n>", strprintf(
                "Maximum tip age in seconds to consider node in initial block download (default: %u)",
                DEFAULT_MAX_TIP_AGE));
    }
    strUsage += HelpMessageOpt("-minrelaytxfee=<amt>", strprintf(
            _("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)"),
            CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-maxtxfee=<amt>", strprintf(
            _("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)"),
            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-printtoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug) {
        strUsage += HelpMessageOpt("-printpriority",
                                   strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)",
                                             DEFAULT_PRINTPRIORITY));
    }
    strUsage += HelpMessageOpt("-shrinkdebugfile",
                               _("Shrink debug.log file on client startup (default: 1 when no -debug)"));

    AppendParamsHelpMessages(strUsage, showDebug);

    strUsage += HelpMessageGroup(_("Node relay options:"));
    if (showDebug)
        strUsage += HelpMessageOpt("-acceptnonstdtxn",
                                   strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)",
                                             "testnet/regtest only; ",
                                             !Params(CBaseChainParams::TESTNET).RequireStandard()));
    strUsage += HelpMessageOpt("-bytespersigop", strprintf(
            _("Equivalent bytes per sigop in transactions for relay and mining (default: %u)"),
            DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-datacarrier", strprintf(_("Relay and mine data carrier transactions (default: %u)"),
                                                         DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-datacarriersize", strprintf(
            _("Maximum size of data in data carrier transactions we relay and mine (default: %u)"),
            MAX_OP_RETURN_RELAY));
    strUsage += HelpMessageOpt("-mempoolreplacement",
                               strprintf(_("Enable transaction replacement in the memory pool (default: %u)"),
                                         DEFAULT_ENABLE_REPLACEMENT));

    strUsage += HelpMessageGroup(_("Block creation options:"));
    strUsage += HelpMessageOpt("-blockmaxweight=<n>",
                               strprintf(_("Set maximum BIP141 block weight (default: %d)"), DEFAULT_BLOCK_MAX_WEIGHT));
    strUsage += HelpMessageOpt("-blockmaxsize=<n>",
                               strprintf(_("Set maximum block size in bytes (default: %d)"), DEFAULT_BLOCK_MAX_SIZE));
    strUsage += HelpMessageOpt("-blockprioritysize=<n>", strprintf(
            _("Set maximum size of high-priority/low-fee transactions in bytes (default: %d)"),
            DEFAULT_BLOCK_PRIORITY_SIZE));
    if (showDebug)
        strUsage += HelpMessageOpt("-blockversion=<n>", "Override block version to test forking scenarios");

    strUsage += HelpMessageGroup(_("RPC server options:"));
    strUsage += HelpMessageOpt("-server", _("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt("-rest", strprintf(_("Accept public REST requests (default: %u)"), DEFAULT_REST_ENABLE));
    strUsage += HelpMessageOpt("-rpcbind=<addr>",
                               _("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-rpccookiefile=<loc>", _("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcauth=<userpw>",
                               _("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcport=<port>",
                               strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"),
                                         BaseParams(CBaseChainParams::MAIN).RPCPort(),
                                         BaseParams(CBaseChainParams::TESTNET).RPCPort()));
    strUsage += HelpMessageOpt("-rpcallowip=<ip>",
                               _("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcthreads=<n>",
                               strprintf(_("Set the number of threads to service RPC calls (default: %d)"),
                                         DEFAULT_HTTP_THREADS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>",
                                   strprintf("Set the depth of the work queue to service RPC calls (default: %d)",
                                             DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)",
                                                                      DEFAULT_HTTP_SERVER_TIMEOUT));

        strUsage += HelpMessageOpt("-rpcforceutf8", strprintf("Replace invalid UTF-8 encoded characters with question marks in RPC response (default: %d)", 1));
    }

    strUsage += HelpMessageGroup("Exodus options:");
    strUsage += HelpMessageOpt("-exodus", "Enable Exodus");
    strUsage += HelpMessageOpt("-startclean", "Clear all persistence files on startup; triggers reparsing of Exodus transactions");
    strUsage += HelpMessageOpt("-exodustxcache=<num>", "The maximum number of transactions in the input transaction cache (default: 500000)");
    strUsage += HelpMessageOpt("-exodusprogressfrequency=<seconds>", "Time in seconds after which the initial scanning progress is reported (default: 30)");
    strUsage += HelpMessageOpt("-exodusdebug=<category>", "Enable or disable log categories, can be \"all\" or \"none\"");
    strUsage += HelpMessageOpt("-autocommit=<flag>", "Enable or disable broadcasting of transactions, when creating transactions (default: 1)");
    strUsage += HelpMessageOpt("-overrideforcedshutdown=<flag>", "Disable force shutdown when error (default: 0)");
    strUsage += HelpMessageOpt("-exodusalertallowsender=<addr>", "Whitelist senders of alerts, can be \"any\")");
    strUsage += HelpMessageOpt("-exodusalertignoresender=<addr>", "Ignore senders of alerts");
    strUsage += HelpMessageOpt("-exodusactivationignoresender=<addr>", "Ignore senders of activations");
    strUsage += HelpMessageOpt("-exodusactivationallowsender=<addr>", "Whitelist senders of activations");
    strUsage += HelpMessageOpt("-exodusuiwalletscope=<number>", "Max. transactions to show in trade and transaction history (default: 65535)");
    strUsage += HelpMessageOpt("-exodusshowblockconsensushash=<number>", "Calculate and log the consensus hash for the specified block");

    return strUsage;
}

std::string LicenseInfo() {
    const std::string URL_SOURCE_CODE = "<https://github.com/zcoinofficial/zcoin>";
    const std::string URL_WEBSITE = "<https://zcoin.io/>";
    // todo: remove urls from translations on next change
    return CopyrightHolders(strprintf(_("Copyright (C) %i-%i"), 2009, COPYRIGHT_YEAR) + " ") + "\n" +
           "\n" +
           strprintf(_("Please contribute if you find %s useful. "
                               "Visit %s for further information about the software."),
                     PACKAGE_NAME, URL_WEBSITE) +
           "\n" +
           strprintf(_("The source code is available from %s."),
                     URL_SOURCE_CODE) +
           "\n" +
           "\n" +
           _("This is experimental software.") + "\n" +
           _("Distributed under the MIT software license, see the accompanying file COPYING or <http://www.opensource.org/licenses/mit-license.php>.") +
           "\n" +
           "\n" +
           _("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software written by Eric Young and UPnP software written by Thomas Bernard.") +
           "\n";
}

static void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex) {
    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = GetArg("-blocknotify", "");

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
}

static bool fHaveGenesis = false;
static boost::mutex cs_GenesisWait;
static CConditionVariable condvar_GenesisWait;

static void BlockNotifyGenesisWait(bool, const CBlockIndex *pBlockIndex) {
    if (pBlockIndex != NULL) {
        {
            boost::unique_lock<boost::mutex> lock_GenesisWait(cs_GenesisWait);
            fHaveGenesis = true;
        }
        condvar_GenesisWait.notify_all();
    }
}

struct CImportingNow {
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};


// If we're using -prune with -reindex, then delete block files that will be ignored by the
// reindex.  Since reindexing works by starting at block file 0 and looping until a blockfile
// is missing, do the same here to delete any later block files after a gap.  Also delete all
// rev files since they'll be rewritten by the reindex anyway.  This ensures that vinfoBlockFile
// is in sync with what's actually on disk by the time we start downloading, so that pruning
// works correctly.
void CleanupBlockRevFiles() {
    using namespace boost::filesystem;
    map <string, path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    path blocksdir = GetDataDir() / "blocks";
    for (directory_iterator it(blocksdir); it != directory_iterator(); it++) {
        if (is_regular_file(*it) &&
            it->path().filename().string().length() == 12 &&
            it->path().filename().string().substr(8, 4) == ".dat") {
            if (it->path().filename().string().substr(0, 3) == "blk")
                mapBlockFiles[it->path().filename().string().substr(3, 5)] = it->path();
            else if (it->path().filename().string().substr(0, 3) == "rev")
                remove(it->path());
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist)
    // start removing block files.
    int nContigCounter = 0;
    BOOST_FOREACH(
    const PAIRTYPE(string, path) &item, mapBlockFiles) {
        if (atoi(item.first) == nContigCounter) {
            nContigCounter++;
            continue;
        }
        remove(item.second);
    }
}

void ThreadImport(std::vector <boost::filesystem::path> vImportFiles) {
    const CChainParams &chainparams = Params();
    RenameThread("bitcoin-loadblk");
    CImportingNow imp;
    // -reindex
    if (fReindex) {
        MTPState::GetMTPState()->Reset();
        int nFile = 0;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int) nFile);
            LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        InitBlockIndex(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (boost::filesystem::exists(pathBootstrap)) {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    BOOST_FOREACH(
    const boost::filesystem::path &path, vImportFiles) {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file) {
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) {
        LogPrintf("Failed to connect best block");
        StartShutdown();
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void) {
    if (!ECC_InitSanityCheck()) {
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }
    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    return true;
}

bool AppInitServers(boost::thread_group &threadGroup) {
    RPCServer::OnStopped(&OnRPCStopped);
    RPCServer::OnPreCommand(&OnRPCPreCommand);
    if (!InitHTTPServer())
        return false;
    if (!StartRPC())
        return false;
    if (!StartHTTPRPC())
        return false;
    if (GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST())
        return false;
    if (!StartHTTPServer())
        return false;
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction() {
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (mapArgs.count("-bind")) {
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (mapArgs.count("-whitebind")) {
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }
#include <sys/stat.h>
    if (mapArgs.count("-proxy")) {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (mapArgs.count("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false)) {
        // Rewrite just private keys: rescan to find transactions
        if (SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (GetBoolArg("-zapwallettxes", false)) {
        if (SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode
    if (GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {
        if (SoftSetBoolArg("-whitelistrelay", false))
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
#ifdef ENABLE_WALLET
        if (SoftSetBoolArg("-walletbroadcast", false))
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
#endif
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
        if (SoftSetBoolArg("-whitelistrelay", true))
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }
}

static std::string ResolveErrMsg(const char *const optname, const std::string &strBind) {
    return strprintf(_("Cannot resolve -%s address: '%s'"), optname, strBind);
}




void RunTor(){
	printf("TOR thread started.\n");

	boost::optional < std::string > clientTransportPlugin;
	struct stat sb;
	if ((stat("obfs4proxy", &sb) == 0 && sb.st_mode & S_IXUSR)
			|| !std::system("which obfs4proxy")) {
		clientTransportPlugin = "obfs4 exec obfs4proxy";
	} else if (stat("obfs4proxy.exe", &sb) == 0 && sb.st_mode & S_IXUSR) {
		clientTransportPlugin = "obfs4 exec obfs4proxy.exe";
	}

	fs::path tor_dir = GetDataDir() / "tor";
	fs::create_directory(tor_dir);
	fs::path log_file = tor_dir / "tor.log";

	std::vector < std::string > argv;
	argv.push_back("tor");
	argv.push_back("--Log");
	argv.push_back("notice file " + log_file.string());
	argv.push_back("--SocksPort");
	argv.push_back("9050");
	argv.push_back("--ignore-missing-torrc");
	argv.push_back("-f");
	argv.push_back((tor_dir / "torrc").string());
	argv.push_back("--HiddenServiceDir");
	argv.push_back((tor_dir / "onion").string());
	argv.push_back("--HiddenServicePort");
	argv.push_back("8168");

	if (clientTransportPlugin) {
		printf("Using OBFS4.\n");
		argv.push_back("--ClientTransportPlugin");
		argv.push_back(*clientTransportPlugin);
		argv.push_back("--UseBridges");
		argv.push_back("1");
	} else {
		printf("No OBFS4 found, not using it.\n");
	}

	std::vector<char *> argv_c;
	std::transform(argv.begin(), argv.end(), std::back_inserter(argv_c),
			convert_str);

	tor_main(argv_c.size(), &argv_c[0]);


}


struct event_base *baseTor;
boost::thread torEnabledThread;

static void TorEnabledThread()
{
	RunTor();
    event_base_dispatch(baseTor);
}


void StartTorEnabled(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    assert(!baseTor);
#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif
    baseTor = event_base_new();
    if (!baseTor) {
        LogPrintf("tor: Unable to create event_base\n");
        return;
    }

    torEnabledThread = boost::thread(boost::bind(&TraceThread<void (*)()>, "torcontrol", &TorEnabledThread));
}

void InterruptTorEnabled()
{
    if (baseTor) {
        LogPrintf("tor: Thread interrupt\n");
        event_base_loopbreak(baseTor);
    }
}

void StopTorEnabled()
{
    if (baseTor) {
        torEnabledThread.join();
        event_base_free(baseTor);
        baseTor = 0;
    }
}

void InitLogging() {
    fPrintToConsole = GetBoolArg("-printtoconsole", false);
    fLogTimestamps = GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    fLogTimeMicros = GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    fLogIPs = GetBoolArg("-logips", DEFAULT_LOGIPS);

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    LogPrintf("Zcoin version %s\n", FormatFullVersion());
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(boost::thread_group &threadGroup, CScheduler &scheduler) {
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking())
        return InitError("Initializing networking failed");

#ifndef WIN32
    if (GetBoolArg("-sysperms", false)) {
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false))
            return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
#endif
    } else {
        umask(077);
    }

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif

    // ********************************************************* Step 2: parameter interactions
    const CChainParams &chainparams = Params();

    // also see: InitParameterInteraction()

    // if using block pruning, then disable txindex
    if (GetArg("-prune", 0)) {
        if (GetBoolArg("-txindex", DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
#ifdef ENABLE_WALLET
        if (GetBoolArg("-rescan", false)) {
            return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));
        }
#endif
    }

    // Make sure enough file descriptors are available
    int nBind = std::max(
            (mapMultiArgs.count("-bind") ? mapMultiArgs.at("-bind").size() : 0) +
            (mapMultiArgs.count("-whitebind") ? mapMultiArgs.at("-whitebind").size() : 0), size_t(1));
    int nUserMaxConnections = GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations
    nMaxConnections = std::max(std::min(nMaxConnections, (int) (FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0);
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."),
                              nUserMaxConnections, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = !mapMultiArgs["-debug"].empty();
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
    const vector <string> &categories = mapMultiArgs["-debug"];
    if (GetBoolArg("-nodebug", false) || find(categories.begin(), categories.end(), string("0")) != categories.end())
        fDebug = false;

    // Check for -debugnet
    if (GetBoolArg("-debugnet", false))
        InitWarning(_("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here
    if (mapArgs.count("-socks"))
        return InitError(
                _("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here
    if (GetBoolArg("-tor", false))
        return InitError(_("Unsupported argument -tor found, use -onion."));

    if (GetBoolArg("-benchmark", false))
        InitWarning(_("Unsupported argument -benchmark ignored, use -debug=bench."));

    if (GetBoolArg("-whitelistalwaysrelay", false))
        InitWarning(
                _("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));

    if (mapArgs.count("-blockminsize"))
        InitWarning("Unsupported argument -blockminsize ignored.");

    // Checkmempool and checkblockindex default to true in regtest mode
    int ratio = std::min<int>(std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0),
                              1000000);
    if (ratio != 0) {
        mempool.setSanityCheck(1.0 / ratio);
        // Changes to mempool should also be made to Dandelion stempool
        stempool.setSanityCheck(1.0 / ratio);
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED);

    // mempool AC_CONFIG_SUBDIRSlimits
    int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t nMempoolSizeMin = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    nScriptCheckThreads = GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

    fServer = GetBoolArg("-server", false);

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024;
    if (nSignedPruneTarget < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nSignedPruneTarget;
    if (nPruneTarget) {
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) {
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."),
                                       MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    RegisterAllCoreRPCCommands(tableRPC);
#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false);
    if (!fDisableWallet)
        RegisterWalletRPCCommands(tableRPC);
#endif

    nConnectTimeout = GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (mapArgs.count("-minrelaytxfee")) {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-minrelaytxfee"], n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            return InitError(AmountErrMsg("minrelaytxfee", mapArgs["-minrelaytxfee"]));
    }

    fRequireStandard = !GetBoolArg("-acceptnonstdtxn", !Params().RequireStandard());
    if (Params().RequireStandard() && !fRequireStandard)
        return InitError(
                strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));
    nBytesPerSigOp = GetArg("-bytespersigop", nBytesPerSigOp);

#ifdef ENABLE_WALLET
    if (!CWallet::ParameterInteraction())
        return false;
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
        nLocalServices = ServiceFlags(nLocalServices | NODE_BLOOM);

    if (GetArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) < 0)
        return InitError("rpcserialversion must be non-negative.");

    if (GetArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) > 1)
        return InitError("unknown rpcserialversion requested.");

    nMaxTipAge = GetArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

    fEnableReplacement = GetBoolArg("-mempoolreplacement", DEFAULT_ENABLE_REPLACEMENT);
    if ((!fEnableReplacement) && mapArgs.count("-mempoolreplacement")) {
        // Minimal effort at forwards compatibility
        std::string strReplacementModeList = GetArg("-mempoolreplacement", "");  // default is impossible
        std::vector <std::string> vstrReplacementModes;
        boost::split(vstrReplacementModes, strReplacementModeList, boost::is_any_of(","));
        fEnableReplacement = (std::find(vstrReplacementModes.begin(), vstrReplacementModes.end(), "fee") !=
                              vstrReplacementModes.end());
    }

    if (!mapMultiArgs["-bip9params"].empty()) {
        // Allow overriding bip9 parameters for testing
        if (!Params().MineBlocksOnDemand()) {
            return InitError("BIP9 parameters may only be overridden on regtest.");
        }
        const vector <string> &deployments = mapMultiArgs["-bip9params"];
        for (auto i : deployments) {
            std::vector <std::string> vDeploymentParams;
            boost::split(vDeploymentParams, i, boost::is_any_of(":"));
            if (vDeploymentParams.size() != 3) {
                return InitError("BIP9 parameters malformed, expecting deployment:start:end");
            }
            int64_t nStartTime, nTimeout;
            if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
                return InitError(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
            }
            if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
                return InitError(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
            }
            bool found = false;
            for (int i = 0; i < (int) Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
                if (vDeploymentParams[0].compare(VersionBitsDeploymentInfo[i].name) == 0) {
                    UpdateRegtestBIP9Parameters(Consensus::DeploymentPos(i), nStartTime, nTimeout);
                    found = true;
                    LogPrintf("Setting BIP9 activation parameters for %s to start=%ld, timeout=%ld\n",
                              vDeploymentParams[0], nStartTime, nTimeout);
                    break;
                }
            }
            if (!found) {
                return InitError(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
            }
        }
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    std::string strDataDir = GetDataDir().string();

    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE *file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."),
                                       strDataDir, _(PACKAGE_NAME)));
    } catch (const boost::interprocess::interprocess_exception &e) {
        return InitError(
                strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running.") + " %s.",
                          strDataDir, _(PACKAGE_NAME), e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();

    if (fPrintToDebugLog)
        OpenDebugLog();

	////////////////////////////////////////////////////////////////////// // themis
	// dev::g_logPost = [&](std::string const& s, char const* c) { LogPrintStr(s + '\n', true); };
	dev::g_logPost = [&](std::string const& s, char const* c) { LogPrintStr(s + '\n'); };
	dev::g_logPost(std::string("\n\n\n\n\n\n\n\n\n\n"), NULL);
	//////////////////////////////////////////////////////////////////////

    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", strDataDir);
    LogPrintf("Using config file %s\n", GetConfigFile().string());
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", nMaxConnections, nFD);
    std::ostringstream strErrors;

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads) {
        for (int i = 0; i < nScriptCheckThreads - 1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
    }

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (fServer) {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        if (!AppInitServers(threadGroup))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    int64_t nStart;

    // ********************************************************* Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
    if (!fDisableWallet) {
        if (!CWallet::Verify())
            return false;
    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: network initialization
    LogPrintf("*** Step 6: network initialization");
    RegisterNodeSignals(GetNodeSignals());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector <string> uacomments;
    BOOST_FOREACH(string
    cmt, mapMultiArgs["-uacomment"])
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(
                _("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
                strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(
        const std::string &snet, mapMultiArgs["-onlynet"]) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network) n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    if (mapArgs.count("-whitelist")) {
        BOOST_FOREACH(
        const std::string &net, mapMultiArgs["-whitelist"]) {
            CSubNet subnet(net);
            if (!subnet.IsValid())
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            CNode::AddWhitelistedRange(subnet);
        }
    }

    // start tor
    boost::filesystem::path pathTorSetting = GetDataDir()/"torsetting.dat";
    std::pair<bool,std::string> torEnabledArg = ReadBinaryFileTor(pathTorSetting.string().c_str());
    if(torEnabledArg.second != "" && torEnabledArg.second != "0"){
    	StartTorEnabled(threadGroup, scheduler);
        SetLimited(NET_TOR);
        SetLimited(NET_IPV4);
        SetLimited(NET_IPV6);
        proxyType addrProxy = proxyType(CService("127.0.0.1", 9050),
                        true);
        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetLimited(NET_IPV4, false);
        SetLimited(NET_IPV6, false);
        SetLimited(NET_TOR, false);
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0"){
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetLimited(NET_TOR); // set onions as unreachable
        } else {
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }

    // see Step 2: parameter interactions for more information about these
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);
    fRelayTxes = !GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY);

    bool fBound = false;
    if (fListen) {
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) {
            BOOST_FOREACH(
            const std::string &strBind, mapMultiArgs["-bind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(ResolveErrMsg("bind", strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
            }
            BOOST_FOREACH(
            const std::string &strBind, mapMultiArgs["-whitebind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(ResolveErrMsg("whitebind", strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        } else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
            fBound |= Bind(CService(in6addr_any, GetListenPort()), BF_NONE);
            fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip")) {
        BOOST_FOREACH(const std::string &strAddr, mapMultiArgs["-externalip"]) {
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
                AddLocal(addrLocal, LOCAL_MANUAL);
            else
                return InitError(ResolveErrMsg("externalip", strAddr));
        }
    }

    BOOST_FOREACH(
    const std::string &strDest, mapMultiArgs["-seednode"])
    AddOneShot(strDest);

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    if (mapArgs.count("-maxuploadtarget")) {
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET) * 1024 * 1024);
    }

    // ********************************************************* Step 7: load block chain
    LogPrintf("Step 7: load block chain ************************************\n");
    fReindex = GetBoolArg("-reindex", false);
    bool fReindexChainState = GetBoolArg("-reindex-chainstate", false);

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    boost::filesystem::path blocksDir = GetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir)) {
        boost::filesystem::create_directories(blocksDir);
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) {
            boost::filesystem::path source = GetDataDir() / strprintf("blk%04u.dat", i);
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i - 1);
            try {
                boost::filesystem::create_hard_link(source, dest);
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            } catch (const boost::filesystem::filesystem_error &e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked) {
            fReindex = true;
        }
    }

    // cache size calculations
    int64_t nTotalCache = (GetArg("-dbcache", nDefaultDbCache) << 20);
//    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
//    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greater than nMaxDbcache
    if (nTotalCache < (1 << 22))
        nTotalCache = (1 << 22);
    int64_t nBlockTreeDBCache = nTotalCache / 8;
//    nBlockTreeDBCache = std::min(nBlockTreeDBCache, (GetBoolArg("-txindex", DEFAULT_TXINDEX) ? nMaxBlockDBAndTxIndexCache : nMaxBlockDBCache) << 20);
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", false))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2,
                                    (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
    nCoinDBCache = std::min(nCoinDBCache, nMaxCoinsDBCache << 20); // cap total coins db cache
    nTotalCache -= nCoinDBCache;
//    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache
    nCoinCacheUsage = nTotalCache / 300;
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool fLoaded = false;
    while (!fLoaded) {
        bool fReset = fReindex;
        std::string strLoadError;
        LogPrintf("Loading block index...\n");
        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                LogPrintf("UnloadBlockIndex() \n");
                UnloadBlockIndex();
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);

	            if (!fReindex) {
                    // Check existing block index database version, reindex if needed
                    if (pblocktree->GetBlockIndexVersion() < ZC_ADVANCED_INDEX_VERSION) {
                        LogPrintf("Upgrade to new version of block index required, reindex forced\n");
                        delete pblocktree;
			            fReindex = fReset = true;
                        pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);
		            }
	            }

                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex || fReindexChainState);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);
                LogPrintf("fReindex = %s\n", fReindex);
                if (fReindex) {
                    pblocktree->WriteReindexing(true);
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }
                LogPrintf("LoadBlockIndex...\n");
                if (!LoadBlockIndex()) {
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex(chainparams)) {
                    strLoadError = _("Error initializing block database");
                    break;
                }

				/////////////////////////////////////////////////////////// themis
				if ((GetBoolArg("-dgpstorage", false) && GetBoolArg("-dgpevm", false)) || (!GetBoolArg("-dgpstorage", false) && GetBoolArg("-dgpevm", false)) ||
					(!GetBoolArg("-dgpstorage", false) && !GetBoolArg("-dgpevm", false))) {
					fGettingValuesDGP = true;
				}
				else {
					fGettingValuesDGP = false;
				}

				dev::eth::Ethash::init();
				fs::path themisStateDir = GetDataDir() / "stateThemis";
				bool fStatus = fs::exists(themisStateDir);
				const std::string dirThemis(themisStateDir.string());
				const dev::h256 hashDB(dev::sha3(dev::rlp("")));
				dev::eth::BaseState existsThemisstate = fStatus ? dev::eth::BaseState::PreExisting : dev::eth::BaseState::Empty;
				globalState = std::unique_ptr<ThemisState>(new ThemisState(dev::u256(0), ThemisState::openDB(dirThemis, hashDB, dev::WithExisting::Trust), dirThemis, existsThemisstate));
				dev::eth::ChainParams cp((dev::eth::genesisInfo(dev::eth::Network::themisMainNetwork)));
				globalSealEngine = std::unique_ptr<dev::eth::SealEngineFace>(cp.createSealEngine());

				pstorageresult.reset(new StorageResults(themisStateDir.string()));
				if (fReset) {
					pstorageresult->wipeResults();
				}

				if (chainActive.Tip() != nullptr) {
					globalState->setRoot(uintToh256(chainActive.Tip()->reserved[0]));
					globalState->setRootUTXO(uintToh256(chainActive.Tip()->reserved[1]));
				}
				else {
					globalState->setRoot(dev::sha3(dev::rlp("")));
					globalState->setRootUTXO(uintToh256(chainparams.GenesisBlock().reserved[1]));
					globalState->populateFrom(cp.genesisState);
				}
				globalState->db().commit();
				globalState->dbUtxo().commit();

				fRecordLogOpcodes = GetBoolArg("-record-log-opcodes", false);
				fIsVMlogFile = fs::exists(GetDataDir() / "vmExecLogs.json");

				/*
				// Check for changed -logevents state
				if (fLogEvents != GetBoolArg("-logevents", DEFAULT_LOGEVENTS) && !fLogEvents) {
					strLoadError = _("You need to rebuild the database using -reindex-chainstate to enable -logevents");
					break;
				}

				if (!GetBoolArg("-logevents", DEFAULT_LOGEVENTS))
				{
					pstorageresult->wipeResults();
					pblocktree->WipeHeightIndex();
					fLogEvents = false;
					pblocktree->WriteFlag("logevents", fLogEvents);
				}
				*/

				///////////////////////////////////////////////////////////


                // Check for changed -txindex state
                if (fTxIndex != GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
                    strLoadError = _("You need to rebuild the database using -reindex-chainstate to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode) {
                    strLoadError = _(
                            "You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                if (!fReindex && chainActive.Tip() != NULL) {
                    uiInterface.InitMessage(_("Rewinding blocks..."));
                    if (!RewindBlockIndex(chainparams)) {
                        strLoadError = _(
                                "Unable to rewind the database to a pre-fork state. You will need to redownload the blockchain");
                        break;
                    }
                }

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (fHavePruned && GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP) {
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; only checking available blocks",
                              MIN_BLOCKS_TO_KEEP);
                }

                {
                    LOCK(cs_main);
                    CBlockIndex *tip = chainActive.Tip();
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) {
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                                 "This may be due to your computer's date and time being set incorrectly. "
                                                 "Only rebuild the block database if you are sure that your computer's date and time are correct");
                        break;
                    }
                }
                LogPrintf("CVerifyDB().VerifyDB...\n");
                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                                          GetArg("-checkblocks", DEFAULT_CHECKBLOCKS))) {
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            } catch (const std::exception &e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while (false);

        if (!fLoaded) {
            // first suggest a reindex
            if (!fReset) {
                bool fRet = uiInterface.ThreadSafeQuestion(
                        strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                        strLoadError + ".\nPlease restart with -reindex or -reindex-chainstate to recover.",
                        "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) {
                    fReindex = true;
                    fRequestShutdown = false;
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown) {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;

    // ********************************************************* Step 7.5: load exodus

    if (isExodusEnabled()) {
        if (!fTxIndex) {
            // ask the user if they would like us to modify their config file for them
            std::string msg = _("Disabled transaction index detected.\n\n"
                                "Exodus requires an enabled transaction index. To enable "
                                "transaction indexing, please use the \"-txindex\" option as "
                                "command line argument or add \"txindex=1\" to your client "
                                "configuration file within your data directory.\n\n"
                                "Configuration file"); // allow translation of main text body while still allowing differing config file string
            msg += ": " + GetConfigFile().string() + "\n\n";
            msg += _("Would you like Exodus to attempt to update your configuration file accordingly?");
            bool fRet = uiInterface.ThreadSafeMessageBox(msg, "", CClientUIInterface::MSG_INFORMATION | CClientUIInterface::BTN_OK | CClientUIInterface::MODAL | CClientUIInterface::BTN_ABORT);
            if (fRet) {
                // add txindex=1 to config file in GetConfigFile()
                boost::filesystem::path configPathInfo = GetConfigFile();
                FILE *fp = fopen(configPathInfo.string().c_str(), "at");
                if (!fp) {
                    std::string failMsg = _("Unable to update configuration file at");
                    failMsg += ":\n" + GetConfigFile().string() + "\n\n";
                    failMsg += _("The file may be write protected or you may not have the required permissions to edit it.\n");
                    failMsg += _("Please add txindex=1 to your configuration file manually.\n\nExodus will now shutdown.");
                    return InitError(failMsg);
                }
                fprintf(fp, "\ntxindex=1\n");
                fflush(fp);
                fclose(fp);
                std::string strUpdated = _(
                        "Your configuration file has been updated.\n\n"
                        "Exodus will now shutdown - please restart the client for your new configuration to take effect.");
                uiInterface.ThreadSafeMessageBox(strUpdated, "", CClientUIInterface::MSG_INFORMATION | CClientUIInterface::BTN_OK | CClientUIInterface::MODAL);
                return false;
            } else {
                return InitError(_("Please add txindex=1 to your configuration file manually.\n\nOmni Core will now shutdown."));
            }
        }

        uiInterface.InitMessage(_("Parsing Exodus transactions..."));
        exodus_init();
    }

    // ********************************************************* Step 8: load wallet

#ifdef ENABLE_WALLET
    LogPrintf("Step 8: load wallet ************************************\n");
    if (fDisableWallet) {
        pwalletMain = NULL;
        LogPrintf("Wallet disabled!\n");
    } else {
        CWallet::InitLoadWallet();
        if (!pwalletMain)
            return false;
    }
#else // ENABLE_WALLET
    LogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // Exodus code should be initialized and wallet should now be loaded, perform an initial populate
    if (isExodusEnabled()) {
        CheckWalletUpdate();
    }

    // ********************************************************* Step 9: data directory maintenance
    LogPrintf("Step 9: data directory maintenance **********************\n");
    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode) {
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices = ServiceFlags(nLocalServices & ~NODE_NETWORK);
        if (!fReindex) {
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }

    if (Params().GetConsensus().vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        // Only advertize witness capabilities if they have a reasonable start time.
        // This allows us to have the code merged without a defined softfork, by setting its
        // end time to 0.
        // Note that setting NODE_WITNESS is never required: the only downside from not
        // doing so is that after activation, no upgraded nodes will fetch from you.
        nLocalServices = ServiceFlags(nLocalServices | NODE_WITNESS);
        // Only care about others providing witness capabilities if there is a softfork
        // defined.
        nRelevantServices = ServiceFlags(nRelevantServices | NODE_WITNESS);
    }

    // ********************************************************* Step 10: import blocks

    if (!CheckDiskSpace())
        return false;

    // Either install a handler to notify us when genesis activates, or set fHaveGenesis directly.
    // No locking, as this happens before any background thread is started.
    if (chainActive.Tip() == NULL) {
        uiInterface.NotifyBlockTip.connect(BlockNotifyGenesisWait);
    } else {
        fHaveGenesis = true;
    }

    if (mapArgs.count("-blocknotify"))
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    std::vector <boost::filesystem::path> vImportFiles;
    if (mapArgs.count("-loadblock")) {
        BOOST_FOREACH(
        const std::string &strFile, mapMultiArgs["-loadblock"])
        vImportFiles.push_back(strFile);
    }

    // Temporary measure: refactor and changing data structures needed to fix high stack usage
    boost::thread_attributes threadAttr;
    threadAttr.set_stack_size(4*1024*1024);

    threadGroup.add_thread(new boost::thread(threadAttr, boost::bind(&ThreadImport, vImportFiles)));

    // Wait for genesis block to be processed
    {
        boost::unique_lock<boost::mutex> lock(cs_GenesisWait);
        while (!fHaveGenesis) {
            condvar_GenesisWait.wait(lock);
        }
        uiInterface.NotifyBlockTip.disconnect(BlockNotifyGenesisWait);
    }

    // ********************************************************* Step 11: start node

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    //// debug print
    LogPrintf("mapBlockIndex.size() = %u\n", mapBlockIndex.size());
    LogPrintf("nBestHeight = %d\n", chainActive.Height());
#ifdef ENABLE_WALLET
    LogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    LogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0);
    LogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
#endif

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler);
    // Generate coins in the background
    GenerateBitcoins(GetBoolArg("-gen", DEFAULT_GENERATE), GetArg("-genproclimit", DEFAULT_GENERATE_THREADS),
                     chainparams);

    // ********************************************************* Step 11a: setup PrivateSend
    fZNode = GetBoolArg("-znode", false);

    LogPrintf("fZNode = %s\n", fZNode);
    LogPrintf("znodeConfig.getCount(): %s\n", znodeConfig.getCount());

    if ((fZNode || znodeConfig.getCount() > 0) && !fTxIndex) {
        return InitError("Enabling Znode support requires turning on transaction indexing."
                                 "Please add txindex=1 to your configuration and start with -reindex");
    }

    if (fZNode) {
        LogPrintf("ZNODE:\n");

        if (!GetArg("-znodeaddr", "").empty()) {
            // Hot Znode (either local or remote) should get its address in
            // CActiveZnode::ManageState() automatically and no longer relies on Znodeaddr.
            return InitError(_("znodeaddr option is deprecated. Please use znode.conf to manage your remote znodes."));
        }

        std::string strZnodePrivKey = GetArg("-znodeprivkey", "");
        if (!strZnodePrivKey.empty()) {
            if (!darkSendSigner.GetKeysFromSecret(strZnodePrivKey, activeZnode.keyZnode,
                                                  activeZnode.pubKeyZnode))
                return InitError(_("Invalid znodeprivkey. Please see documentation."));

            LogPrintf("  pubKeyZnode: %s\n", CBitcoinAddress(activeZnode.pubKeyZnode.GetID()).ToString());
        } else {
            return InitError(
                    _("You must specify a znodeprivkey in the configuration. Please see documentation for help."));
        }
    }

    LogPrintf("Using Znode config file %s\n", GetZnodeConfigFile().string());

    if (GetBoolArg("-znconflock", true) && pwalletMain && (znodeConfig.getCount() > 0)) {
        LOCK(pwalletMain->cs_wallet);
        LogPrintf("Locking Znodes:\n");
        uint256 mnTxHash;
        int outputIndex;
        BOOST_FOREACH(CZnodeConfig::CZnodeEntry mne, znodeConfig.getEntries()) {
            mnTxHash.SetHex(mne.getTxHash());
            outputIndex = boost::lexical_cast<unsigned int>(mne.getOutputIndex());
            COutPoint outpoint = COutPoint(mnTxHash, outputIndex);
            // don't lock non-spendable outpoint (i.e. it's already spent or it's not from this wallet at all)
            if (pwalletMain->IsMine(CTxIn(outpoint)) != ISMINE_SPENDABLE) {
                LogPrintf("  %s %s - IS NOT SPENDABLE, was not locked\n", mne.getTxHash(), mne.getOutputIndex());
                continue;
            }
            pwalletMain->LockCoin(outpoint);
            LogPrintf("  %s %s - locked successfully\n", mne.getTxHash(), mne.getOutputIndex());
        }
    }

    nLiquidityProvider = GetArg("-liquidityprovider", nLiquidityProvider);
    nLiquidityProvider = std::min(std::max(nLiquidityProvider, 0), 100);
    darkSendPool.SetMinBlockSpacing(nLiquidityProvider * 15);

    fEnablePrivateSend = false;
//    fEnablePrivateSend = GetBoolArg("-enableprivatesend", 0);
//    fPrivateSendMultiSession = GetBoolArg("-privatesendmultisession", DEFAULT_PRIVATESEND_MULTISESSION);
//    nPrivateSendRounds = GetArg("-privatesendrounds", DEFAULT_PRIVATESEND_ROUNDS);
//    nPrivateSendRounds = std::min(std::max(nPrivateSendRounds, 2), nLiquidityProvider ? 99999 : 16);
//    nPrivateSendAmount = GetArg("-privatesendamount", DEFAULT_PRIVATESEND_AMOUNT);
//    nPrivateSendAmount = std::min(std::max(nPrivateSendAmount, 2), 999999);

    fEnableInstantSend = false;
//    fEnableInstantSend = GetBoolArg("-enableinstantsend", 1);
//    nInstantSendDepth = GetArg("-instantsenddepth", DEFAULT_INSTANTSEND_DEPTH);
//    nInstantSendDepth = std::min(std::max(nInstantSendDepth, 0), 60);

    // lite mode disables all Znode and Darksend related functionality
    fLiteMode = GetBoolArg("-litemode", false);
    if (fZNode && fLiteMode) {
        return InitError("You can not start a znode in litemode");
    }

    LogPrintf("fLiteMode %d\n", fLiteMode);
//    LogPrintf("nInstantSendDepth %d\n", nInstantSendDepth);
//    LogPrintf("PrivateSend rounds %d\n", nPrivateSendRounds);
//    LogPrintf("PrivateSend amount %d\n", nPrivateSendAmount);

    darkSendPool.InitDenominations();

    // ********************************************************* Step 11b: Load cache data

    // LOAD SERIALIZED DAT FILES INTO DATA CACHES FOR INTERNAL USE
    uiInterface.InitMessage(_("Loading znode cache..."));
    CFlatDB<CZnodeMan> flatdb1("zncache.dat", "magicZnodeCache");
    if (!flatdb1.Load(mnodeman)) {
        return InitError("Failed to load znode cache from zncache.dat");
    }

    if (mnodeman.size()) {
        uiInterface.InitMessage(_("Loading Znode payment cache..."));
        CFlatDB<CZnodePayments> flatdb2("znpayments.dat", "magicZnodePaymentsCache");
        if (!flatdb2.Load(mnpayments)) {
            return InitError("Failed to load znode payments cache from znpayments.dat");
        }
    } else {
        uiInterface.InitMessage(_("Znode cache is empty, skipping payments cache..."));
    }

    uiInterface.InitMessage(_("Loading fulfilled requests cache..."));
    CFlatDB<CNetFulfilledRequestManager> flatdb4("netfulfilled.dat", "magicFulfilledCache");
	flatdb4.Load(netfulfilledman);

    // if (!flatdb4.Load(netfulfilledman)) {
    //     LogPrint"Failed to load fulfilled requests cache from netfulfilled.dat");
    // }

    // ********************************************************* Step 11c: update block tip in Dash modules

    // force UpdatedBlockTip to initialize pCurrentBlockIndex for DS, MN payments and budgets
    // but don't call it directly to prevent triggering of other listeners like zmq etc.
    // GetMainSignals().UpdatedBlockTip(chainActive.Tip());
    mnodeman.UpdatedBlockTip(chainActive.Tip());
    darkSendPool.UpdatedBlockTip(chainActive.Tip());
    mnpayments.UpdatedBlockTip(chainActive.Tip());
    znodeSync.UpdatedBlockTip(chainActive.Tip());
    // governance.UpdatedBlockTip(chainActive.Tip());

    // ********************************************************* Step 11d: start dash-privatesend thread

    threadGroup.create_thread(boost::bind(&ThreadCheckDarkSendPool));



    // ********************************************************* Step 12: finished

    SetRPCWarmupFinished();
    uiInterface.InitMessage(_("Done loading"));

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        LogPrintf("Step 12: ReacceptWalletTransactions\n");
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile)));
    }
#endif

    return !fRequestShutdown;
}
