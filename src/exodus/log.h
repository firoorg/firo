#ifndef ELYSIUM_LOG_H
#define ELYSIUM_LOG_H

#include "util.h"
#include "tinyformat.h"

#include <string>

/** Prints to the log file. */
int LogFilePrint(const std::string& str);

/** Determine whether to override compiled debug levels. */
void InitDebugLogLevels();

/** Scrolls log file, if it's getting too big. */
void ShrinkDebugLog();

// Debug flags
extern bool exodus_debug_parser_data;
extern bool exodus_debug_parser_readonly;
extern bool exodus_debug_parser_dex;
extern bool exodus_debug_parser;
extern bool exodus_debug_verbose;
extern bool exodus_debug_verbose2;
extern bool exodus_debug_verbose3;
extern bool exodus_debug_vin;
extern bool exodus_debug_script;
extern bool exodus_debug_dex;
extern bool exodus_debug_send;
extern bool exodus_debug_tokens;
extern bool exodus_debug_spec;
extern bool exodus_debug_exo;
extern bool exodus_debug_tally;
extern bool exodus_debug_sp;
extern bool exodus_debug_sto;
extern bool exodus_debug_txdb;
extern bool exodus_debug_tradedb;
extern bool exodus_debug_persistence;
extern bool exodus_debug_ui;
extern bool exodus_debug_pending;
extern bool exodus_debug_metadex1;
extern bool exodus_debug_metadex2;
extern bool exodus_debug_metadex3;
extern bool exodus_debug_packets;
extern bool exodus_debug_packets_readonly;
extern bool exodus_debug_walletcache;
extern bool exodus_debug_consensus_hash;
extern bool exodus_debug_consensus_hash_every_block;
extern bool exodus_debug_alerts;
extern bool exodus_debug_consensus_hash_every_transaction;
extern bool exodus_debug_fees;

/* When we switch to C++11, this can be switched to variadic templates instead
 * of this macro-based construction (see tinyformat.h).
 */
#define MAKE_ELYSIUM_ERROR_AND_LOG_FUNC(n)                                    \
    template<TINYFORMAT_ARGTYPES(n)>                                            \
    static inline int PrintToLog(const char* format, TINYFORMAT_VARARGS(n))     \
    {                                                                           \
        return LogFilePrint(tfm::format(format, TINYFORMAT_PASSARGS(n)));       \
    }                                                                           \
    template<TINYFORMAT_ARGTYPES(n)>                                            \
    static inline int PrintToLog(TINYFORMAT_VARARGS(n))                         \
    {                                                                           \
        return LogFilePrint(tfm::format("%s", TINYFORMAT_PASSARGS(n)));         \
    }

TINYFORMAT_FOREACH_ARGNUM(MAKE_ELYSIUM_ERROR_AND_LOG_FUNC)

#undef MAKE_ELYSIUM_ERROR_AND_LOG_FUNC


#endif // ELYSIUM_LOG_H
