// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "logging.h"

#include "tinyformat.h"
#include "util.h"
#include "utiltime.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <optional>
#include <type_traits>
#include <utility>

const char* const DEFAULT_DEBUGLOGFILE = "debug.log";

bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fNoDebug = false; // Compatibility for https://github.com/firoorg/firo/issues/1011
bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
std::atomic<bool> fReopenDebugLog{false};

namespace {

constexpr auto MAX_USER_SETABLE_SEVERITY_LEVEL{BCLog::Level::Info};

using CategoryMapping = std::pair<std::string_view, BCLog::LogFlags>;

/**
 * Canonical category names. The constexpr table has no destruction-time
 * dependency, so categorized logging remains safe from static destructors.
 */
constexpr std::array<CategoryMapping, 42> LOG_CATEGORIES_BY_STR{{
    {"CDbIndexHelper", BCLog::DBINDEX},
    {"addrman", BCLog::ADDRMAN},
    {"alert", BCLog::ALERT},
    {"bench", BCLog::BENCH},
    {"blockstorage", BCLog::BLOCKSTORAGE},
    {"chainlocks", BCLog::CHAINLOCKS},
    {"cmpctblock", BCLog::CMPCTBLOCK},
    {"coindb", BCLog::COINDB},
    {"db", BCLog::DB},
    {"estimatefee", BCLog::ESTIMATEFEE},
    {"gobject", BCLog::GOBJECT},
    {"http", BCLog::HTTP},
    {"i2p", BCLog::I2P},
    {"instantsend", BCLog::INSTANTSEND},
    {"ipc", BCLog::IPC},
    {"kernel", BCLog::KERNEL},
    {"leveldb", BCLog::LEVELDB},
    {"libevent", BCLog::LIBEVENT},
    {"llmq", BCLog::LLMQ},
    {"llmq-dkg", BCLog::LLMQ_DKG},
    {"llmq-sigs", BCLog::LLMQ_SIGS},
    {"lock", BCLog::LOCK},
    {"mempool", BCLog::MEMPOOL},
    {"mempoolrej", BCLog::MEMPOOLREJ},
    {"mnpayments", BCLog::MNPAYMENTS},
    {"mnsync", BCLog::MNSYNC},
    {"net", BCLog::NET},
    {"privatebroadcast", BCLog::PRIVBROADCAST},
    {"proxy", BCLog::PROXY},
    {"prune", BCLog::PRUNE},
    {"qt", BCLog::QT},
    {"rand", BCLog::RAND},
    {"reindex", BCLog::REINDEX},
    {"rpc", BCLog::RPC},
    {"scan", BCLog::SCAN},
    {"selectcoins", BCLog::SELECTCOINS},
    {"tor", BCLog::TOR},
    {"txpackages", BCLog::TXPACKAGES},
    {"txreconciliation", BCLog::TXRECONCILIATION},
    {"validation", BCLog::VALIDATION},
    {"walletdb", BCLog::WALLETDB},
    {"zmq", BCLog::ZMQ},
}};

/** Historical spellings accepted as aliases of first-class categories. */
constexpr std::array<CategoryMapping, 1> LOG_CATEGORY_ALIASES{{
    {"mempool-reject", BCLog::MEMPOOLREJ},
}};

constexpr bool CategoryMappingsAreUnique()
{
    for (size_t i = 0; i < LOG_CATEGORIES_BY_STR.size(); ++i) {
        for (size_t j = i + 1; j < LOG_CATEGORIES_BY_STR.size(); ++j) {
            if (LOG_CATEGORIES_BY_STR[i].first == LOG_CATEGORIES_BY_STR[j].first ||
                LOG_CATEGORIES_BY_STR[i].second == LOG_CATEGORIES_BY_STR[j].second) {
                return false;
            }
        }
    }
    return true;
}

static_assert(CategoryMappingsAreUnique());
static_assert(std::is_trivially_destructible_v<decltype(LOG_CATEGORIES_BY_STR)>);
static_assert(std::is_trivially_destructible_v<decltype(LOG_CATEGORY_ALIASES)>);

int FileWriteStr(std::string_view str, FILE* file)
{
    return fwrite(str.data(), 1, str.size(), file);
}

size_t BufferedLogUsage(const BCLog::Logger::BufferedLog& entry)
{
    if (entry.legacy) return 0; // Preserve Firo's unbounded legacy startup buffer.
    return sizeof(entry) + entry.str.capacity() + entry.threadname.capacity();
}

std::optional<BCLog::Level> GetLogLevel(std::string_view level)
{
    if (level == "trace") return BCLog::Level::Trace;
    if (level == "debug") return BCLog::Level::Debug;
    if (level == "info") return BCLog::Level::Info;
    if (level == "warning") return BCLog::Level::Warning;
    if (level == "error") return BCLog::Level::Error;
    return std::nullopt;
}

std::string LogCategoryToStr(BCLog::LogFlags category)
{
    if (category == BCLog::ALL) return "all";
    const auto it = std::find_if(LOG_CATEGORIES_BY_STR.begin(), LOG_CATEGORIES_BY_STR.end(),
                                 [category](const CategoryMapping& item) {
                                     return item.second == category;
                                 });
    assert(it != LOG_CATEGORIES_BY_STR.end());
    return it == LOG_CATEGORIES_BY_STR.end() ? "unknown" : std::string(it->first);
}

std::string RemoveLocalPrefix(std::string_view file)
{
    if (file.starts_with("./")) file.remove_prefix(2);
    return std::string(file);
}

} // namespace

BCLog::Logger& LogInstance()
{
    // Intentionally leaked so global destructors can continue logging safely.
    static BCLog::Logger* logger = new BCLog::Logger();
    return *logger;
}

bool GetLogCategory(BCLog::LogFlags& flag, std::string_view category)
{
    if (category.empty() || category == "1" || category == "all") {
        flag = BCLog::ALL;
        return true;
    }

    for (const auto& [name, category_flag] : LOG_CATEGORIES_BY_STR) {
        if (name == category) {
            flag = category_flag;
            return true;
        }
    }
    for (const auto& [name, category_flag] : LOG_CATEGORY_ALIASES) {
        if (name == category) {
            flag = category_flag;
            return true;
        }
    }
    return false;
}

void ConfigureLegacyLogCategories(const std::vector<std::string>& categories,
                                  const std::vector<std::string>& excluded_categories)
{
    auto& logger = LogInstance();
    logger.DisableCategory(BCLog::ALL);
    logger.ClearLegacyCategories();
    fDebug = false;
    fNoDebug = false;

    // Firo historically treats -debug=0/-nodebug as an absolute override,
    // including when other -debug values are present.
    if (std::find(categories.begin(), categories.end(), "0") != categories.end()) {
        fNoDebug = true;
        return;
    }

    // Bitcoin v31.1 processes only values after the last -debug=none.
    auto first = categories.begin();
    const auto last_none = std::find(categories.rbegin(), categories.rend(), "none");
    if (last_none != categories.rend()) first = last_none.base();

    for (auto it = first; it != categories.end(); ++it) {
        fDebug = true;
        if (!logger.EnableCategory(*it)) logger.EnableLegacyCategory(*it);
    }

    // Exclusions always take precedence over enabled categories. Unknown
    // strings are retained for out-of-tree legacy callers.
    for (const auto& category : excluded_categories) {
        if (!logger.DisableCategory(category)) logger.DisableLegacyCategory(category);
    }
}

namespace BCLog {

std::string LogEscapeMessage(std::string_view str)
{
    std::string result;
    result.reserve(str.size());
    for (char input : str) {
        const uint8_t ch = static_cast<uint8_t>(input);
        if ((ch >= 32 || ch == '\n') && ch != 0x7f) {
            result += input;
        } else {
            result += strprintf("\\x%02x", ch);
        }
    }
    return result;
}

LogRateLimiter::LogRateLimiter(uint64_t max_bytes, std::chrono::seconds reset_window)
    : m_max_bytes(max_bytes), m_reset_window(reset_window)
{
}

std::shared_ptr<LogRateLimiter> LogRateLimiter::Create(
    SchedulerFunction&& scheduler_func, uint64_t max_bytes,
    std::chrono::seconds reset_window)
{
    auto limiter = std::shared_ptr<LogRateLimiter>(new LogRateLimiter(max_bytes, reset_window));
    std::weak_ptr<LogRateLimiter> weak_limiter{limiter};
    scheduler_func(
        [weak_limiter] {
            if (auto shared_limiter = weak_limiter.lock()) shared_limiter->Reset();
        },
        std::chrono::duration_cast<std::chrono::milliseconds>(reset_window));
    return limiter;
}

LogRateLimiter::Status LogRateLimiter::Consume(const SourceLocation& source_loc,
                                               const std::string& str)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& stats = m_source_locations.try_emplace(source_loc, m_max_bytes).first->second;
    Status status = stats.m_dropped_bytes > 0 ? Status::STILL_SUPPRESSED : Status::UNSUPPRESSED;
    if (!stats.Consume(str.size()) && status == Status::UNSUPPRESSED) {
        status = Status::NEWLY_SUPPRESSED;
        m_suppression_active = true;
    }
    return status;
}

void LogRateLimiter::Reset()
{
    decltype(m_source_locations) source_locations;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        source_locations.swap(m_source_locations);
        m_suppression_active = false;
    }

    for (const auto& [source_loc, stats] : source_locations) {
        if (stats.m_dropped_bytes == 0) continue;
        LogPrintLevel_(
            LogFlags::ALL, Level::Warning, false,
            "Restarting logging from %s:%d (%s): %d bytes were dropped during the last %ss.",
            std::string(source_loc.file_name()), source_loc.line(),
            std::string(source_loc.function_name_short()), stats.m_dropped_bytes,
            m_reset_window.count());
    }
}

bool LogRateLimiter::Stats::Consume(uint64_t bytes)
{
    if (bytes > m_available_bytes) {
        m_dropped_bytes += bytes;
        m_available_bytes = 0;
        return false;
    }
    m_available_bytes -= bytes;
    return true;
}

bool Logger::Enabled() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_buffering || m_print_to_console || m_print_to_file || !m_print_callbacks.empty();
}

std::list<std::function<void(const std::string&)>>::iterator
Logger::PushBackCallback(std::function<void(const std::string&)> callback)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_print_callbacks.push_back(std::move(callback));
    return --m_print_callbacks.end();
}

void Logger::DeleteCallback(std::list<std::function<void(const std::string&)>>::iterator it)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_print_callbacks.erase(it);
}

size_t Logger::NumConnections() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_print_callbacks.size();
}

std::string Logger::LogTimestampStr(int64_t time_micros) const
{
    if (!m_log_timestamps) return {};

    std::string timestamp = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", time_micros / 1000000);
    if (m_log_time_micros) timestamp += strprintf(".%06d", time_micros % 1000000);
    timestamp += ' ';
    return timestamp;
}

std::string Logger::GetLogPrefix(LogFlags category, Level level) const
{
    if (category == NONE) category = ALL;
    const bool has_category = m_always_print_category_level || category != ALL;
    if (!has_category && level == Level::Info) return {};

    std::string result{"["};
    if (has_category) result += LogCategoryToStr(category);
    if (m_always_print_category_level || !has_category || level != Level::Debug) {
        if (has_category) result += ':';
        result += LogLevelToStr(level);
    }
    result += "] ";
    return result;
}

void Logger::FormatLogStrInPlace(std::string& str, LogFlags category, Level level,
                                 const SourceLocation& source_loc,
                                 std::string_view threadname, int64_t time_micros) const
{
    if (!str.ends_with('\n')) str.push_back('\n');
    str.insert(0, GetLogPrefix(category, level));
    if (m_log_sourcelocations) {
        str.insert(0, strprintf("[%s:%d] [%s] ", RemoveLocalPrefix(source_loc.file_name()),
                               source_loc.line(), std::string(source_loc.function_name_short())));
    }
    if (m_log_threadnames) {
        str.insert(0, strprintf("[%s] ", threadname.empty() ? "unknown" : std::string(threadname)));
    }
    str.insert(0, LogTimestampStr(time_micros));
}

void Logger::FormatLegacyLogStrInPlace(std::string& str, int64_t time_micros,
                                       const SourceLocation* source_loc,
                                       LogFlags category, std::string_view category_name,
                                       Level level, bool contextual)
{
    // This intentionally mirrors Firo's original partial-line timestamp behavior.
    const bool modern_prefix = contextual &&
        (m_log_threadnames || m_log_sourcelocations || m_always_print_category_level);
    if (!m_log_timestamps && !modern_prefix) return;

    if (m_legacy_started_new_line) {
        std::string prefix = LogTimestampStr(time_micros);
        if (contextual && m_log_threadnames) {
            const std::string threadname = GetThreadName();
            prefix += strprintf("[%s] ", threadname.empty() ? "unknown" : threadname);
        }
        if (contextual && m_log_sourcelocations && source_loc) {
            prefix += strprintf("[%s:%d] [%s] ", RemoveLocalPrefix(source_loc->file_name()),
                                source_loc->line(),
                                std::string(source_loc->function_name_short()));
        }
        if (contextual && m_always_print_category_level) {
            if (!category_name.empty() && category != ALL) {
                prefix += strprintf("[%s:%s] ", std::string(category_name),
                                    LogLevelToStr(level));
            } else {
                prefix += GetLogPrefix(category, level);
            }
        }
        str.insert(0, prefix);
    }

    m_legacy_started_new_line = !str.empty() && str.back() == '\n';
}

bool Logger::StartLogging()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    assert(m_buffering);
    assert(m_fileout == nullptr);

    if (m_print_to_file) {
        if (m_file_path.empty()) return false;
        m_fileout = fsbridge::fopen(m_file_path, "a");
        if (!m_fileout) return false;
        setbuf(m_fileout, nullptr);
    }

    m_buffering = false;
    if (m_buffer_lines_discarded > 0) {
        LogPrintStr_(strprintf("Early logging buffer overflowed, %d log lines discarded.\n",
                              m_buffer_lines_discarded),
                     SourceLocation{__func__}, ALL, Level::Info, false);
    }

    while (!m_msgs_before_open.empty()) {
        BufferedLog entry = std::move(m_msgs_before_open.front());
        m_msgs_before_open.pop_front();
        m_cur_buffer_memusage -= std::min(m_cur_buffer_memusage, BufferedLogUsage(entry));

        std::string str = std::move(entry.str);
        if (!entry.legacy) {
            FormatLogStrInPlace(str, entry.category, entry.level, entry.source_loc,
                                entry.threadname, entry.time_micros);
            if (m_print_to_console) fwrite(str.data(), 1, str.size(), stdout);
        }
        // Legacy messages were buffered only for debug.log, even if console
        // output is enabled by the time OpenDebugLog() is called.
        if (m_print_to_file && m_fileout) FileWriteStr(str, m_fileout);
        for (const auto& callback : m_print_callbacks) callback(str);
    }

    m_cur_buffer_memusage = 0;
    if (m_print_to_console) fflush(stdout);
    return true;
}

void Logger::DisconnectTestLogger()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_buffering = true;
    if (m_fileout) fclose(m_fileout);
    m_fileout = nullptr;
    m_print_callbacks.clear();
    m_max_buffer_memusage = DEFAULT_MAX_LOG_BUFFER;
    m_cur_buffer_memusage = 0;
    m_buffer_lines_discarded = 0;
    m_msgs_before_open.clear();
    m_legacy_started_new_line = true;
}

void Logger::DisableLogging()
{
    m_print_to_file = false;
    m_print_to_console = false;
    StartLogging();
}

bool Logger::ReopenFile()
{
    if (!m_reopen_file.exchange(false)) return true;
    if (m_file_path.empty()) return false;

    FILE* new_file = fsbridge::fopen(m_file_path, "a");
    if (!new_file) return false;
    setbuf(new_file, nullptr);
    if (m_fileout) fclose(m_fileout);
    m_fileout = new_file;
    return true;
}

void Logger::LogPrintStr(std::string_view str, SourceLocation&& source_loc,
                         LogFlags category, Level level, bool should_ratelimit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    LogPrintStr_(str, std::move(source_loc), category, level, should_ratelimit);
}

void Logger::LogPrintStr_(std::string_view str, SourceLocation&& source_loc,
                          LogFlags category, Level level, bool should_ratelimit)
{
    if (fNoDebug && level != Level::Error && !str.starts_with("ERROR:")) return;

    std::string escaped = LogEscapeMessage(str);
    if (m_buffering) {
        BufferedLog entry{
            GetLogTimeMicros(),
            std::move(escaped),
            GetThreadName(),
            std::move(source_loc),
            category,
            level,
            false,
        };
        m_cur_buffer_memusage += BufferedLogUsage(entry);
        m_msgs_before_open.push_back(std::move(entry));
        while (m_cur_buffer_memusage > m_max_buffer_memusage && !m_msgs_before_open.empty()) {
            const size_t usage = BufferedLogUsage(m_msgs_before_open.front());
            if (usage == 0) {
                // Never discard a legacy compatibility message.
                auto first_modern = std::find_if(m_msgs_before_open.begin(), m_msgs_before_open.end(),
                                                 [](const BufferedLog& item) { return !item.legacy; });
                if (first_modern == m_msgs_before_open.end()) break;
                m_cur_buffer_memusage -= std::min(m_cur_buffer_memusage, BufferedLogUsage(*first_modern));
                m_msgs_before_open.erase(first_modern);
            } else {
                m_cur_buffer_memusage -= std::min(m_cur_buffer_memusage, usage);
                m_msgs_before_open.pop_front();
            }
            ++m_buffer_lines_discarded;
        }
        return;
    }

    FormatLogStrInPlace(escaped, category, level, source_loc, GetThreadName(), GetLogTimeMicros());

    const bool suppress_file = ApplyRateLimiting(escaped, source_loc, should_ratelimit);

    if (m_print_to_console) {
        fwrite(escaped.data(), 1, escaped.size(), stdout);
        fflush(stdout);
    }
    for (const auto& callback : m_print_callbacks) callback(escaped);
    if (m_print_to_file && !suppress_file && m_fileout) {
        ReopenFile();
        if (m_fileout) FileWriteStr(escaped, m_fileout);
    }
}

bool Logger::ApplyRateLimiting(std::string& str, const SourceLocation& source_loc,
                               bool should_ratelimit)
{
    bool suppress_file = false;
    if (should_ratelimit && m_limiter) {
        const auto status = m_limiter->Consume(source_loc, str);
        if (status == LogRateLimiter::Status::NEWLY_SUPPRESSED) {
            LogPrintStr_(
                strprintf("Excessive logging detected from %s:%d (%s): >%d bytes logged during "
                          "the last time window of %is. Suppressing logging to disk from this "
                          "source location until the window resets. Console logging unaffected. "
                          "Last log entry.",
                          std::string(source_loc.file_name()), source_loc.line(),
                          std::string(source_loc.function_name_short()), m_limiter->m_max_bytes,
                          m_limiter->m_reset_window.count()),
                SourceLocation{__func__}, ALL, Level::Warning, false);
        } else if (status == LogRateLimiter::Status::STILL_SUPPRESSED) {
            suppress_file = true;
        }
    }

    if (m_limiter && m_limiter->SuppressionsActive()) str.insert(0, "[*] ");
    return suppress_file;
}

int Logger::LogPrintLegacy(const std::string& str, const SourceLocation* source_loc,
                           LogFlags category, std::string_view category_name,
                           Level level, bool should_ratelimit)
{
    if (fNoDebug && !std::string_view(str).starts_with("ERROR:")) return 0;

    std::lock_guard<std::mutex> lock(m_mutex);
    std::string formatted = str;
    const bool contextual = source_loc != nullptr;
    FormatLegacyLogStrInPlace(formatted, GetLogTimeMicros(), source_loc, category,
                              category_name, level, contextual);

    int result = 0;
    if (m_print_to_console) {
        if (source_loc) ApplyRateLimiting(formatted, *source_loc, false);
        result = FileWriteStr(formatted, stdout);
        fflush(stdout);
        for (const auto& callback : m_print_callbacks) callback(formatted);
    } else if (m_print_to_file) {
        if (m_buffering) {
            result = formatted.size();
            m_msgs_before_open.push_back(BufferedLog{
                GetLogTimeMicros(), std::move(formatted), {}, SourceLocation{__func__},
                ALL, Level::Info, true});
        } else if (m_fileout) {
            const SourceLocation direct_source{__func__};
            const SourceLocation& rate_source = source_loc ? *source_loc : direct_source;
            const bool suppress_file = ApplyRateLimiting(
                formatted, rate_source, contextual && should_ratelimit);
            if (!suppress_file) {
                ReopenFile();
                if (m_fileout) result = FileWriteStr(formatted, m_fileout);
            }
            for (const auto& callback : m_print_callbacks) callback(formatted);
        }
    } else if (!m_buffering) {
        if (source_loc) ApplyRateLimiting(formatted, *source_loc, false);
        for (const auto& callback : m_print_callbacks) callback(formatted);
    }
    return result;
}

void Logger::SetRateLimiting(std::shared_ptr<LogRateLimiter> limiter)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_limiter = std::move(limiter);
}

std::unordered_map<LogFlags, Level> Logger::CategoryLevels() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_category_log_levels;
}

void Logger::SetCategoryLogLevel(const std::unordered_map<LogFlags, Level>& levels)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_category_log_levels = levels;
    m_legacy_category_log_levels.clear();
}

void Logger::AddCategoryLogLevel(LogFlags category, Level level)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_category_log_levels[category] = level;
}

bool Logger::SetCategoryLogLevel(std::string_view category, std::string_view level)
{
    LogFlags flag;
    const auto parsed_level = GetLogLevel(level);
    if (!parsed_level || *parsed_level > MAX_USER_SETABLE_SEVERITY_LEVEL) {
        return false;
    }
    if (GetLogCategory(flag, category)) {
        AddCategoryLogLevel(flag, *parsed_level);
    } else {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_legacy_category_log_levels[std::string(category)] = *parsed_level;
    }
    return true;
}

bool Logger::SetLogLevel(std::string_view level)
{
    const auto parsed_level = GetLogLevel(level);
    if (!parsed_level || *parsed_level > MAX_USER_SETABLE_SEVERITY_LEVEL) return false;
    m_log_level = *parsed_level;
    return true;
}

void Logger::EnableCategory(LogFlags flag)
{
    m_categories.fetch_or(static_cast<CategoryMask>(flag));
}

bool Logger::EnableCategory(std::string_view category)
{
    LogFlags flag;
    if (!GetLogCategory(flag, category)) return false;
    EnableCategory(flag);
    return true;
}

void Logger::DisableCategory(LogFlags flag)
{
    m_categories.fetch_and(~static_cast<CategoryMask>(flag));
}

bool Logger::DisableCategory(std::string_view category)
{
    LogFlags flag;
    if (!GetLogCategory(flag, category)) return false;
    DisableCategory(flag);
    return true;
}

void Logger::EnableLegacyCategory(std::string_view category)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_legacy_excluded_categories.erase(std::string(category));
    m_legacy_categories.emplace(category);
}

void Logger::DisableLegacyCategory(std::string_view category)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_legacy_categories.erase(std::string(category));
    m_legacy_excluded_categories.emplace(category);
}

void Logger::ClearLegacyCategories()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_legacy_categories.clear();
    m_legacy_excluded_categories.clear();
    m_legacy_category_log_levels.clear();
}

bool Logger::LegacyCategoryEnabled(std::string_view category) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_legacy_excluded_categories.count(std::string(category)) != 0) return false;
    if (m_categories.load(std::memory_order_relaxed) == static_cast<CategoryMask>(ALL)) return true;
    return m_legacy_categories.count(std::string(category)) != 0;
}

bool Logger::WillLogLegacyCategoryLevel(std::string_view category, Level level) const
{
    if (level >= Level::Info) return true;
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string category_string{category};
    if (m_legacy_excluded_categories.count(category_string) != 0) return false;
    if (m_categories.load(std::memory_order_relaxed) != static_cast<CategoryMask>(ALL) &&
        m_legacy_categories.count(category_string) == 0) {
        return false;
    }
    const auto it = m_legacy_category_log_levels.find(category_string);
    return level >= (it == m_legacy_category_log_levels.end() ? LogLevel() : it->second);
}

bool Logger::WillLogCategory(LogFlags category) const
{
    return (m_categories.load(std::memory_order_relaxed) & static_cast<CategoryMask>(category)) != 0;
}

bool Logger::WillLogCategoryLevel(LogFlags category, Level level) const
{
    if (level >= Level::Info) return true;
    if (!WillLogCategory(category)) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_category_log_levels.find(category);
    return level >= (it == m_category_log_levels.end() ? LogLevel() : it->second);
}

std::vector<LogCategory> Logger::LogCategoriesList() const
{
    std::vector<LogCategory> result;
    result.reserve(LOG_CATEGORIES_BY_STR.size());
    for (const auto& [category, flag] : LOG_CATEGORIES_BY_STR) {
        result.push_back(LogCategory{std::string(category), WillLogCategory(flag)});
    }
    return result;
}

std::string Logger::LogCategoriesString() const
{
    std::string result;
    for (const auto& category : LogCategoriesList()) {
        if (!result.empty()) result += ", ";
        result += category.category;
    }
    return result;
}

std::string Logger::LogLevelsString() const
{
    return "info, debug, trace";
}

std::string Logger::LogLevelToStr(Level level)
{
    switch (level) {
    case Level::Trace: return "trace";
    case Level::Debug: return "debug";
    case Level::Info: return "info";
    case Level::Warning: return "warning";
    case Level::Error: return "error";
    }
    assert(false);
    return "unknown";
}

bool Logger::DefaultShrinkDebugFile() const
{
    return m_categories.load() == NONE;
}

void Logger::ShrinkDebugFile()
{
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;
    assert(!m_file_path.empty());

    FILE* file = fsbridge::fopen(m_file_path, "r");
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (const fs::filesystem_error&) {
    }

    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10)) {
        std::vector<char> data(RECENT_DEBUG_HISTORY_SIZE, 0);
        if (fseek(file, -static_cast<long>(data.size()), SEEK_END)) {
            LogWarning("Failed to shrink debug log file: fseek(...) failed");
            fclose(file);
            return;
        }
        const int bytes = fread(data.data(), 1, data.size(), file);
        fclose(file);

        file = fsbridge::fopen(m_file_path, "w");
        if (file) {
            fwrite(data.data(), 1, bytes, file);
            fclose(file);
        }
    } else if (file) {
        fclose(file);
    }
}

} // namespace BCLog

bool LogAcceptCategory(const char* category, BCLog::Level level)
{
    if (category == nullptr) return true;
    if (!fDebug) return false;

    BCLog::LogFlags flag;
    if (GetLogCategory(flag, category)) return LogInstance().WillLogCategoryLevel(flag, level);
    return LogInstance().WillLogLegacyCategoryLevel(category, level);
}

int LogPrintStr(const std::string& str)
{
    return LogInstance().LogPrintLegacy(str);
}

int LogPrintCategory(const char* category, const std::string& str,
                     SourceLocation&& source_loc)
{
    BCLog::LogFlags flag{BCLog::ALL};
    const std::string_view category_name = category ? std::string_view(category) : std::string_view{};
    GetLogCategory(flag, category_name);
    return LogInstance().LogPrintLegacy(str, &source_loc, flag, category_name,
                                        BCLog::Level::Debug, false);
}

int LogPrintCategory(BCLog::LogFlags category, const std::string& str,
                     SourceLocation&& source_loc)
{
    return LogInstance().LogPrintLegacy(str, &source_loc, category, {},
                                        BCLog::Level::Debug, false);
}

int LogPrintfCompat(const std::string& str, SourceLocation&& source_loc)
{
    return LogInstance().LogPrintLegacy(str, &source_loc, BCLog::ALL, {},
                                        BCLog::Level::Info, true);
}

bool OpenDebugLog()
{
    auto& logger = LogInstance();
    if (logger.m_file_path.empty()) logger.m_file_path = GetDataDir() / DEFAULT_DEBUGLOGFILE;
    return logger.StartLogging();
}

void ShrinkDebugFile()
{
    auto& logger = LogInstance();
    if (logger.m_file_path.empty()) logger.m_file_path = GetDataDir() / DEFAULT_DEBUGLOGFILE;
    logger.ShrinkDebugFile();
}

bool util::log::ShouldLog(Category category, Level level)
{
    return LogInstance().WillLogCategoryLevel(static_cast<BCLog::LogFlags>(category), level);
}

void util::log::Log(Entry entry)
{
    auto& logger = LogInstance();
    if (!logger.Enabled()) return;
    logger.LogPrintStr(std::move(entry.message), std::move(entry.source_loc),
                       static_cast<BCLog::LogFlags>(entry.category), entry.level,
                       entry.should_ratelimit);
}
