// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include "fs.h"
#include "logging/categories.h"
#include "util/log.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

static constexpr bool DEFAULT_LOGTIMEMICROS = false;
static constexpr bool DEFAULT_LOGIPS = false;
static constexpr bool DEFAULT_LOGTIMESTAMPS = true;
static constexpr bool DEFAULT_LOGTHREADNAMES = false;
static constexpr bool DEFAULT_LOGSOURCELOCATIONS = false;
static constexpr bool DEFAULT_LOGLEVELALWAYS = false;
extern const char* const DEFAULT_DEBUGLOGFILE;

// Compatibility globals used throughout Firo. Logger members below alias these
// values, so either interface can configure the same logger.
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;
extern bool fNoDebug;
extern bool fLogTimestamps;
extern bool fLogTimeMicros;
extern bool fLogIPs;
extern std::atomic<bool> fReopenDebugLog;

struct SourceLocationEqual {
    bool operator()(const SourceLocation& lhs, const SourceLocation& rhs) const noexcept
    {
        return lhs.line() == rhs.line() && lhs.file_name() == rhs.file_name();
    }
};

struct SourceLocationHasher {
    size_t operator()(const SourceLocation& location) const noexcept
    {
        const size_t file_hash = std::hash<std::string_view>{}(location.file_name());
        const size_t line_hash = std::hash<std::uint_least32_t>{}(location.line());
        return file_hash ^ (line_hash + 0x9e3779b9 + (file_hash << 6) + (file_hash >> 2));
    }
};

struct LogCategory {
    std::string category;
    bool active;
};

namespace BCLog {

inline constexpr Level DEFAULT_LOG_LEVEL{Level::Debug};
inline constexpr size_t DEFAULT_MAX_LOG_BUFFER{1'000'000};
inline constexpr uint64_t RATELIMIT_MAX_BYTES{1024 * 1024};
inline constexpr auto RATELIMIT_WINDOW{std::chrono::hours{1}};
inline constexpr bool DEFAULT_LOGRATELIMIT{true};

std::string LogEscapeMessage(std::string_view str);

class LogRateLimiter
{
public:
    struct Stats {
        uint64_t m_available_bytes;
        uint64_t m_dropped_bytes{0};

        explicit Stats(uint64_t max_bytes) : m_available_bytes(max_bytes) {}
        bool Consume(uint64_t bytes);
    };

    using SchedulerFunction =
        std::function<void(std::function<void()>, std::chrono::milliseconds)>;

    static std::shared_ptr<LogRateLimiter> Create(
        SchedulerFunction&& scheduler_func, uint64_t max_bytes,
        std::chrono::seconds reset_window);

    const uint64_t m_max_bytes;
    const std::chrono::seconds m_reset_window;

    enum class Status {
        UNSUPPRESSED,
        NEWLY_SUPPRESSED,
        STILL_SUPPRESSED,
    };

    Status Consume(const SourceLocation& source_loc, const std::string& str);
    void Reset();
    bool SuppressionsActive() const { return m_suppression_active.load(); }

private:
    LogRateLimiter(uint64_t max_bytes, std::chrono::seconds reset_window);

    mutable std::mutex m_mutex;
    std::unordered_map<SourceLocation, Stats, SourceLocationHasher, SourceLocationEqual>
        m_source_locations;
    std::atomic<bool> m_suppression_active{false};
};

class Logger
{
public:
    struct BufferedLog {
        int64_t time_micros;
        std::string str;
        std::string threadname;
        SourceLocation source_loc;
        LogFlags category;
        Level level;
        bool legacy;
    };

private:
    mutable std::mutex m_mutex;
    FILE* m_fileout{nullptr};
    std::list<BufferedLog> m_msgs_before_open;
    bool m_buffering{true};
    size_t m_max_buffer_memusage{DEFAULT_MAX_LOG_BUFFER};
    size_t m_cur_buffer_memusage{0};
    size_t m_buffer_lines_discarded{0};
    bool m_legacy_started_new_line{true};

    std::shared_ptr<LogRateLimiter> m_limiter;
    std::unordered_map<LogFlags, Level> m_category_log_levels;
    std::unordered_map<std::string, Level> m_legacy_category_log_levels;
    std::atomic<Level> m_log_level{DEFAULT_LOG_LEVEL};
    std::atomic<CategoryMask> m_categories{NONE};
    std::atomic<bool> m_legacy_all_categories{false};
    std::unordered_set<std::string> m_legacy_categories;
    std::unordered_set<std::string> m_legacy_excluded_categories;

    std::list<std::function<void(const std::string&)>> m_print_callbacks;

    void FormatLogStrInPlace(std::string& str, LogFlags category, Level level,
                             const SourceLocation& source_loc,
                             std::string_view threadname, int64_t time_micros) const;
    void FormatLegacyLogStrInPlace(std::string& str, int64_t time_micros,
                                   const SourceLocation* source_loc,
                                   LogFlags category, std::string_view category_name,
                                   Level level, bool contextual);
    std::string LogTimestampStr(int64_t time_micros) const;
    std::string GetLogPrefix(LogFlags category, Level level) const;
    void LogPrintStr_(std::string_view str, SourceLocation&& source_loc,
                      LogFlags category, Level level, bool should_ratelimit);
    bool ApplyRateLimiting(std::string& str, const SourceLocation& source_loc,
                           bool should_ratelimit);
    bool ReopenFile();

public:
    // References preserve the ABI and behavior of Firo's existing globals.
    bool& m_print_to_console{fPrintToConsole};
    bool& m_print_to_file{fPrintToDebugLog};
    bool& m_log_timestamps{fLogTimestamps};
    bool& m_log_time_micros{fLogTimeMicros};
    bool m_log_threadnames{DEFAULT_LOGTHREADNAMES};
    bool m_log_sourcelocations{DEFAULT_LOGSOURCELOCATIONS};
    bool m_always_print_category_level{DEFAULT_LOGLEVELALWAYS};
    fs::path m_file_path;
    std::atomic<bool>& m_reopen_file{fReopenDebugLog};

    void LogPrintStr(std::string_view str, SourceLocation&& source_loc,
                     LogFlags category, Level level, bool should_ratelimit);
    int LogPrintLegacy(const std::string& str, const SourceLocation* source_loc = nullptr,
                       LogFlags category = ALL, std::string_view category_name = {},
                       Level level = Level::Info, bool should_ratelimit = false);

    bool Enabled() const;
    std::list<std::function<void(const std::string&)>>::iterator
    PushBackCallback(std::function<void(const std::string&)> callback);
    void DeleteCallback(std::list<std::function<void(const std::string&)>>::iterator it);
    size_t NumConnections() const;

    bool StartLogging();
    void DisconnectTestLogger();
    void DisableLogging();
    void ShrinkDebugFile();

    void SetRateLimiting(std::shared_ptr<LogRateLimiter> limiter);
    std::unordered_map<LogFlags, Level> CategoryLevels() const;
    void SetCategoryLogLevel(const std::unordered_map<LogFlags, Level>& levels);
    void AddCategoryLogLevel(LogFlags category, Level level);
    bool SetCategoryLogLevel(std::string_view category, std::string_view level);

    Level LogLevel() const { return m_log_level.load(); }
    void SetLogLevel(Level level) { m_log_level = level; }
    bool SetLogLevel(std::string_view level);

    CategoryMask GetCategoryMask() const { return m_categories.load(); }
    void EnableCategory(LogFlags flag);
    bool EnableCategory(std::string_view category);
    void DisableCategory(LogFlags flag);
    bool DisableCategory(std::string_view category);
    void EnableLegacyCategory(std::string_view category);
    void DisableLegacyCategory(std::string_view category);
    void ClearLegacyCategories();
    bool LegacyCategoryEnabled(std::string_view category) const;
    bool WillLogLegacyCategoryLevel(std::string_view category, Level level) const;

    bool WillLogCategory(LogFlags category) const;
    bool WillLogCategoryLevel(LogFlags category, Level level) const;

    std::vector<LogCategory> LogCategoriesList() const;
    std::string LogCategoriesString() const;
    std::string LogLevelsString() const;
    static std::string LogLevelToStr(Level level);
    bool DefaultShrinkDebugFile() const;
};

} // namespace BCLog

BCLog::Logger& LogInstance();

/** Apply ordered legacy -debug and -debugexclude values to the logger. */
void ConfigureLegacyLogCategories(const std::vector<std::string>& categories,
                                  const std::vector<std::string>& excluded_categories);

inline bool LogAcceptCategory(BCLog::LogFlags category,
                              BCLog::Level level = BCLog::Level::Debug)
{
    return LogInstance().WillLogCategoryLevel(category, level);
}

/** Legacy string-category compatibility. A null category logs unconditionally. */
bool LogAcceptCategory(const char* category,
                       BCLog::Level level = BCLog::Level::Debug);
bool GetLogCategory(BCLog::LogFlags& flag, std::string_view category);

/**
 * Raw legacy output API retained for callers without source/category context.
 * This sink preserves historical formatting and intentionally does not apply
 * per-source rate limiting because all such calls would share the sink's own
 * source location.
 */
int LogPrintStr(const std::string& str);
int LogPrintCategory(const char* category, const std::string& str,
                     SourceLocation&& source_loc);
int LogPrintCategory(BCLog::LogFlags category, const std::string& str,
                     SourceLocation&& source_loc);
int LogPrintfCompat(const std::string& str, SourceLocation&& source_loc);
bool OpenDebugLog();
void ShrinkDebugFile();

template <typename Category, typename Formatter>
inline void LogPrintCategoryCompat(Category category, Formatter&& formatter,
                                   SourceLocation&& source_loc)
{
    if (LogAcceptCategory(category, BCLog::Level::Debug)) {
        LogPrintCategory(category, formatter(), std::move(source_loc));
    }
}

#define LogPrint(category, ...)                                                    \
    do {                                                                           \
        LogPrintCategoryCompat((category), [&] { return tfm::format(__VA_ARGS__); }, \
                               SourceLocation{__func__});                           \
    } while (0)

#define LogPrintf(...)                                                             \
    do {                                                                           \
        LogPrintfCompat(tfm::format(__VA_ARGS__), SourceLocation{__func__});        \
    } while (0)

#endif // BITCOIN_LOGGING_H
