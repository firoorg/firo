// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_LOG_H
#define BITCOIN_UTIL_LOG_H

#include "logging/categories.h"
#include "tinyformat.h"

#include <cstdint>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

/** Like std::source_location, but allowing the function name to be overridden. */
class SourceLocation
{
public:
    SourceLocation(const char* function,
                   std::source_location location = std::source_location::current())
        : m_function(function), m_location(location)
    {
    }

    std::string_view file_name() const { return m_location.file_name(); }
    std::uint_least32_t line() const { return m_location.line(); }
    std::string_view function_name_short() const { return m_function; }

private:
    std::string_view m_function;
    std::source_location m_location;
};

namespace util::log {

/** Opaque here; interpreted by consumers as BCLog::LogFlags. */
using Category = uint64_t;

enum class Level {
    Trace = 0,
    Debug,
    Info,
    Warning,
    Error,
};

struct Entry {
    Category category;
    Level level;
    bool should_ratelimit;
    SourceLocation source_loc;
    std::string message;
};

bool ShouldLog(Category category, Level level);
void Log(Entry entry);

} // namespace util::log

namespace BCLog {
using Level = util::log::Level;
} // namespace BCLog

template <typename... Args>
inline void LogPrintFormatInternal(SourceLocation&& source_loc, BCLog::LogFlags category,
                                   BCLog::Level level, bool should_ratelimit,
                                   const std::string& format, const Args&... args)
{
    std::string message;
    try {
        message = tfm::format(format, args...);
    } catch (const std::exception& e) {
        message = "Error \"" + std::string(e.what()) +
                  "\" while formatting log message: " + format;
    }
    util::log::Log(util::log::Entry{
        static_cast<util::log::Category>(category),
        level,
        should_ratelimit,
        std::move(source_loc),
        std::move(message),
    });
}

#define LogPrintLevel_(category, level, should_ratelimit, ...) \
    LogPrintFormatInternal(SourceLocation{__func__}, category, level, should_ratelimit, __VA_ARGS__)

#define LogInfo(...) \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Info, true, __VA_ARGS__)
#define LogWarning(...) \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Warning, true, __VA_ARGS__)
#define LogError(...) \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Error, true, __VA_ARGS__)

// Conditional macros avoid evaluating formatting arguments for disabled logs.
#define detail_LogIfCategoryAndLevelEnabled(category, level, ...) \
    do {                                                           \
        if (util::log::ShouldLog((category), (level))) {           \
            LogPrintLevel_(category, level, false, __VA_ARGS__);   \
        }                                                          \
    } while (0)

#define LogDebug(category, ...) \
    detail_LogIfCategoryAndLevelEnabled(category, BCLog::Level::Debug, __VA_ARGS__)
#define LogTrace(category, ...) \
    detail_LogIfCategoryAndLevelEnabled(category, BCLog::Level::Trace, __VA_ARGS__)

#endif // BITCOIN_UTIL_LOG_H
