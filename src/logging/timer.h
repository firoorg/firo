// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_TIMER_H
#define BITCOIN_LOGGING_TIMER_H

#include "util/log.h"

#include <chrono>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace BCLog {

template <typename TimeType>
class Timer
{
public:
    Timer(std::string prefix, std::string end_msg,
          LogFlags log_category = LogFlags::ALL,
          bool message_on_completion = true)
        : m_prefix(std::move(prefix)),
          m_title(std::move(end_msg)),
          m_log_category(log_category),
          m_message_on_completion(message_on_completion)
    {
        Log(strprintf("%s started", m_title));
        m_start = std::chrono::steady_clock::now();
    }

    ~Timer()
    {
        Log(m_message_on_completion ? strprintf("%s completed", m_title) : "completed");
    }

    void Log(const std::string& message)
    {
        const std::string full_message = LogMsg(message);
        if (m_log_category == LogFlags::ALL) {
            LogInfo("%s\n", full_message);
        } else {
            LogDebug(m_log_category, "%s\n", full_message);
        }
    }

    std::string LogMsg(const std::string& message) const
    {
        if (!m_start) return strprintf("%s: %s", m_prefix, message);

        const auto elapsed = std::chrono::steady_clock::now() - *m_start;
        if constexpr (std::is_same_v<TimeType, std::chrono::microseconds>) {
            return strprintf("%s: %s (%i\u03bcs)", m_prefix, message,
                             std::chrono::duration_cast<TimeType>(elapsed).count());
        } else if constexpr (std::is_same_v<TimeType, std::chrono::milliseconds>) {
            const double count = std::chrono::duration<double, std::milli>(elapsed).count();
            return strprintf("%s: %s (%.2fms)", m_prefix, message, count);
        } else if constexpr (std::is_same_v<TimeType, std::chrono::seconds>) {
            const double count = std::chrono::duration<double>(elapsed).count();
            return strprintf("%s: %s (%.2fs)", m_prefix, message, count);
        } else {
            static_assert(!sizeof(TimeType), "Unsupported logging timer duration");
        }
    }

private:
    std::optional<std::chrono::steady_clock::time_point> m_start;
    const std::string m_prefix;
    const std::string m_title;
    const LogFlags m_log_category;
    const bool m_message_on_completion;
};

} // namespace BCLog

#define BCLOG_PASTE_IMPL(x, y) x##y
#define BCLOG_PASTE(x, y) BCLOG_PASTE_IMPL(x, y)
#define BCLOG_UNIQUE_NAME(name) BCLOG_PASTE(name, __COUNTER__)

#define LOG_TIME_MICROS_WITH_CATEGORY(end_msg, category) \
    BCLog::Timer<std::chrono::microseconds> BCLOG_UNIQUE_NAME(logging_timer)(__func__, end_msg, category)
#define LOG_TIME_MILLIS_WITH_CATEGORY(end_msg, category) \
    BCLog::Timer<std::chrono::milliseconds> BCLOG_UNIQUE_NAME(logging_timer)(__func__, end_msg, category)
#define LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE(end_msg, category) \
    BCLog::Timer<std::chrono::milliseconds> BCLOG_UNIQUE_NAME(logging_timer)(__func__, end_msg, category, false)
#define LOG_TIME_SECONDS(end_msg) \
    BCLog::Timer<std::chrono::seconds> BCLOG_UNIQUE_NAME(logging_timer)(__func__, end_msg)

#endif // BITCOIN_LOGGING_TIMER_H
