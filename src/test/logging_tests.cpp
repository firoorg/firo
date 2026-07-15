// Copyright (c) 2019-present The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls.h"
#include "init.h"
#include "logging.h"
#include "logging/timer.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <array>
#include <chrono>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

std::string ReadFile(const fs::path& path)
{
    fs::ifstream stream{path};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

void LegacyRateLimitedLog(const std::string& message)
{
    LogPrintf("%s", message);
}

void ParseArgs(const std::vector<std::string>& args)
{
    std::vector<std::string> storage{"test_firo"};
    storage.insert(storage.end(), args.begin(), args.end());
    std::vector<const char*> argv;
    argv.reserve(storage.size());
    for (const auto& arg : storage) argv.push_back(arg.c_str());
    ParseParameters(argv.size(), argv.data());
}

} // namespace

struct LoggingTestingSetup : public BasicTestingSetup {
    BCLog::Logger& logger{LogInstance()};
    fs::path previous_path;
    bool previous_print_to_console;
    bool previous_print_to_file;
    bool previous_log_timestamps;
    bool previous_log_time_micros;
    bool previous_log_threadnames;
    bool previous_log_sourcelocations;
    bool previous_log_level_always;
    bool previous_reopen;
    bool previous_debug;
    bool previous_no_debug;
    BCLog::CategoryMask previous_category_mask;
    BCLog::Level previous_log_level;
    std::unordered_map<BCLog::LogFlags, BCLog::Level> previous_category_levels;
    std::vector<std::string> messages;

    LoggingTestingSetup()
        : previous_path(logger.m_file_path),
          previous_print_to_console(logger.m_print_to_console),
          previous_print_to_file(logger.m_print_to_file),
          previous_log_timestamps(logger.m_log_timestamps),
          previous_log_time_micros(logger.m_log_time_micros),
          previous_log_threadnames(logger.m_log_threadnames),
          previous_log_sourcelocations(logger.m_log_sourcelocations),
          previous_log_level_always(logger.m_always_print_category_level),
          previous_reopen(logger.m_reopen_file.load()),
          previous_debug(fDebug),
          previous_no_debug(fNoDebug),
          previous_category_mask(logger.GetCategoryMask()),
          previous_log_level(logger.LogLevel()),
          previous_category_levels(logger.CategoryLevels())
    {
        logger.DisconnectTestLogger();
        logger.m_print_to_console = false;
        logger.m_print_to_file = false;
        logger.m_log_timestamps = false;
        logger.m_log_time_micros = false;
        logger.m_log_threadnames = false;
        logger.m_log_sourcelocations = false;
        logger.m_always_print_category_level = false;
        logger.m_reopen_file = false;
        logger.DisableCategory(BCLog::ALL);
        logger.ClearLegacyCategories();
        logger.SetLogLevel(BCLog::DEFAULT_LOG_LEVEL);
        logger.SetCategoryLogLevel({});
        logger.SetRateLimiting(nullptr);
        fDebug = false;
        fNoDebug = false;

        logger.PushBackCallback([this](const std::string& message) {
            messages.push_back(message);
        });
        if (!logger.StartLogging()) throw std::runtime_error("Failed to start test logger");
    }

    ~LoggingTestingSetup()
    {
        logger.DisconnectTestLogger();
        logger.m_file_path = previous_path;
        logger.m_print_to_console = previous_print_to_console;
        logger.m_print_to_file = previous_print_to_file;
        logger.m_log_timestamps = previous_log_timestamps;
        logger.m_log_time_micros = previous_log_time_micros;
        logger.m_log_threadnames = previous_log_threadnames;
        logger.m_log_sourcelocations = previous_log_sourcelocations;
        logger.m_always_print_category_level = previous_log_level_always;
        logger.m_reopen_file = previous_reopen;
        logger.DisableCategory(BCLog::ALL);
        logger.EnableCategory(static_cast<BCLog::LogFlags>(previous_category_mask));
        logger.ClearLegacyCategories();
        logger.SetLogLevel(previous_log_level);
        logger.SetCategoryLogLevel(previous_category_levels);
        logger.SetRateLimiting(nullptr);
        fDebug = previous_debug;
        fNoDebug = previous_no_debug;
    }
};

BOOST_FIXTURE_TEST_SUITE(logging_tests, LoggingTestingSetup)

BOOST_AUTO_TEST_CASE(category_mapping)
{
    static constexpr std::array<std::string_view, 27> required_categories{
        "addrman", "bench", "chainlocks", "cmpctblock", "coindb", "db",
        "estimatefee", "gobject", "http", "instantsend", "libevent", "llmq",
        "llmq-dkg", "llmq-sigs", "mempool", "mempoolrej", "mnpayments",
        "mnsync", "net", "proxy", "prune", "rand", "reindex", "rpc",
        "selectcoins", "tor", "zmq",
    };

    const std::string categories = logger.LogCategoriesString();
    for (const auto category : required_categories) {
        BOOST_TEST_CONTEXT("category " << category) {
            BCLog::LogFlags flag{BCLog::NONE};
            BOOST_CHECK(GetLogCategory(flag, category));
            BOOST_CHECK(flag != BCLog::NONE);
            BOOST_CHECK(flag != BCLog::ALL);
            BOOST_CHECK(categories.find(category) != std::string::npos);
        }
    }

    BCLog::LogFlags canonical{BCLog::NONE};
    BCLog::LogFlags alias{BCLog::NONE};
    BOOST_REQUIRE(GetLogCategory(canonical, "mempoolrej"));
    BOOST_REQUIRE(GetLogCategory(alias, "mempool-reject"));
    BOOST_CHECK_EQUAL(canonical, alias);
    BOOST_CHECK_EQUAL(canonical, BCLog::MEMPOOLREJ);

    BOOST_CHECK(GetLogCategory(canonical, "CDbIndexHelper"));
    BOOST_CHECK_EQUAL(canonical, BCLog::DBINDEX);
    BOOST_CHECK(!GetLogCategory(canonical, "not-an-in-tree-category"));

    // logging.cpp compile-time assertions guarantee that the backing category
    // tables are trivially destructible and have unique names and flags.
}

BOOST_AUTO_TEST_CASE(legacy_category_and_output_compatibility)
{
    fDebug = true;
    BOOST_REQUIRE(logger.EnableCategory("net"));
    BOOST_REQUIRE(logger.EnableCategory("instantsend"));
    logger.EnableLegacyCategory("plugin-category");

    BOOST_CHECK(LogAcceptCategory("net"));
    BOOST_CHECK(LogAcceptCategory("instantsend"));
    BOOST_CHECK(LogAcceptCategory("plugin-category"));
    BOOST_CHECK(!LogAcceptCategory("rpc"));
    BOOST_CHECK(LogAcceptCategory(nullptr));
    BOOST_CHECK(LogAcceptCategory(BCLog::NET));

    LogPrint("net", "legacy %d", 1);
    LogPrint(BCLog::INSTANTSEND, " typed");
    LogPrint("plugin-category", " plugin");
    LogPrintf(" unconditional\n");

    const std::vector<std::string> expected{
        "legacy 1", " typed", " plugin", " unconditional\n",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(messages.begin(), messages.end(),
                                  expected.begin(), expected.end());

    fDebug = false;
    LogPrint("net", "hidden");
    BOOST_CHECK_EQUAL(messages.size(), expected.size());

    fNoDebug = true;
    LogPrintf("also hidden\n");
    LogPrintStr("ERROR: still visible\n");
    BOOST_REQUIRE_EQUAL(messages.size(), expected.size() + 1);
    BOOST_CHECK_EQUAL(messages.back(), "ERROR: still visible\n");
}

BOOST_AUTO_TEST_CASE(modern_log_macros_and_levels)
{
    logger.EnableCategory(BCLog::NET);

    LogTrace(BCLog::NET, "trace hidden");
    LogDebug(BCLog::NET, "debug %d", 1);
    LogInfo("info %d", 2);
    LogWarning("warning");
    LogError("error");

    const std::vector<std::string> expected{
        "[net] debug 1\n",
        "info 2\n",
        "[warning] warning\n",
        "[error] error\n",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(messages.begin(), messages.end(),
                                  expected.begin(), expected.end());

    BOOST_REQUIRE(logger.SetCategoryLogLevel("net", "trace"));
    LogTrace(BCLog::NET, "trace visible");
    BOOST_REQUIRE_EQUAL(messages.size(), expected.size() + 1);
    BOOST_CHECK_EQUAL(messages.back(), "[net:trace] trace visible\n");

    BOOST_CHECK(!logger.SetLogLevel("warning"));
    BOOST_CHECK(logger.SetCategoryLogLevel("unknown", "debug"));
    BOOST_CHECK(!logger.SetCategoryLogLevel("unknown", "warning"));
}

BOOST_AUTO_TEST_CASE(legacy_levels_context_and_raw_sink)
{
    ConfigureLegacyLogCategories({"net", "plugin-category"}, {});

    BOOST_REQUIRE(logger.SetCategoryLogLevel("net", "info"));
    LogPrint("net", "net hidden");
    LogPrint("plugin-category", "plugin visible");
    BOOST_REQUIRE_EQUAL(messages.size(), 1U);
    BOOST_CHECK_EQUAL(messages.back(), "plugin visible");

    BOOST_REQUIRE(logger.SetCategoryLogLevel("plugin-category", "info"));
    LogPrint("plugin-category", "plugin hidden");
    BOOST_CHECK_EQUAL(messages.size(), 1U);

    BOOST_REQUIRE(logger.SetCategoryLogLevel("net", "debug"));
    BOOST_REQUIRE(logger.SetCategoryLogLevel("plugin-category", "debug"));
    messages.clear();
    const std::string previous_thread_name = GetThreadName();
    RenameThread("logging-test");
    logger.m_log_threadnames = true;
    logger.m_log_sourcelocations = true;
    logger.m_always_print_category_level = true;

    LogPrint("net", "categorized\n");
    LogPrint("plugin-category", "plugin categorized\n");
    LogPrintf("unconditional\n");
    LogPrintStr("raw compatibility sink\n");

    RenameThread(previous_thread_name.c_str());
    BOOST_REQUIRE_EQUAL(messages.size(), 4U);
    BOOST_CHECK(messages[0].find("[logging-test] [") == 0);
    BOOST_CHECK(messages[0].find("logging_tests.cpp:") != std::string::npos);
    BOOST_CHECK(messages[0].find("[test_method] [net:debug] categorized\n") != std::string::npos);
    BOOST_CHECK(messages[1].find("[logging-test] [") == 0);
    BOOST_CHECK(messages[1].find("[test_method] [plugin-category:debug] plugin categorized\n") != std::string::npos);
    BOOST_CHECK(messages[2].find("[logging-test] [") == 0);
    BOOST_CHECK(messages[2].find("[test_method] [all:info] unconditional\n") != std::string::npos);
    BOOST_CHECK_EQUAL(messages[3], "raw compatibility sink\n");
}

BOOST_AUTO_TEST_CASE(debug_category_precedence)
{
    ConfigureLegacyLogCategories({"net", "none", "rpc"}, {"rpc"});
    BOOST_CHECK(fDebug);
    BOOST_CHECK(!fNoDebug);
    BOOST_CHECK(!LogAcceptCategory("net"));
    BOOST_CHECK(!LogAcceptCategory("rpc"));

    ConfigureLegacyLogCategories({"plugin-before", "none", "plugin-after"}, {});
    BOOST_CHECK(!LogAcceptCategory("plugin-before"));
    BOOST_CHECK(LogAcceptCategory("plugin-after"));

    ConfigureLegacyLogCategories({"all"}, {"net", "plugin-category"});
    BOOST_CHECK(LogAcceptCategory("rpc"));
    BOOST_CHECK(!LogAcceptCategory("net"));
    BOOST_CHECK(!LogAcceptCategory("plugin-category"));

    ConfigureLegacyLogCategories({"plugin-category"}, {"all"});
    BOOST_CHECK(!LogAcceptCategory("plugin-category"));
    BOOST_CHECK(!LogAcceptCategory("net"));

    ConfigureLegacyLogCategories({"none"}, {});
    BOOST_CHECK(!fDebug);
    BOOST_CHECK(!fNoDebug);
    LogPrintf("none keeps unconditional logging\n");
    BOOST_REQUIRE(!messages.empty());
    BOOST_CHECK_EQUAL(messages.back(), "none keeps unconditional logging\n");

    const size_t message_count = messages.size();
    ConfigureLegacyLogCategories({"net", "0", "rpc"}, {});
    BOOST_CHECK(!fDebug);
    BOOST_CHECK(fNoDebug);
    LogPrintf("historically suppressed\n");
    LogPrintStr("ERROR: retained\n");
    BOOST_REQUIRE_EQUAL(messages.size(), message_count + 1);
    BOOST_CHECK_EQUAL(messages.back(), "ERROR: retained\n");
}

BOOST_AUTO_TEST_CASE(start_logging_open_failure_and_buffered_flush)
{
    const fs::path temp_dir = fs::temp_directory_path() / fs::unique_path("firo-logging-%%%%-%%%%");
    const fs::path invalid_log = temp_dir / "invalid.log";
    const fs::path valid_log = temp_dir / "debug.log";
    fs::create_directories(invalid_log);

    logger.DisconnectTestLogger();
    logger.m_print_to_console = false;
    logger.m_print_to_file = true;
    logger.m_file_path = invalid_log;
    LogPrintf("buffered before failed open\n");
    BOOST_CHECK(!logger.StartLogging());

    logger.m_file_path = valid_log;
    BOOST_REQUIRE(logger.StartLogging());
    logger.DisconnectTestLogger();
    BOOST_CHECK(ReadFile(valid_log).find("buffered before failed open\n") != std::string::npos);

    fs::remove_all(temp_dir);
}

BOOST_AUTO_TEST_CASE(legacy_early_logging_buffer_is_bounded)
{
    const fs::path temp_dir = fs::temp_directory_path() / fs::unique_path("firo-logbuffer-%%%%-%%%%");
    const fs::path log_path = temp_dir / "debug.log";
    fs::create_directories(temp_dir);

    logger.DisconnectTestLogger();
    logger.m_print_to_console = false;
    logger.m_print_to_file = true;
    logger.m_file_path = log_path;
    logger.m_log_timestamps = false;

    LogPrintf("discarded marker\n");
    LogPrintf("%s\n", std::string(BCLog::DEFAULT_MAX_LOG_BUFFER, 'x'));
    LogPrintf("retained marker\n");
    BOOST_REQUIRE(logger.StartLogging());
    logger.DisconnectTestLogger();

    const std::string contents = ReadFile(log_path);
    BOOST_CHECK(contents.find("Early logging buffer overflowed, 2 log lines discarded.") != std::string::npos);
    BOOST_CHECK(contents.find("discarded marker") == std::string::npos);
    BOOST_CHECK(contents.find("retained marker") != std::string::npos);

    fs::remove_all(temp_dir);
}

BOOST_AUTO_TEST_CASE(legacy_log_rate_limiting)
{
    const fs::path temp_dir = fs::temp_directory_path() / fs::unique_path("firo-lograte-%%%%-%%%%");
    const fs::path log_path = temp_dir / "debug.log";
    fs::create_directories(temp_dir);

    logger.DisconnectTestLogger();
    logger.m_print_to_console = false;
    logger.m_print_to_file = true;
    logger.m_file_path = log_path;
    logger.m_log_timestamps = false;
    BOOST_REQUIRE(logger.StartLogging());

    std::function<void()> reset;
    std::chrono::milliseconds scheduled_window{0};
    auto limiter = BCLog::LogRateLimiter::Create(
        [&](auto func, auto window) {
            reset = std::move(func);
            scheduled_window = window;
        },
        8,
        std::chrono::seconds{60});
    logger.SetRateLimiting(limiter);
    BOOST_CHECK_EQUAL(scheduled_window.count(), 60000);

    LegacyRateLimitedLog("1234567\n");
    LegacyRateLimitedLog("x\n");
    LogPrintStr("direct\n");
    ConfigureLegacyLogCategories({"net"}, {});
    LogPrint("net", "conditional\n");
    LegacyRateLimitedLog("y\n");
    BOOST_REQUIRE(reset);
    reset();
    LegacyRateLimitedLog("z\n");

    logger.SetRateLimiting(nullptr);
    logger.DisconnectTestLogger();
    const std::string contents = ReadFile(log_path);
    BOOST_CHECK(contents.find("1234567\n") != std::string::npos);
    BOOST_CHECK(contents.find("Excessive logging detected") != std::string::npos);
    BOOST_CHECK(contents.find("[*] x\n") != std::string::npos);
    BOOST_CHECK(contents.find("[*] direct\n") != std::string::npos);
    BOOST_CHECK(contents.find("[*] conditional\n") != std::string::npos);
    BOOST_CHECK(contents.find("[*] y\n") == std::string::npos);
    BOOST_CHECK(contents.find("Restarting logging") != std::string::npos);
    BOOST_CHECK(contents.find("z\n") != std::string::npos);

    fs::remove_all(temp_dir);
}

BOOST_AUTO_TEST_CASE(logging_argument_parsing)
{
    ParseArgs({"-nodebuglogfile", "-logratelimit=0"});
    InitLogging();
    BOOST_CHECK(!fPrintToDebugLog);
    BOOST_CHECK_EQUAL(logger.m_file_path.filename().string(), DEFAULT_DEBUGLOGFILE);
    BOOST_CHECK(!GetBoolArg("-logratelimit", BCLog::DEFAULT_LOGRATELIMIT));

    ParseArgs({"-debuglogfile=first.log", "-nodebuglogfile", "-debuglogfile=final.log",
               "-logratelimit=0", "-logratelimit=1", "-debug=net", "-debug=none",
               "-debug=rpc", "-debugexclude=rpc"});
    InitLogging();
    BOOST_CHECK(fPrintToDebugLog);
    BOOST_CHECK_EQUAL(logger.m_file_path, GetDataDir() / "final.log");
    BOOST_CHECK(GetBoolArg("-logratelimit", BCLog::DEFAULT_LOGRATELIMIT));
    BOOST_REQUIRE_EQUAL(mapMultiArgs.at("-debugexclude").size(), 1U);
    ConfigureLegacyLogCategories(mapMultiArgs.at("-debug"), mapMultiArgs.at("-debugexclude"));
    BOOST_CHECK(!LogAcceptCategory("net"));
    BOOST_CHECK(!LogAcceptCategory("rpc"));
    BOOST_CHECK(fDebug);
    BOOST_CHECK(!fNoDebug);

    ParseArgs({"-debuglogfile"});
    InitLogging();
    BOOST_CHECK(fPrintToDebugLog);
    BOOST_CHECK_EQUAL(logger.m_file_path, GetDataDir() / DEFAULT_DEBUGLOGFILE);

    ParseArgs({});
}

BOOST_AUTO_TEST_CASE(compatibility_globals_alias_logger_settings)
{
    BOOST_CHECK(&logger.m_print_to_console == &fPrintToConsole);
    BOOST_CHECK(&logger.m_print_to_file == &fPrintToDebugLog);
    BOOST_CHECK(&logger.m_log_timestamps == &fLogTimestamps);
    BOOST_CHECK(&logger.m_log_time_micros == &fLogTimeMicros);
    BOOST_CHECK(&logger.m_reopen_file == &fReopenDebugLog);

    logger.m_log_timestamps = true;
    BOOST_CHECK(fLogTimestamps);
    fLogTimeMicros = true;
    BOOST_CHECK(logger.m_log_time_micros);
}

BOOST_AUTO_TEST_CASE(log_escape_and_rate_limit_stats)
{
    BOOST_CHECK_EQUAL(BCLog::LogEscapeMessage("line\n\x01"), "line\n\\x01");

    BCLog::LogRateLimiter::Stats stats{100};
    BOOST_CHECK(stats.Consume(60));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, 40U);
    BOOST_CHECK(!stats.Consume(41));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, 0U);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, 41U);
}

BOOST_AUTO_TEST_CASE(logging_timer)
{
    BCLog::Timer<std::chrono::microseconds> timer{"logging_tests", "timer"};
    const std::string message = timer.LogMsg("checkpoint");
    BOOST_CHECK_EQUAL(message.substr(0, 27), "logging_tests: checkpoint (");
}

BOOST_AUTO_TEST_SUITE_END()
