// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_BENCH_BENCHMARK_H
#define FIRO_BENCH_BENCHMARK_H

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <functional>

// Platform-specific performance counter support
// Only enabled if explicitly requested via -DBENCH_PERF_COUNTERS
#ifdef BENCH_PERF_COUNTERS
    #ifdef __linux__
        #include <linux/perf_event.h>
        #include <sys/ioctl.h>
        #include <unistd.h>
        #include <cstring>
    #else
        #error "BENCH_PERF_COUNTERS is only supported on Linux"
    #endif
#endif

namespace benchmark {

// Benchmark metrics structure
struct BenchMetrics {
    std::string name;
    uint64_t iterations;
    
    // Timing metrics (always available)
    double min_time_ns;
    double max_time_ns;
    double avg_time_ns;
    double median_time_ns;
    double stddev_time_ns;
    
    // CPU cycles (platform-dependent)
    uint64_t min_cycles;
    uint64_t max_cycles;
    uint64_t avg_cycles;
    
    // Memory metrics (if available)
    size_t peak_memory_bytes;
    
#ifdef BENCH_PERF_COUNTERS
    // Linux perf counters (only if explicitly enabled)
    uint64_t cache_misses;
    uint64_t cache_references;
    uint64_t branch_misses;
    uint64_t instructions;
#endif
    
    void print() const;
    void print_csv_header() const;
    void print_csv() const;
};

// Performance counter wrapper
class PerfCounters {
public:
    PerfCounters();
    ~PerfCounters();
    
    void start();
    void stop();
    
    uint64_t get_cycles() const { return cycles; }
    
#ifdef BENCH_PERF_COUNTERS
    uint64_t get_cache_misses() const { return cache_misses; }
    uint64_t get_cache_references() const { return cache_references; }
    uint64_t get_branch_misses() const { return branch_misses; }
    uint64_t get_instructions() const { return instructions; }
#endif

private:
    uint64_t cycles;
    
#ifdef BENCH_PERF_COUNTERS
    int fd_cycles;
    int fd_cache_misses;
    int fd_cache_refs;
    int fd_branch_misses;
    int fd_instructions;
    
    uint64_t cache_misses;
    uint64_t cache_references;
    uint64_t branch_misses;
    uint64_t instructions;
    
    int setup_perf_event(uint32_t type, uint64_t config);
#endif
};

// Benchmark runner
class BenchRunner {
public:
    BenchRunner(const std::string& name, uint64_t min_iterations = 10, double min_time_seconds = 1.0);
    
    // Run benchmark function and collect metrics
    template<typename Func>
    BenchMetrics run(Func&& func);
    
    void set_warmup_iterations(uint64_t warmup) { warmup_iterations = warmup; }
    void set_min_iterations(uint64_t min_iter) { min_iterations = min_iter; }
    void set_min_time(double seconds) { min_time_seconds = seconds; }
    
private:
    std::string name;
    uint64_t warmup_iterations;
    uint64_t min_iterations;
    double min_time_seconds;
    
    void warmup(std::function<void()> func);
    double calculate_stddev(const std::vector<double>& values, double mean) const;
    double calculate_median(std::vector<double> values) const;
};

// Template implementation
template<typename Func>
BenchMetrics BenchRunner::run(Func&& func) {
    BenchMetrics metrics = {};
    metrics.name = name;
    
    // Warmup phase
    std::function<void()> func_wrapper = func;
    warmup(func_wrapper);
    
    // Measurement phase
    std::vector<double> times;
    std::vector<uint64_t> cycles_vec;
    times.reserve(min_iterations * 2);
    cycles_vec.reserve(min_iterations * 2);

#ifdef BENCH_PERF_COUNTERS
    uint64_t total_cache_misses = 0;
    uint64_t total_cache_refs = 0;
    uint64_t total_branch_misses = 0;
    uint64_t total_instructions = 0;
#endif
    
    uint64_t total_iterations = 0;
    auto start_time = std::chrono::steady_clock::now();
    
    PerfCounters perf;
    
    while (total_iterations < min_iterations || 
           std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count() < min_time_seconds) {
        
        perf.start();
        auto t1 = std::chrono::high_resolution_clock::now();
        
        func();
        
        auto t2 = std::chrono::high_resolution_clock::now();
        perf.stop();
        
        double elapsed_ns = std::chrono::duration<double, std::nano>(t2 - t1).count();
        times.push_back(elapsed_ns);
        cycles_vec.push_back(perf.get_cycles());

#ifdef BENCH_PERF_COUNTERS
        total_cache_misses += perf.get_cache_misses();
        total_cache_refs += perf.get_cache_references();
        total_branch_misses += perf.get_branch_misses();
        total_instructions += perf.get_instructions();
#endif
        
        total_iterations++;
    }
    
    // Calculate statistics
    metrics.iterations = total_iterations;
    
    metrics.min_time_ns = *std::min_element(times.begin(), times.end());
    metrics.max_time_ns = *std::max_element(times.begin(), times.end());
    
    double sum = 0.0;
    for (double t : times) sum += t;
    metrics.avg_time_ns = sum / times.size();
    
    metrics.median_time_ns = calculate_median(times);
    metrics.stddev_time_ns = calculate_stddev(times, metrics.avg_time_ns);
    
    if (!cycles_vec.empty()) {
        metrics.min_cycles = *std::min_element(cycles_vec.begin(), cycles_vec.end());
        metrics.max_cycles = *std::max_element(cycles_vec.begin(), cycles_vec.end());
        
        uint64_t sum_cycles = 0;
        for (uint64_t c : cycles_vec) sum_cycles += c;
        metrics.avg_cycles = sum_cycles / cycles_vec.size();
    }
    
#ifdef BENCH_PERF_COUNTERS
    metrics.cache_misses = total_cache_misses;
    metrics.cache_references = total_cache_refs;
    metrics.branch_misses = total_branch_misses;
    metrics.instructions = total_instructions;
#endif
    
    return metrics;
}

// Macro for easy benchmark registration
#define BENCHMARK(name, func) \
    static void bench_##name() { \
        benchmark::BenchRunner runner(#name); \
        auto metrics = runner.run(func); \
        metrics.print(); \
    }

} // namespace benchmark

#endif // FIRO_BENCH_BENCHMARK_H
