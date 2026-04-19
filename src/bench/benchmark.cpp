// Copyright (c) 2025 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "benchmark.h"
#include <algorithm>
#include <cmath>

#ifdef __linux__
#include <asm/unistd.h>
#endif

namespace benchmark {

// BenchMetrics implementation
void BenchMetrics::print() const {
    std::cout << "\n=== Benchmark: " << name << " ===\n";
    std::cout << "Iterations: " << iterations << "\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Time (ns):\n";
    std::cout << "  Min:    " << min_time_ns << " ns (" << std::setprecision(6) << (min_time_ns / 1e9) << " s)\n";
    std::cout << "  Max:    " << std::setprecision(2) << max_time_ns << " ns (" << std::setprecision(6) << (max_time_ns / 1e9) << " s)\n";
    std::cout << "  Avg:    " << std::setprecision(2) << avg_time_ns << " ns (" << std::setprecision(6) << (avg_time_ns / 1e9) << " s)\n";
    std::cout << "  Median: " << std::setprecision(2) << median_time_ns << " ns (" << std::setprecision(6) << (median_time_ns / 1e9) << " s)\n";
    std::cout << "  StdDev: " << stddev_time_ns << "\n";
    
    if (avg_cycles > 0) {
        std::cout << "Cycles:\n";
        std::cout << "  Min: " << min_cycles << "\n";
        std::cout << "  Max: " << max_cycles << "\n";
        std::cout << "  Avg: " << avg_cycles << "\n";
    }
    
#ifdef BENCH_PERF_COUNTERS
    std::cout << "Performance Counters:\n";
    std::cout << "  Cache Misses:     " << cache_misses << "\n";
    std::cout << "  Cache References: " << cache_references << "\n";
    if (cache_references > 0) {
        double miss_rate = (double)cache_misses / cache_references * 100.0;
        std::cout << "  Cache Miss Rate:  " << std::setprecision(2) << miss_rate << "%\n";
    }
    std::cout << "  Branch Misses:    " << branch_misses << "\n";
    std::cout << "  Instructions:     " << instructions << "\n";
    if (avg_cycles > 0 && instructions > 0) {
        // IPC = average instructions per iteration / average cycles per iteration
        double avg_instructions = (double)instructions / iterations;
        double ipc = avg_instructions / avg_cycles;
        std::cout << "  IPC:              " << std::setprecision(2) << ipc << "\n";
    }
#endif
    std::cout << std::endl;
}

void BenchMetrics::print_csv_header() const {
    std::cout << "name,iterations,min_ns,max_ns,avg_ns,median_ns,stddev_ns,min_cycles,max_cycles,avg_cycles";
#ifdef BENCH_PERF_COUNTERS
    std::cout << ",cache_misses,cache_refs,branch_misses,instructions";
#endif
    std::cout << "\n";
}

void BenchMetrics::print_csv() const {
    std::cout << name << ","
              << iterations << ","
              << std::fixed << std::setprecision(2)
              << min_time_ns << ","
              << max_time_ns << ","
              << avg_time_ns << ","
              << median_time_ns << ","
              << stddev_time_ns << ","
              << min_cycles << ","
              << max_cycles << ","
              << avg_cycles;
#ifdef BENCH_PERF_COUNTERS
    std::cout << "," << cache_misses
              << "," << cache_references
              << "," << branch_misses
              << "," << instructions;
#endif
    std::cout << "\n";
}

// PerfCounters implementation
#ifdef BENCH_PERF_COUNTERS
int PerfCounters::setup_perf_event(uint32_t type, uint64_t config) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = type;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = config;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    
    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    return fd;
}
#endif

PerfCounters::PerfCounters() : cycles(0) {
#ifdef BENCH_PERF_COUNTERS
    cache_misses = 0;
    cache_references = 0;
    branch_misses = 0;
    instructions = 0;
    
    fd_cycles = setup_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    fd_cache_misses = setup_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
    fd_cache_refs = setup_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
    fd_branch_misses = setup_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
    fd_instructions = setup_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
#endif
}

PerfCounters::~PerfCounters() {
#ifdef BENCH_PERF_COUNTERS
    if (fd_cycles >= 0) close(fd_cycles);
    if (fd_cache_misses >= 0) close(fd_cache_misses);
    if (fd_cache_refs >= 0) close(fd_cache_refs);
    if (fd_branch_misses >= 0) close(fd_branch_misses);
    if (fd_instructions >= 0) close(fd_instructions);
#endif
}

void PerfCounters::start() {
#ifdef BENCH_PERF_COUNTERS
    if (fd_cycles >= 0) {
        ioctl(fd_cycles, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (fd_cache_misses >= 0) {
        ioctl(fd_cache_misses, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_cache_misses, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (fd_cache_refs >= 0) {
        ioctl(fd_cache_refs, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_cache_refs, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (fd_branch_misses >= 0) {
        ioctl(fd_branch_misses, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_branch_misses, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (fd_instructions >= 0) {
        ioctl(fd_instructions, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_instructions, PERF_EVENT_IOC_ENABLE, 0);
    }
#endif
}

void PerfCounters::stop() {
#ifdef BENCH_PERF_COUNTERS
    if (fd_cycles >= 0) {
        ioctl(fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
        if (read(fd_cycles, &cycles, sizeof(uint64_t)) != static_cast<ssize_t>(sizeof(uint64_t))) {
            cycles = 0;
        }
    }
    if (fd_cache_misses >= 0) {
        ioctl(fd_cache_misses, PERF_EVENT_IOC_DISABLE, 0);
        if (read(fd_cache_misses, &cache_misses, sizeof(uint64_t)) != static_cast<ssize_t>(sizeof(uint64_t))) {
            cache_misses = 0;
        }
    }
    if (fd_cache_refs >= 0) {
        ioctl(fd_cache_refs, PERF_EVENT_IOC_DISABLE, 0);
        if (read(fd_cache_refs, &cache_references, sizeof(uint64_t)) != static_cast<ssize_t>(sizeof(uint64_t))) {
            cache_references = 0;
        }
    }
    if (fd_branch_misses >= 0) {
        ioctl(fd_branch_misses, PERF_EVENT_IOC_DISABLE, 0);
        if (read(fd_branch_misses, &branch_misses, sizeof(uint64_t)) != static_cast<ssize_t>(sizeof(uint64_t))) {
            branch_misses = 0;
        }
    }
    if (fd_instructions >= 0) {
        ioctl(fd_instructions, PERF_EVENT_IOC_DISABLE, 0);
        if (read(fd_instructions, &instructions, sizeof(uint64_t)) != static_cast<ssize_t>(sizeof(uint64_t))) {
            instructions = 0;
        }
    }
#endif
}

// BenchRunner implementation
BenchRunner::BenchRunner(const std::string& benchmark_name, uint64_t min_iters, double min_time_secs)
    : name(benchmark_name)
    , warmup_iterations(3)
    , min_iterations(min_iters)
    , min_time_seconds(min_time_secs)
{
}

void BenchRunner::warmup(std::function<void()> func) {
    for (uint64_t i = 0; i < warmup_iterations; ++i) {
        func();
    }
}

double BenchRunner::calculate_stddev(const std::vector<double>& values, double mean) const {
    if (values.size() <= 1) return 0.0;
    
    double sum_sq_diff = 0.0;
    for (double v : values) {
        double diff = v - mean;
        sum_sq_diff += diff * diff;
    }
    
    return std::sqrt(sum_sq_diff / (values.size() - 1));
}

double BenchRunner::calculate_median(std::vector<double> values) const {
    if (values.empty()) return 0.0;
    
    std::sort(values.begin(), values.end());
    size_t n = values.size();
    
    if (n % 2 == 0) {
        return (values[n/2 - 1] + values[n/2]) / 2.0;
    } else {
        return values[n/2];
    }
}

} // namespace benchmark
