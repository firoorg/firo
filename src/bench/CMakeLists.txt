# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GenerateHeaders)
generate_header_from_raw(data/block413567.raw benchmark::data)

add_executable(bench_firo
  ${CMAKE_CURRENT_SOURCE_DIR}/bench_bitcoin.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bench.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/data/block413567.raw.h
# Benchmarks:
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ccoins_caching.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/checkblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/checkqueue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto_hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/Examples.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lockedpool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mempool_eviction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/perf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rollingbloom.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/verify_script.cpp
)

target_link_libraries(bench_firo
  core_interface
  firo_node
  Boost::headers
  Boost::filesystem
  secp256k1pp
)

if(ENABLE_WALLET)
  target_sources(bench_firo
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/coin_selection.cpp
  )
  target_link_libraries(bench_firo firo_wallet)
endif()

add_test(NAME bench_sanity_check_high_priority
  COMMAND bench_firo -sanity-check -priority-level=high
)

install(TARGETS bench_firo
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Spark/Lelantus benchmarking framework
option(BUILD_BENCH_SPARK "Build Spark/Lelantus benchmarks" OFF)

if(BUILD_BENCH_SPARK)
  message(STATUS "Building Spark benchmarks")
  
  # Generic benchmarking framework library
  add_library(firo_benchmark STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/benchmark.cpp
  )
  
  target_include_directories(firo_benchmark PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  )
  
  # Optional: Enable Linux perf counters (requires explicit opt-in)
  option(ENABLE_BENCH_PERF_COUNTERS "Enable Linux perf counters in benchmarks (Linux only)" OFF)
  
  if(ENABLE_BENCH_PERF_COUNTERS)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_compile_definitions(firo_benchmark PUBLIC BENCH_PERF_COUNTERS)
      message(STATUS "  Linux perf counters: ENABLED")
    else()
      message(WARNING "  ENABLE_BENCH_PERF_COUNTERS is only supported on Linux, ignoring")
    endif()
  else()
    message(STATUS "  Linux perf counters: DISABLED (use -DENABLE_BENCH_PERF_COUNTERS=ON to enable)")
  endif()
  
  # Grootle proof benchmarks
  add_executable(bench_spark_grootle
    ${CMAKE_CURRENT_SOURCE_DIR}/spark_grootle.cpp
  )
  
  target_link_libraries(bench_spark_grootle
    firo_benchmark
    firo_node
    Boost::filesystem
    secp256k1pp
  )
  
  # BPPlus (Bulletproofs+) benchmarks
  add_executable(bench_spark_bpplus
    ${CMAKE_CURRENT_SOURCE_DIR}/spark_bpplus.cpp
  )
  
  target_link_libraries(bench_spark_bpplus
    firo_benchmark
    firo_node
    Boost::filesystem
    secp256k1pp
  )
  
  # Chaum proof benchmarks
  add_executable(bench_spark_chaum
    ${CMAKE_CURRENT_SOURCE_DIR}/spark_chaum.cpp
  )
  
  target_link_libraries(bench_spark_chaum
    firo_benchmark
    firo_node
    Boost::filesystem
    secp256k1pp
  )
  
  # Schnorr signature benchmarks
  add_executable(bench_spark_schnorr
    ${CMAKE_CURRENT_SOURCE_DIR}/spark_schnorr.cpp
  )
  
  target_link_libraries(bench_spark_schnorr
    firo_benchmark
    firo_node
    Boost::filesystem
    secp256k1pp
  )
  
  # Install benchmark executables
  install(TARGETS bench_spark_grootle bench_spark_bpplus bench_spark_chaum bench_spark_schnorr
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  
  message(STATUS "  Benchmarks: bench_spark_grootle, bench_spark_bpplus, bench_spark_chaum, bench_spark_schnorr")
endif()
