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
