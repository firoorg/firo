# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GenerateHeaders)
generate_header_from_raw(data/block413567.raw benchmark::data)

add_executable(bench_firo
  bench_bitcoin.cpp
  bench.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/data/block413567.raw.h
# Benchmarks:
  base58.cpp
  ccoins_caching.cpp
  checkblock.cpp
  checkqueue.cpp
  crypto_hash.cpp
  Examples.cpp
  lockedpool.cpp
  mempool_eviction.cpp
  perf.cpp
  rollingbloom.cpp
  verify_script.cpp
)

target_link_libraries(bench_firo
  core_interface
  firo_node
  Boost::headers
)

if(ENABLE_WALLET)
  target_sources(bench_firo
    PRIVATE
      coin_selection.cpp
  )
  target_link_libraries(bench_firo firo_wallet)
endif()

add_test(NAME bench_sanity_check_high_priority
  COMMAND bench_firo -sanity-check -priority-level=high
)

install(TARGETS bench_firo
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
