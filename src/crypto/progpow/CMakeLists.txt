# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(keccak STATIC EXCLUDE_FROM_ALL
    lib/keccak/keccak.c
    lib/keccak/keccakf800.c
    lib/keccak/keccakf1600.c
)

add_library(ethash STATIC EXCLUDE_FROM_ALL
    lib/ethash/ethash.cpp
    lib/ethash/managed.cpp
    lib/ethash/primes.c
    lib/ethash/progpow.cpp
)

target_link_libraries(ethash
  PRIVATE
    core_interface
    ${Boost_LIBRARIES}
   PUBLIC
    keccak
)

target_include_directories(ethash
  PUBLIC
  ${Boost_INCLUDE_DIR}
)