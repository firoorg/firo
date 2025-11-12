# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.

target_sources(test_firo
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantus_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mnemonic_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/spark_wallet_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txbuilder_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet_test_fixture.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet_tests.cpp
)
target_link_libraries(test_firo firo_wallet)
