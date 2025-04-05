# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.

target_sources(test_firo
  PRIVATE
  accounting_tests.cpp
  crypto_tests.cpp
  lelantus_tests.cpp
  mnemonic_tests.cpp
  sigma_tests.cpp
  spark_wallet_tests.cpp
  txbuilder_tests.cpp
  wallet_test_fixture.cpp
  wallet_tests.cpp
)
target_link_libraries(test_firo firo_wallet)
