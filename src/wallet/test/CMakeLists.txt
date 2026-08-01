# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.

target_sources(test_firo
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mnemonic_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/spark_batch_planner_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/spark_wallet_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet_test_fixture.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet_tests.cpp
)
target_link_libraries(test_firo firo_wallet)
if(ENABLE_SQLITE_WALLET)
  target_link_libraries(test_firo SQLite3::SQLite3)
endif()

# These cases use standalone fixtures and are not discovered by the suite-only
# test registration in src/test/CMakeLists.txt.
foreach(wallet_test_name IN ITEMS
  wallet_database_factory_preopen_policy
  wallet_mnemonic_encryption_persists
)
  add_test(NAME ${wallet_test_name}
    COMMAND test_firo --run_test=${wallet_test_name} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
  )
  set_property(TEST ${wallet_test_name} PROPERTY
    SKIP_REGULAR_EXPRESSION "no test cases matching filter"
  )
endforeach()

if(ENABLE_SQLITE_WALLET)
  add_test(NAME sqlite_wallet_encryption_failure_contract
    COMMAND test_firo --run_test=sqlite_wallet_encryption_failure_contract --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
  )
endif()
