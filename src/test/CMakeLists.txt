# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GenerateHeaders)
generate_header_from_json(data/base58_encode_decode.json)
generate_header_from_json(data/base58_keys_invalid.json)
generate_header_from_json(data/base58_keys_valid.json)
generate_header_from_json(data/script_tests.json)
generate_header_from_json(data/sighash.json)
generate_header_from_json(data/tx_invalid.json)
generate_header_from_json(data/tx_valid.json)

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
add_executable(test_firo
  ${CMAKE_CURRENT_BINARY_DIR}/data/base58_encode_decode.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/base58_keys_invalid.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/base58_keys_valid.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/script_tests.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/sighash.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/tx_invalid.json.h
  ${CMAKE_CURRENT_BINARY_DIR}/data/tx_valid.json.h
  addrman_tests.cpp
  allocator_tests.cpp
  amount_tests.cpp
  arith_uint256_tests.cpp
  base32_tests.cpp
  base58_tests.cpp
  base64_tests.cpp
  bip32_tests.cpp
  bip47_test_data.h
  bip47_tests.cpp
  bip47_serialization_tests.cpp
  blockencodings_tests.cpp
  bloom_tests.cpp
  bswap_tests.cpp
  checkqueue_tests.cpp
  coins_tests.cpp
  compress_tests.cpp
  crypto_tests.cpp
  cuckoocache_tests.cpp
  DoS_tests.cpp
  fixtures.cpp
  fixtures.h
  getarg_tests.cpp
  hash_tests.cpp
  key_tests.cpp
  dbwrapper_tests.cpp
  lelantus_tests.cpp
  lelantus_mintspend_test.cpp
  lelantus_state_tests.cpp
  sigma_lelantus_transition.cpp
  limitedmap_tests.cpp
  main_tests.cpp
  mbstring_tests.cpp
  mempool_tests.cpp
  merkle_tests.cpp
  miner_tests.cpp
  mtp_halving_tests.cpp
  mtp_tests.cpp
  mtp_trans_tests.cpp
  firopow_tests.cpp
  multisig_tests.cpp
  netbase_tests.cpp
  net_tests.cpp
  pmt_tests.cpp
  prevector_tests.cpp
  raii_event_tests.cpp
  random_tests.cpp
  reverselock_tests.cpp
  rpc_tests.cpp
  sanity_tests.cpp
  scheduler_tests.cpp
  scriptnum10.h
  scriptnum_tests.cpp
  script_P2SH_tests.cpp
  script_tests.cpp
  serialize_tests.cpp
  sighash_tests.cpp
  sigma_manymintspend_test.cpp
  sigma_mintspend_numinputs.cpp
  sigma_mintspend_test.cpp
  sigma_partialspend_mempool_tests.cpp
  sigma_state_tests.cpp
  sigopcount_tests.cpp
  skiplist_tests.cpp
  streams_tests.cpp
  test_bitcoin.cpp
  test_bitcoin.h
  test_random.h
  testutil.cpp
  testutil.h
  timedata_tests.cpp
  transaction_tests.cpp
  txdb_tests.cpp
  txvalidationcache_tests.cpp
  uint256_tests.cpp
  univalue_tests.cpp
  util_tests.cpp
  multiexponentation_test.cpp
  firsthalving_tests.cpp
  evospork_tests.cpp
  evo_deterministicmns_tests.cpp
  evo_simplifiedmns_tests.cpp
  progpow_tests.cpp
  bls_tests.cpp
)

target_link_libraries(test_firo
  core_interface
  firo_cli
  firo_node
  bitcoin_consensus
  secp256k1
  Boost::headers
  libevent::extra
  secp256k1pp
  univalue
  leveldb
  firo_wallet
  ${TOR_LIBRARY}
  Boost::filesystem  
)

target_include_directories(test_firo
  PUBLIC
  ${CMAKE_CURRENT_BINARY_DIR}
)

apply_wrapped_exception_flags(test_firo)

if(ENABLE_WALLET)
  add_subdirectory(${PROJECT_SOURCE_DIR}/src/wallet/test wallet)
endif()

if(WITH_MULTIPROCESS)
  target_link_libraries(bitcoin_ipc_test
    PRIVATE
      core_interface
      univalue
  )

  target_sources(test_firo
    PRIVATE
      ipc_tests.cpp
  )
  target_link_libraries(test_firo bitcoin_ipc_test bitcoin_ipc)
endif()

function(add_boost_test source_file)
  if(NOT EXISTS ${source_file})
    return()
  endif()

  file(READ "${source_file}" source_file_content)
  string(REGEX
    MATCH "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(([A-Za-z0-9_]+)"
    test_suite_macro "${source_file_content}"
  )
  string(REGEX
    REPLACE "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(" ""
    test_suite_name "${test_suite_macro}"
  )
  if(test_suite_name)
    add_test(NAME ${test_suite_name}
      COMMAND test_firo --run_test=${test_suite_name} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
    )
    set_property(TEST ${test_suite_name} PROPERTY
      SKIP_REGULAR_EXPRESSION "no test cases matching filter"
    )
  endif()
endfunction()

function(add_all_test_targets)
  get_target_property(test_source_dir test_firo SOURCE_DIR)
  get_target_property(test_sources test_firo SOURCES)
  foreach(test_source ${test_sources})
    cmake_path(IS_RELATIVE test_source result)
    if(result)
      cmake_path(APPEND test_source_dir ${test_source} OUTPUT_VARIABLE test_source)
    endif()
    add_boost_test(${test_source})
  endforeach()
endfunction()

add_all_test_targets()

list(APPEND installable_targets test_firo)