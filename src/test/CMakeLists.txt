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
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/allocator_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/amount_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base32_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base58_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base64_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bip32_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bip47_test_data.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bip47_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bip47_serialization_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blockencodings_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bswap_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/checkqueue_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coins_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compress_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cuckoocache_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/DoS_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/fixtures.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/fixtures.h
  ${CMAKE_CURRENT_SOURCE_DIR}/getarg_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/hash_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/key_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantus_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantus_mintspend_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantus_state_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma_lelantus_transition.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/limitedmap_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/main_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mbstring_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mempool_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/merkle_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/miner_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mtp_halving_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mtp_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mtp_trans_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/firopow_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/multisig_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/net_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pmt_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/prevector_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/raii_event_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/random_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/reverselock_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sanity_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/scriptnum10.h
  ${CMAKE_CURRENT_SOURCE_DIR}/scriptnum_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script_P2SH_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/serialize_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sighash_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma_manymintspend_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma_mintspend_numinputs.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma_mintspend_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma_state_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigopcount_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/skiplist_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/streams_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/test_bitcoin.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/test_bitcoin.h
  ${CMAKE_CURRENT_SOURCE_DIR}/test_random.h
  ${CMAKE_CURRENT_SOURCE_DIR}/testutil.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/testutil.h
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transaction_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txvalidationcache_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/multiexponentation_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/firsthalving_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evospork_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo_deterministicmns_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo_simplifiedmns_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/progpow_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sparkname_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdmint/test/lelantus_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/challenge_generator_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/coin_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/inner_product_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/joinsplit_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/lelantus_primitives_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/lelantus_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/lelantus_test_fixture.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/lelantus_test_fixture.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/range_proof_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/schnorr_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/ownership_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/serialize_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../liblelantus/test/sigma_extended_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/transcript_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/schnorr_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/chaum_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/bpplus_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/grootle_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/aead_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/encrypt_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/coin_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/mint_transaction_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/spend_transaction_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/f4grumble_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../libspark/test/address_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../test/spark_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../test/spark_state_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../test/spark_mintspend_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/coin_spend_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/coin_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/primitives_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/protocol_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/r1_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/serialize_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../sigma/test/sigma_primitive_types_test.cpp
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
    ${CMAKE_CURRENT_SOURCE_DIR}/ipc_tests.cpp
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