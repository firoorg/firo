function(add_spark_fuzz_target target source)
  add_executable(${target} ${source})
  target_link_libraries(${target}
    core_interface
    warn_interface
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
    bitcoin_util
    Boost::filesystem
    Boost::program_options
  )
  if(NOT FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION)
    target_sources(${target} PRIVATE fuzz.cpp)
  endif()
endfunction()

add_spark_fuzz_target(fuzz_spark_spend_parser spark_spend_parser.cpp)
add_spark_fuzz_target(
  fuzz_spark_spend_v1_parser
  ../../fuzz/libspark/spend_transaction_fuzz.cpp
)
add_spark_fuzz_target(
  fuzz_spark_spend_v2_parser
  ../../fuzz/libspark/spend_transaction_v2_payload_fuzz.cpp
)
