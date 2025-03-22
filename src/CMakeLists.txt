# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)
include(AddWindowsResources)
include(WindowsSystemConfiguration)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/config/bitcoin-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating bitcoin-build-info.h"
  VERBATIM
)
add_library(bitcoin_clientversion OBJECT EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)

#=============================
# util library
# Firo does not have util subdirectory
#=============================

add_library(bitcoin_util STATIC EXCLUDE_FROM_ALL
  fs.cpp
  utilmoneystr.cpp
  policy/rbf.cpp
  utilstrencodings.cpp
  mbstring.cpp
  threadinterrupt.cpp
  utiltime.cpp
  random.cpp
  sync.cpp
  support/lockedpool.cpp
  bls/bls_batchverifier.h
  bls/bls_ies.cpp
  bls/bls_ies.h
  bls/bls_worker.cpp
  bls/bls_worker.h
  support/lockedpool.cpp
  chainparamsbase.cpp
  clientversion.cpp
  compat/glibc_sanity.cpp
  compat/glibcxx_sanity.cpp
  compat/strnlen.cpp
  mbstring.cpp
  fs.cpp
  random.cpp
  rpc/protocol.cpp
  support/cleanse.cpp
  sync.cpp
  threadinterrupt.cpp
  util.cpp
  utilmoneystr.cpp
  utilstrencodings.cpp
  utiltime.cpp
  crypto/scrypt.cpp
  primitives/block.cpp
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    Boost::thread
    Boost::chrono
    secp256k1
    leveldb
    univalue
    $<$<BOOL:${WIN32}>:windows_system>
)

add_subdirectory(crypto)
add_subdirectory(univalue)
if(WITH_MULTIPROCESS)
  add_subdirectory(ipc)
endif()

#=============================
# secp256k1 subtree
#=============================
message("")
message("Configuring secp256k1 subtree...")
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
if(NOT BUILD_TESTS)
  # Always skip the ctime tests, if we are building no other tests.
  # Otherwise, they are built if Valgrind is available. See SECP256K1_VALGRIND.
  set(SECP256K1_BUILD_CTIME_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
endif()
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
include(GetTargetInterface)
# -fsanitize and related flags apply to both C++ and C,
# so we can pass them down to libsecp256k1 as CFLAGS and LDFLAGS.
get_target_interface(core_sanitizer_cxx_flags "" sanitize_interface COMPILE_OPTIONS)
set(SECP256K1_APPEND_CFLAGS ${core_sanitizer_cxx_flags} CACHE STRING "" FORCE)
unset(core_sanitizer_cxx_flags)
get_target_interface(core_sanitizer_linker_flags "" sanitize_interface LINK_OPTIONS)
set(SECP256K1_APPEND_LDFLAGS ${core_sanitizer_linker_flags} CACHE STRING "" FORCE)
unset(core_sanitizer_linker_flags)
# We want to build libsecp256k1 with the most tested RelWithDebInfo configuration.
enable_language(C)
foreach(config IN LISTS CMAKE_BUILD_TYPE CMAKE_CONFIGURATION_TYPES)
  if(config STREQUAL "")
    continue()
  endif()
  string(TOUPPER "${config}" config)
  set(CMAKE_C_FLAGS_${config} "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
endforeach()
# If the CFLAGS environment variable is defined during building depends
# and configuring this build system, its content might be duplicated.
if(DEFINED ENV{CFLAGS})
  deduplicate_flags(CMAKE_C_FLAGS)
endif()
add_subdirectory(secp256k1)
set_target_properties(secp256k1 PROPERTIES
  EXCLUDE_FROM_ALL TRUE
)
string(APPEND CMAKE_C_COMPILE_OBJECT " ${APPEND_CPPFLAGS} ${APPEND_CFLAGS}")

add_library(bitcoin_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/merkle.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
  amount.h
  arith_uint256.cpp
  arith_uint256.h
  bls/bls.cpp
  bls/bls.h
  consensus/merkle.cpp
  consensus/merkle.h
  consensus/params.h
  consensus/validation.h
  hash.cpp
  flat-database.h
  hash.h
  prevector.h
  crypto/scrypt.h
  primitives/block.h
  primitives/precomputed_hash.h
  primitives/transaction.cpp
  primitives/transaction.h
  pubkey.cpp
  pubkey.h
  script/bitcoinconsensus.cpp
  script/interpreter.cpp
  script/interpreter.h
  script/script.cpp
  script/script.h
  script/script_error.cpp
  script/script_error.h
  serialize.h
  tinyformat.h
  uint256.cpp
  uint256.h
  utilstrencodings.cpp
  utilstrencodings.h
  version.h
)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    secp256k1
    leveldb
    ${BLS_DASH_LIBRARY}
  PUBLIC
    OpenSSL::Crypto
    bitcoin_crypto
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  base58.cpp
  libspark/bech32.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  bloom.cpp
  init.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  chainparams.cpp
  key.cpp
  merkleblock.cpp
  netaddress.cpp
  netbase.cpp
  policy/policy.cpp
  protocol.cpp
  rpc/rawtransaction.cpp
  scheduler.cpp
  script/sign.cpp
  amount.cpp
  base58.cpp
  chainparams.cpp
  coins.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  hdmint/hdmint.cpp
  key.cpp
  keystore.cpp
  netaddress.cpp
  netbase.cpp
  protocol.cpp
  saltedhasher.cpp
  scheduler.cpp
  script/sign.cpp
  script/standard.cpp
  warnings.cpp
  $<$<BOOL:${ENABLE_CRASH_HOOKS}>:stacktraces.cpp>
)
target_link_libraries(bitcoin_common
  PUBLIC
    core_interface
    bitcoin_consensus
    bitcoin_util
    univalue
    secp256k1
    Boost::headers
    $<$<BOOL:ENABLE_CRASH_HOOKS>:${BACKTRACE_LIBRARY}>
    leveldb
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<BOOL:${WIN32}>:windows_system>
)

if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
  target_compile_options(bitcoin_common PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
endif()

include(InstallBinaryComponent)
set(installable_targets)
if(ENABLE_WALLET)
  add_subdirectory(wallet)
endif()


# P2P and RPC server functionality used by `bitcoind` and `firo-qt` executables.
add_library(firo_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  blockencodings.cpp
  chain.cpp
  dbwrapper.cpp
  httprpc.cpp
  httpserver.cpp
  init.cpp
  chain.cpp
  net.cpp
  net_processing.cpp
  miner.cpp
  warnings.cpp
  noui.cpp
  policy/fees.cpp
  policy/rbf.cpp
  pow.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/server.cpp
  script/sigcache.cpp
  torcontrol.cpp
  txdb.cpp
  txmempool.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  ui_interface.cpp
  compat/glibc_sanity.cpp
  compat/glibcxx_sanity.cpp
  activemasternode.cpp
  addrman.cpp
  addrdb.cpp
  batchedlogger.cpp
  bloom.cpp
  blockencodings.cpp
  chain.cpp
  checkpoints.cpp
  dsnotificationinterface.cpp
  evo/cbtx.cpp
  evo/deterministicmns.cpp
  evo/evodb.cpp
  evo/mnauth.cpp
  evo/providertx.cpp
  evo/simplifiedmns.cpp
  evo/specialtx.cpp
  evo/spork.cpp
  llmq/quorums.cpp
  llmq/quorums_blockprocessor.cpp
  llmq/quorums_commitment.cpp
  llmq/quorums_chainlocks.cpp
  llmq/quorums_debug.cpp
  llmq/quorums_dkgsessionhandler.cpp
  llmq/quorums_dkgsessionmgr.cpp
  llmq/quorums_dkgsession.cpp
  llmq/quorums_init.cpp
  llmq/quorums_instantsend.cpp
  llmq/quorums_signing.cpp
  llmq/quorums_signing_shares.cpp
  llmq/quorums_utils.cpp
  masternode-payments.cpp
  masternode-sync.cpp
  masternode-utils.cpp
  httprpc.cpp
  httpserver.cpp
  init.cpp
  dbwrapper.cpp
  threadinterrupt.cpp
  merkleblock.cpp
  miner.cpp
  messagesigner.cpp
  net.cpp
  netfulfilledman.cpp
  net_processing.cpp
  noui.cpp
  policy/fees.cpp
  policy/policy.cpp
  primitives/mint_spend.cpp
  pow.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/masternode.cpp
  rpc/mining.cpp
  rpc/misc.cpp
  rpc/net.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/rpcevo.cpp
  rpc/rpcquorums.cpp
  script/sigcache.cpp
  script/ismine.cpp
  timedata.cpp
  torcontrol.cpp
  txdb.cpp
  txmempool.cpp
  ui_interface.cpp
  batchproof_container.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  sigma.cpp
  lelantus.cpp
  bip47/paymentcode.cpp
  spark/state.cpp
  spark/primitives.cpp
  coin_containers.cpp
  mtpstate.cpp
  sigma/coin.cpp
  sigma/coinspend.cpp
  sigma/spend_metadata.cpp
  sigma/params.cpp
  liblelantus/lelantus_primitives.cpp
  liblelantus/lelantus_prover.cpp
  liblelantus/lelantus_verifier.cpp
  liblelantus/sigmaextended_prover.cpp
  liblelantus/sigmaextended_verifier.cpp
  liblelantus/schnorr_prover.cpp
  liblelantus/schnorr_verifier.cpp
  liblelantus/innerproduct_proof_verifier.cpp
  liblelantus/innerproduct_proof_generator.cpp
  liblelantus/range_prover.cpp
  liblelantus/range_verifier.cpp
  liblelantus/coin.cpp
  liblelantus/joinsplit.cpp
  liblelantus/spend_metadata.cpp
  liblelantus/params.cpp
  libspark/transcript.cpp
  libspark/params.cpp
  libspark/schnorr.cpp
  libspark/chaum.cpp
  libspark/coin.cpp
  libspark/bpplus.cpp
  libspark/grootle.cpp
  libspark/keys.cpp
  libspark/util.cpp
  libspark/aead.cpp
  libspark/kdf.cpp
  libspark/hash.cpp
  libspark/mint_transaction.cpp
  libspark/spend_transaction.cpp
  libspark/f4grumble.cpp
  libspark/bech32.cpp
)

target_link_libraries(firo_node
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_util
    secp256k1
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    leveldb
    univalue
    Boost::headers
    Boost::thread
    OpenSSL::Crypto
    ${TOR_LIBRARY}
    OpenSSL::SSL
    ${MINIUPNP_LIBRARY}
    ${ZLIB_LIBRARY}
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<BOOL:${WIN32}>:windows_system>
)

# Bitcoin Core firod.
if(BUILD_DAEMON)
  add_executable(firod
    bitcoind.cpp
  )
  add_windows_resources(firod bitcoind-res.rc)
  target_link_libraries(firod
    core_interface
    univalue
    Boost::thread
    firo_node
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    firo_cli
    secp256k1
    secp256k1pp
    $<TARGET_NAME_IF_EXISTS:firo_wallet>
    ${TOR_LIBRARY}
    $<$<BOOL:${WIN32}>:windows_system>
  )
  if(WIN32)
    set_target_properties(firod PROPERTIES OUTPUT_NAME "${FIRO_DAEMON_NAME}.exe")
  else()
    set_target_properties(firod PROPERTIES OUTPUT_NAME "${FIRO_DAEMON_NAME}")
  endif()
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    target_compile_options(firod PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
  endif()
  list(APPEND installable_targets firod)
endif()
if(WITH_MULTIPROCESS)
  add_executable(bitcoin-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  target_link_libraries(bitcoin-node
    core_interface
    firo_node
    bitcoin_ipc
    $<TARGET_NAME_IF_EXISTS:firo_wallet>
  )
  list(APPEND installable_targets bitcoin-node)

  if(BUILD_TESTS)
    # bitcoin_ipc_test library target is defined here in src/CMakeLists.txt
    # instead of src/test/CMakeLists.txt so capnp files in src/test/ are able to
    # reference capnp files in src/ipc/capnp/ by relative path. The Cap'n Proto
    # compiler only allows importing by relative path when the importing and
    # imported files are underneath the same compilation source prefix, so the
    # source prefix must be src/, not src/test/
    add_library(bitcoin_ipc_test STATIC EXCLUDE_FROM_ALL
      test/ipc_test.cpp
    )
    target_capnp_sources(bitcoin_ipc_test ${PROJECT_SOURCE_DIR}
      test/ipc_test.capnp
    )
    add_dependencies(bitcoin_ipc_test bitcoin_ipc_headers)
  endif()
endif()


add_library(firo_cli STATIC EXCLUDE_FROM_ALL
  rpc/client.cpp
  rpc/protocol.cpp
  util.cpp
)
target_link_libraries(firo_cli
  PUBLIC
    core_interface
    univalue
    Boost::filesystem
    Boost::thread
    Boost::program_options
    firo_node
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    $<TARGET_NAME_IF_EXISTS:firo_wallet>
    ${TOR_LIBRARY}
    $<$<BOOL:${WIN32}>:windows_system>
)
target_include_directories(firo_cli
  PUBLIC
)

# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(firo-cli bitcoin-cli.cpp)
  add_windows_resources(firo-cli bitcoin-cli-res.rc)
  target_link_libraries(firo-cli
    core_interface
    univalue
    firo_node
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    firo_cli
    $<TARGET_NAME_IF_EXISTS:firo_wallet>
    ${TOR_LIBRARY}
    $<$<BOOL:${WIN32}>:windows_system>
  )
  if(WIN32)
    set_target_properties(firo-cli PROPERTIES OUTPUT_NAME "${FIRO_CLI_NAME}.exe")
  else()
    set_target_properties(firo-cli PROPERTIES OUTPUT_NAME "${FIRO_CLI_NAME}")
  endif()
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    target_compile_options(firo-cli PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
  endif()
  list(APPEND installable_targets firo-cli)
endif()


if(BUILD_TX)
  add_executable(firo-tx bitcoin-tx.cpp 
    keystore.cpp
    script/standard.cpp
  )
  add_windows_resources(firo-tx bitcoin-tx-res.rc)
  target_link_libraries(firo-tx
    core_interface
    bitcoin_crypto    
    firo_cli
    bitcoin_common
    bitcoin_util
    univalue
    secp256k1pp
    secp256k1
    $<$<BOOL:${WIN32}>:windows_system>
    $<$<BOOL:${WIN32}>:OpenSSL::Crypto>
  )
  if(WIN32)
    set_target_properties(firo-tx PROPERTIES OUTPUT_NAME "${FIRO_TX_NAME}.exe")
  else()
    set_target_properties(firo-tx PROPERTIES OUTPUT_NAME "${FIRO_TX_NAME}")
  endif()
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    target_compile_options(firo-tx PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
  endif()
  list(APPEND installable_targets firo-tx)
endif()



if(BUILD_GUI)
  add_subdirectory(qt)
endif()


if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
endif()

if(BUILD_UTIL_CHAINSTATE)
  add_executable(bitcoin-chainstate
    bitcoin-chainstate.cpp
  )
  # TODO: The `SKIP_BUILD_RPATH` property setting can be deleted
  #       in the future after reordering Guix script commands to
  #       perform binary checks after the installation step.
  # Relevant discussions:
  # - https://github.com/hebasto/bitcoin/pull/236#issuecomment-2183120953
  # - https://github.com/bitcoin/bitcoin/pull/30312#issuecomment-2191235833
  set_target_properties(bitcoin-chainstate PROPERTIES
    SKIP_BUILD_RPATH OFF
  )
  target_link_libraries(bitcoin-chainstate
    PRIVATE
      core_interface
      bitcoinkernel
  )
endif()


if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()


install(TARGETS ${installable_targets}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
unset(installable_targets)

if(INSTALL_MAN)
  # TODO: these stubs are no longer needed. man pages should be generated at install time.
  install(DIRECTORY ../doc/man/
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    FILES_MATCHING PATTERN *.1
  )
endif()