# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)
include(AddWindowsResources)
include(WindowsSystemConfiguration)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/config/bitcoin-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/build.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/build.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating build.h"
  VERBATIM
)
add_library(bitcoin_clientversion OBJECT EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)
target_include_directories(bitcoin_clientversion PRIVATE ${PROJECT_BINARY_DIR}/src)

#=============================
# util library
# Firo does not have util subdirectory
#=============================

add_library(bitcoin_util STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls_batchverifier.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls_ies.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls_ies.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls_worker.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls_worker.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chainparamsbase.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibc_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibcxx_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/strnlen.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/fs.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mbstring.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/random.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/protocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/cleanse.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/lockedpool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/threadinterrupt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utilmoneystr.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utilstrencodings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utiltime.cpp
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    Boost::thread
    Boost::chrono
    univalue
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
# We need SECP256K1_BUILD to prevent nonnull warnings
# Basically saying to SECP256K1 we are building it.
add_compile_definitions(SECP256K1_BUILD=1)
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
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.h
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls/bls.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/params.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/validation.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.h
  ${CMAKE_CURRENT_SOURCE_DIR}/flat-database.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/prevector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/block.h
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/precomputed_hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/transaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/transaction.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/bitcoinconsensus.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/serialize.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tinyformat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utilstrencodings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utilstrencodings.h
  ${CMAKE_CURRENT_SOURCE_DIR}/version.h
)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    secp256k1
    leveldb
    univalue
    ${BLS_DASH_LIBRARY}
  PUBLIC
    univalue
    OpenSSL::Crypto
    bitcoin_crypto
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chainparams.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chainparamsbase.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coins.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compressor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_write.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/hdmint/hdmint.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/init.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/key.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/keystore.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/bech32.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netaddress.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rawtransaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/saltedhasher.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sign.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/warnings.cpp
  $<$<BOOL:${ENABLE_CRASH_HOOKS}>:${CMAKE_CURRENT_SOURCE_DIR}/stacktraces.cpp>
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

apply_wrapped_exception_flags(bitcoin_common)

include(InstallBinaryComponent)
set(installable_targets)
if(ENABLE_WALLET)
  add_subdirectory(wallet)
endif()


# P2P and RPC server functionality used by `bitcoind` and `firo-qt` executables.
add_library(firo_node STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/activemasternode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/addrdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/batchedlogger.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/batchproof_container.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bip47/paymentcode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blockencodings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/checkpoints.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin_containers.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibc_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibcxx_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dsnotificationinterface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/cbtx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/deterministicmns.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/evodb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/mnauth.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/providertx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/simplifiedmns.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/specialtx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/evo/spork.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httprpc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httpserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/init.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantus.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/coin.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/innerproduct_proof_generator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/innerproduct_proof_verifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/joinsplit.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/lelantus_primitives.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/lelantus_prover.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/lelantus_verifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/params.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/range_prover.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/range_verifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/schnorr_prover.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/schnorr_verifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/sigmaextended_prover.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/sigmaextended_verifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/liblelantus/spend_metadata.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/aead.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/bech32.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/bpplus.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/chaum.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/coin.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/f4grumble.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/grootle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/kdf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/keys.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/mint_transaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/params.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/schnorr.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/spend_transaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/transcript.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/libspark/util.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_blockprocessor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_chainlocks.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_commitment.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_debug.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_dkgsession.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_dkgsessionhandler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_dkgsessionmgr.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_init.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_instantsend.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_signing.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_signing_shares.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/llmq/quorums_utils.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/masternode-payments.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/masternode-sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/masternode-utils.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/messagesigner.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/miner.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mtpstate.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/net.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/net_processing.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netfulfilledman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/noui.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/fees.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pow.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/primitives/mint_spend.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rest.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/blockchain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/masternode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/mining.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/misc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/net.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rawtransaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcevo.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcquorums.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/server.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/ismine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sigcache.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma/coin.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma/coinspend.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma/params.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sigma/spend_metadata.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/spark/primitives.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sparkname.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/spark/state.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/threadinterrupt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/torcontrol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txmempool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_interface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/validation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/validationinterface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/versionbits.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/warnings.cpp
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
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoind.cpp
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
  set_platform_output_name(firod FIRO_DAEMON_NAME)
  apply_wrapped_exception_flags(firod)
  list(APPEND installable_targets firod)
endif()
if(WITH_MULTIPROCESS)
  add_executable(bitcoin-node
    ${CMAKE_CURRENT_SOURCE_DIR}/bitcoind.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/init/bitcoin-node.cpp
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
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/client.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/protocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util.cpp
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
  add_executable(firo-cli ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin-cli.cpp)
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
  set_platform_output_name(firo-cli FIRO_CLI_NAME)
  apply_wrapped_exception_flags(firo-cli)
  list(APPEND installable_targets firo-cli)
endif()


if(BUILD_TX)
  add_executable(firo-tx ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin-tx.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/keystore.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.cpp
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
  set_platform_output_name(firo-tx FIRO_TX_NAME)
  apply_wrapped_exception_flags(firo-tx)
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
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin-chainstate.cpp
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
  COMPONENT GUI
)
unset(installable_targets)

if(INSTALL_MAN AND NOT WIN32)
  # Install man pages with correct Firo names
  if(BUILD_DAEMON)
    install(FILES ${PROJECT_SOURCE_DIR}/doc/man/bitcoind.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
      RENAME firod.1
    )
  endif()
  if(BUILD_CLI)
    install(FILES ${PROJECT_SOURCE_DIR}/doc/man/bitcoin-cli.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
      RENAME firo-cli.1
    )
  endif()
  if(BUILD_TX)
    install(FILES ${PROJECT_SOURCE_DIR}/doc/man/bitcoin-tx.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
      RENAME firo-tx.1
    )
  endif()
endif()