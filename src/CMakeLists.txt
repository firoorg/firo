# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)
include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
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
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    secp256k1
    leveldb
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
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
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
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
set(CMAKE_EXPORT_COMPILE_COMMANDS OFF)
add_subdirectory(secp256k1)
set_target_properties(secp256k1 PROPERTIES
  EXCLUDE_FROM_ALL TRUE
)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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
)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    secp256k1
    leveldb
  PUBLIC
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
)
target_link_libraries(bitcoin_common
  PUBLIC
    core_interface
    bitcoin_consensus
    bitcoin_util
    univalue
    secp256k1
    Boost::headers
    leveldb
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

set(installable_targets)
if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(bitcoin-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    add_windows_resources(bitcoin-wallet bitcoin-wallet-res.rc)
    target_link_libraries(bitcoin-wallet
      core_interface
      bitcoin_wallet
      bitcoin_common
      bitcoin_util
      Boost::headers
    )
    list(APPEND installable_targets bitcoin-wallet)
  endif()
endif()


# P2P and RPC server functionality used by `bitcoind` and `bitcoin-qt` executables.
add_library(bitcoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  blockencodings.cpp
  chain.cpp
  consensus/tx_verify.cpp
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
)
target_link_libraries(bitcoin_node
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_util
    secp256k1
    $<TARGET_NAME_IF_EXISTS:bitcoin_zmq>
    leveldb
    univalue
    Boost::headers
    Boost::thread
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

# Bitcoin Core bitcoind.
if(BUILD_DAEMON)
  add_executable(bitcoind
    bitcoind.cpp
  )
  add_windows_resources(bitcoind bitcoind-res.rc)
  target_link_libraries(bitcoind
    core_interface
    bitcoin_node
    univalue
    Boost::thread
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  list(APPEND installable_targets bitcoind)
endif()
if(WITH_MULTIPROCESS)
  add_executable(bitcoin-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  target_link_libraries(bitcoin-node
    core_interface
    bitcoin_node
    bitcoin_ipc
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
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


add_library(bitcoin_cli STATIC EXCLUDE_FROM_ALL
  rpc/client.cpp
  rpc/protocol.cpp
  util.cpp
)
target_link_libraries(bitcoin_cli
  PUBLIC
    core_interface
    univalue
    Boost::filesystem
    Boost::thread
    Boost::program_options
)
target_include_directories(bitcoin_cli
  PUBLIC
)

# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(bitcoin-cli bitcoin-cli.cpp)
  add_windows_resources(bitcoin-cli bitcoin-cli-res.rc)
  target_link_libraries(bitcoin-cli
    core_interface
    bitcoin_cli
    bitcoin_common
    bitcoin_util
    libevent::extra
    libevent::core
  )
  list(APPEND installable_targets bitcoin-cli)
  set_target_properties(bitcoin-cli PROPERTIES OUTPUT_NAME ${FIRO_CLI_NAME})
endif()


if(BUILD_TX)
  add_executable(bitcoin-tx bitcoin-tx.cpp)
  add_windows_resources(bitcoin-tx bitcoin-tx-res.rc)
  target_link_libraries(bitcoin-tx
    core_interface
    bitcoin_common
    bitcoin_util
    univalue
  )
  list(APPEND installable_targets bitcoin-tx)
endif()


if(BUILD_UTIL)
  add_executable(bitcoin-util bitcoin-util.cpp)
  add_windows_resources(bitcoin-util bitcoin-util-res.rc)
  target_link_libraries(bitcoin-util
    core_interface
    bitcoin_common
    bitcoin_util
  )
  list(APPEND installable_targets bitcoin-util)
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