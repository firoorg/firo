# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.

add_library(firo_wallet STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/../activemasternode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../masternode-sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../lelantus.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdmint/hdmint.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdmint/mintpool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdmint/wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdmint/tracker.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../spark/state.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../spark/sparkwallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../spark/primitives.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../policy/rbf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../bip47/account.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../bip47/paymentchannel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../bip47/bip47utils.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../bip47/paymentcode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../bip47/secretpoint.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../primitives/mint_spend.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bip39.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/mnemoniccontainer.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/db.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpcdump.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpcwallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txbuilder.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lelantusjoinsplitbuilder.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletexcept.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/authhelper.cpp
)
target_link_libraries(firo_wallet
  PUBLIC
    core_interface
    bitcoin_util
    univalue
    secp256k1
    Boost::headers
    leveldb
)

# Firo only supports BDB for wallet storage.
target_link_libraries(firo_wallet PUBLIC BerkeleyDB::BerkeleyDB)