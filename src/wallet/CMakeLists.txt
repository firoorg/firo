# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.

add_library(firo_wallet STATIC EXCLUDE_FROM_ALL
  ../activemasternode.cpp
  ../masternode-sync.cpp
  ../sigma.cpp
  ../lelantus.cpp
  ../hdmint/hdmint.cpp
  ../hdmint/mintpool.cpp
  ../hdmint/wallet.cpp
  ../hdmint/tracker.cpp
  ../spark/state.cpp
  ../spark/sparkwallet.cpp
  ../spark/primitives.cpp
  ../policy/rbf.cpp
  ../bip47/account.cpp
  ../bip47/paymentchannel.cpp
  ../bip47/bip47utils.cpp
  ../bip47/paymentcode.cpp
  ../bip47/secretpoint.cpp
  ../primitives/mint_spend.cpp 
  crypter.cpp
  bip39.cpp
  mnemoniccontainer.cpp
  db.cpp
  rpcdump.cpp
  rpcwallet.cpp
  sigmaspendbuilder.cpp
  txbuilder.cpp
  lelantusjoinsplitbuilder.cpp
  walletexcept.cpp
  wallet.cpp
  walletdb.cpp
  authhelper.cpp
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