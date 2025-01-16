# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.
add_library(bitcoin_wallet STATIC EXCLUDE_FROM_ALL
    authhelper.cpp
    bip39.cpp
    crypter.cpp
    db.cpp
    lelantusjoinsplitbuilder.cpp
    mnemoniccontainer.cpp
    rpcdump.cpp
    rpcwallet.cpp
    sigmaspendbuilder.cpp
    txbuilder.cpp
    wallet.cpp
    walletdb.cpp
    walletexcept.cpp
)

target_link_libraries(bitcoin_wallet
  PRIVATE
    core_interface
    bitcoin_common
    univalue
    Boost::headers
    secp256k1
    leveldb
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

# Firo only supports BDB for wallet storage.
target_link_libraries(bitcoin_wallet PUBLIC BerkeleyDB::BerkeleyDB)