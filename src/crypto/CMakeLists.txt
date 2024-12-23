# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  progpow.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha512.cpp
  ../support/cleanse.cpp
)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)
