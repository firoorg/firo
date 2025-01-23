# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_subdirectory(progpow)

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
  scrypt.cpp
  MerkleTreeProof/arith_uint256.cpp
  MerkleTreeProof/blake2
  MerkleTreeProof/core.c
  MerkleTreeProof/merkle-tree.cpp
  MerkleTreeProof/mtp.cpp
  MerkleTreeProof/ref.c
  MerkleTreeProof/thread.c
  MerkleTreeProof/blake2/blake2b.c
  MerkleTreeProof/crypto/sha256.cpp
  Lyra2Z/Lyra2.c
  Lyra2Z/Lyra2Z.c
  Lyra2Z/Sponge.c
  Lyra2Z/blake.c
  ../support/cleanse.cpp
)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
    ${Boost_LIBRARIES}
  PUBLIC 
    ethash
    keccak
)

target_include_directories(bitcoin_crypto
  PUBLIC
  ${Boost_INCLUDE_DIR}
)