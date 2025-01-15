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

# Check all endian conversion functions for 16-bit
check_function_exists_and_define(htobe16 bitcoin_crypto PRIVATE HAVE_DECL_HTOBE16)
check_function_exists_and_define(htole16 bitcoin_crypto PRIVATE HAVE_DECL_HTOLE16)
check_function_exists_and_define(be16toh bitcoin_crypto PRIVATE HAVE_DECL_BE16TOH)
check_function_exists_and_define(le16toh bitcoin_crypto PRIVATE HAVE_DECL_LE16TOH)

# Check all endian conversion functions for 32-bit
check_function_exists_and_define(htobe32 bitcoin_crypto PRIVATE HAVE_DECL_HTOBE32)
check_function_exists_and_define(htole32 bitcoin_crypto PRIVATE HAVE_DECL_HTOLE32)
check_function_exists_and_define(be32toh bitcoin_crypto PRIVATE HAVE_DECL_BE32TOH)
check_function_exists_and_define(le32toh bitcoin_crypto PRIVATE HAVE_DECL_LE32TOH)

# Check all endian conversion functions for 64-bit
check_function_exists_and_define(htobe64 bitcoin_crypto PRIVATE HAVE_DECL_HTOBE64)
check_function_exists_and_define(htole64 bitcoin_crypto PRIVATE HAVE_DECL_HTOLE64)
check_function_exists_and_define(be64toh bitcoin_crypto PRIVATE HAVE_DECL_BE64TOH)
check_function_exists_and_define(le64toh bitcoin_crypto PRIVATE HAVE_DECL_LE64TOH)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)
