cmake_minimum_required(VERSION 3.30)
project(spats)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include
${CMAKE_CURRENT_SOURCE_DIR}/.
${CMAKE_CURRENT_SOURCE_DIR}/..
${CMAKE_CURRENT_SOURCE_DIR}/../univalue/include
${CMAKE_CURRENT_SOURCE_DIR}/../leveldb/include
${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/include)

add_definitions(-DHAVE_DECL_HTOBE16=1 -DHAVE_DECL_HTOLE16=1 -DHAVE_DECL_BE16TOH=1 -DHAVE_DECL_LE16TOH=1
        -DHAVE_DECL_HTOBE32=1 -DHAVE_DECL_HTOLE32=1 -DHAVE_DECL_BE32TOH=1 -DHAVE_DECL_LE32TOH=1
        -DHAVE_DECL_HTOBE64=1 -DHAVE_DECL_HTOLE64=1 -DHAVE_DECL_BE64TOH=1 -DHAVE_DECL_LE64TOH=1
)

add_library(spats STATIC
        spark_asset.hpp
        registry.cpp
        registry.hpp
        base_asset.hpp
        identification.hpp
        wallet.cpp
        wallet.hpp
        actions.hpp
        ../utils/constrained_value.hpp
        ../utils/enum.hpp
        ../utils/math.hpp
        ../utils/scaled_amount.hpp
        manager.cpp
        manager.hpp)
