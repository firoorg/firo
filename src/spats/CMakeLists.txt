cmake_minimum_required(VERSION 3.30)
project(spats)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include
${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include/QtCore
${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include/QtGui
${CMAKE_CURRENT_SOURCE_DIR}/../../depends/x86_64-pc-linux-gnu/include/QtWidgets
${CMAKE_CURRENT_SOURCE_DIR}/.
${CMAKE_CURRENT_SOURCE_DIR}/..
${CMAKE_CURRENT_SOURCE_DIR}/../qt/forms
${CMAKE_CURRENT_SOURCE_DIR}/../univalue/include
${CMAKE_CURRENT_SOURCE_DIR}/../leveldb/include
${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1/include)

add_definitions(-DHAVE_DECL_HTOBE16=1 -DHAVE_DECL_HTOLE16=1 -DHAVE_DECL_BE16TOH=1 -DHAVE_DECL_LE16TOH=1
        -DHAVE_DECL_HTOBE32=1 -DHAVE_DECL_HTOLE32=1 -DHAVE_DECL_BE32TOH=1 -DHAVE_DECL_LE32TOH=1
        -DHAVE_DECL_HTOBE64=1 -DHAVE_DECL_HTOLE64=1 -DHAVE_DECL_BE64TOH=1 -DHAVE_DECL_LE64TOH=1
)

add_library(spats STATIC
        spark_asset.cpp
        spark_asset.hpp
        registry.cpp
        registry.hpp
        base_asset.hpp
        identification.hpp
        wallet.cpp
        wallet.hpp
        actions.hpp
        manager.cpp
        manager.hpp
        modification.hpp
        modification.cpp
        user_confirmation.hpp
        ../utils/constexpr_string.hpp
        ../utils/constrained_value.hpp
        ../utils/empty_class.hpp
        ../utils/enum.hpp
        ../utils/lock_proof.hpp
        ../utils/math.hpp
        ../utils/overloaded.hpp
        ../utils/scaled_amount.hpp
        ../utils/scope_exit.hpp
        ../utils/string.hpp
        ../utils/string.cpp
        ../utils/traits.hpp)
