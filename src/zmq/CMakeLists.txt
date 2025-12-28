# Copyright (c) 2023-present The firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(firo_zmq STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/zmqabstractnotifier.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/zmqnotificationinterface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/zmqpublishnotifier.cpp
)
target_compile_definitions(firo_zmq
  INTERFACE
    ENABLE_ZMQ=1
  PRIVATE
    $<$<BOOL:${WIN32}>:ZMQ_STATIC>
)
target_link_libraries(firo_zmq
  PRIVATE
    core_interface
    univalue
    zeromq
    secp256k1
    leveldb
)
