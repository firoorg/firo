# Copyright (c) 2023-present The firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(firo_zmq STATIC EXCLUDE_FROM_ALL
  zmqabstractnotifier.cpp
  zmqnotificationinterface.cpp
  zmqpublishnotifier.cpp
)
target_compile_definitions(firo_zmq
  INTERFACE
    ENABLE_ZMQ=1
)
target_link_libraries(firo_zmq
  PRIVATE
    core_interface
    univalue
    zeromq
    secp256k1
    leveldb
)
