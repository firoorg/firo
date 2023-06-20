# This file is used for IDE purposes only. We don't build with it.

set(CMAKE_CXX_STANDARD 14)

cmake_minimum_required(VERSION 3.0)

project(firod CXX)

add_definitions(-DENABLE_WALLET=1)
add_definitions(-DENABLE_ELYSIUM=1)
set(ENABLE_WALLET ON)
set(ENABLE_ELYSIUM ON)
set(INCLUDE_DIRS src src/univalue/include src/client-api src/zmq src/zmqserver src/wallet src/qt src/qt/forms src/hdmint src/elysium src/crypto src/leveldb/include src/secp256k1 src/secp256k1/include src/secp256k1/cpp src/bls)
include_directories(${INCLUDE_DIRS})

file(GLOB_RECURSE SRC_FILES *.h *.cpp *.ui)
add_executable(firod ${SRC_FILES})

unset(ENV{LC_ALL})
unset(ENV{LC_CTYPE})
unset(ENV{LANG})
execute_process(COMMAND make -C ${CMAKE_SOURCE_DIR}/depends print-HOST
    OUTPUT_STRIP_TRAILING_WHITESPACE
    OUTPUT_VARIABLE __DEPENDS_TARGET)
string(REPLACE "=" ";" _DEPENDS_TARGET ${__DEPENDS_TARGET})
list(GET _DEPENDS_TARGET 1 DEPENDS_TARGET)
set(DEPENDS_INCLUDE depends/${DEPENDS_TARGET}/include)
include_directories(${DEPENDS_INCLUDE} ${DEPENDS_INCLUDE}/QtAccessibilitySupport ${DEPENDS_INCLUDE}/QtClipboardSupport
    ${DEPENDS_INCLUDE}/QtCore ${DEPENDS_INCLUDE}/QtDeviceDiscoverySupport ${DEPENDS_INCLUDE}/QtEdidSupport
    ${DEPENDS_INCLUDE}/QtEventDispatcherSupport ${DEPENDS_INCLUDE}/QtFbSup ${DEPENDS_INCLUDE}/QtNetwork
    ${DEPENDS_INCLUDE}/QtPlatformHeaders ${DEPENDS_INCLUDE}/QtPrintSupport ${DEPENDS_INCLUDE}/QtServiceSupport
    ${DEPENDS_INCLUDE}/QtTest ${DEPENDS_INCLUDE}/QtThemeSupport ${DEPENDS_INCLUDE}/QtWidgets
)