# Copyright 2013 Corgan Labs
# This file is part of the Zerocoin project
# See LICENSE file or http://opensource.org/licenses/MIT for terms

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Prevented in-tree build. This is bad practice.")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE "Release")
   message(STATUS "Build type not specified: defaulting to release.")
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "")

#
# Setup overall project
#
cmake_minimum_required(VERSION 2.8)
project(zerocoin)

# Appended to CMAKE_INSTALL_PREFIX
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake/Modules)

#
# Project-wide package dependencies
#
# Find and configure the Boost C++ libraries
include(BoostConfig)

# Find and configure OpenSSL crypto library
include(FindOpenSSL)

#
# Project-wide directory settings
#
set(BITCOIN_BIGNUM_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/bitcoin_bignum)

#
# Project-wide installation settings
#
set(ZEROCOIN_INCLUDE_DIR include/zerocoin)
set(ZEROCOIN_BIN_DIR     bin)
set(ZEROCOIN_LIB_DIR     lib)

#
# pkg-config substitution variables
#
file(TO_NATIVE_PATH "${CMAKE_INSTALL_PREFIX}"             prefix)
file(TO_NATIVE_PATH "\${prefix}"                          exec_prefix)
file(TO_NATIVE_PATH "\${exec_prefix}/${ZEROCOIN_LIB_DIR}" libdir)
file(TO_NATIVE_PATH "\${prefix}/${ZEROCOIN_INCLUDE_DIR}"  includedir)

#
# Add individual directories to project
#
#add_subdirectory(foo)

#
# Create uninstall target
#
configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/cmake_uninstall.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
@ONLY)

add_custom_target(uninstall
  ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

########################################################################
# Shared library generation libzerocoin.so
########################################################################

#
# Tell compiler where to search for include files
#
include_directories(
  ${BITCOIN_BIGNUM_INCLUDE_DIR}
  ${Boost_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
)

#
# Tell linker where to look for library files
#
link_directories(
  ${Boost_LIBRARY_DIRS}
)

#
# List of libraries to link in
#
list(APPEND zerocoin_libs
  ${Boost_LIBRARIES}
  ${OPENSSL_CRYPTO_LIBRARY}
)

#
# List of source files to compile
#
list(APPEND zerocoin_sources
  Accumulator.cpp
  AccumulatorProofOfKnowledge.cpp
  Coin.cpp
  CoinSpend.cpp
  Commitment.cpp
  ParamGeneration.cpp
  Params.cpp
  SerialNumberSignatureOfKnowledge.cpp
  SpendMetaData.cpp
)

#
# Create shared library libzerocoin.so
#
add_library(zerocoin SHARED ${zerocoin_sources})
target_link_libraries(zerocoin ${zerocoin_libs})

#
# Install shared library
#
install(TARGETS zerocoin
  LIBRARY DESTINATION ${ZEROCOIN_LIB_DIR}
)

#
# Install header files
#
install(FILES
  bitcoin_bignum/allocators.h
  bitcoin_bignum/bignum.h
  bitcoin_bignum/clientversion.h
  bitcoin_bignum/compat.h
  bitcoin_bignum/hash.h
  bitcoin_bignum/netbase.h
  bitcoin_bignum/serialize.h
  bitcoin_bignum/uint256.h
  bitcoin_bignum/version.h
  DESTINATION ${ZEROCOIN_INCLUDE_DIR}/bitcoin_bignum
)

install(FILES
  Accumulator.h
  AccumulatorProofOfKnowledge.h
  Coin.h
  CoinSpend.h
  Commitment.h
  ParamGeneration.h
  Params.h
  SerialNumberSignatureOfKnowledge.h
  SpendMetaData.h
  Zerocoin.h
  DESTINATION ${ZEROCOIN_INCLUDE_DIR}
)

#
# Create pkg-config file
#
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/zerocoin.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/zerocoin.pc
@ONLY)

#
# Install pkg-config file
#
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/zerocoin.pc
  DESTINATION ${ZEROCOIN_LIB_DIR}/pkgconfig
)

########################################################################
# Executable files
########################################################################

add_executable(paramgen paramgen.cpp)
target_link_libraries(paramgen zerocoin)

add_executable(benchmark Benchmark.cpp)
target_link_libraries(benchmark zerocoin)

add_executable(test Tests.cpp)
target_link_libraries(test zerocoin)

add_executable(tutorial Tutorial.cpp)
target_link_libraries(tutorial zerocoin)
