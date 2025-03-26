# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(WIN32 OR MINGW)
  message(FATAL_ERROR "The Qt tests are not supported on Windows")
endif()

set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(test_firo-qt
  compattests.cpp
  rpcnestedtests.cpp
  test_main.cpp
  uritests.cpp
  test_sendcoinsentry.cpp
  ../../test/test_bitcoin.cpp
  ../../test/testutil.cpp
)

# Add this to skip specific files from UIC processing
set_source_files_properties(
    ../../test/test_bitcoin.cpp
    PROPERTIES SKIP_AUTOUIC ON 
)

target_link_libraries(test_firo-qt
  PRIVATE
  core_interface
  firoqt
  firo_node
  ${TOR_LIBRARY}
  Boost::headers
  Boost::unit_test_framework
  Qt5::Test
  Qt5::Dependencies
  Qt5::Widgets
  Boost::thread
  $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
  $<TARGET_NAME_IF_EXISTS:libevent::extra>
  $<TARGET_NAME_IF_EXISTS:libevent::core>
  $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
  firo_cli
  $<TARGET_NAME_IF_EXISTS:firo_wallet>
  $<$<BOOL:${WIN32}>:windows_system>  
)

apply_wrapped_exception_flags(test_firo-qt)

# Add macOS-specific frameworks
if(APPLE)
    target_link_libraries(test_firo-qt PRIVATE
        "-framework CoreVideo"
        "-framework IOKit"
        "-framework IOSurface"
        "-framework ApplicationServices"
        "-framework QuartzCore"
        "-framework Security"
        "-framework SystemConfiguration"
        "-framework Metal"
        "-framework Foundation"
        "-framework AppKit"
        "-framework Carbon"
    )
endif()

import_plugins(test_firo-qt)

if(ENABLE_WALLET)
  target_sources(test_firo-qt
    PRIVATE
      ../../wallet/test/wallet_tests.cpp
      ../../wallet/test/wallet_test_fixture.cpp
  )
endif()

add_test(NAME test_firo-qt
  COMMAND test_firo-qt
)
if(WIN32 AND VCPKG_TARGET_TRIPLET)
  # On Windows, vcpkg configures Qt with `-opengl dynamic`, which makes
  # the "minimal" platform plugin unusable due to internal Qt bugs.
  set_tests_properties(test_firo-qt PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=windows"
  )
endif()

list(APPEND installable_targets test_firo-qt)
