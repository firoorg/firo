# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

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
  core_interface
  firoqt
  firo_node
  Boost::headers
  Boost::unit_test_framework
  Qt5::Test
  Qt5::Dependencies
)

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

install_binary_component(test_firo-qt)
