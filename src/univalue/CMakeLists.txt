# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(univalue STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/univalue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/univalue_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/univalue_write.cpp
)
target_include_directories(univalue
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(univalue PRIVATE core_interface)

if(BUILD_TESTS)
  add_executable(unitester ${CMAKE_CURRENT_SOURCE_DIR}/test/unitester.cpp)
  target_compile_definitions(unitester
    PRIVATE
      JSON_TEST_SRC=\"${CMAKE_CURRENT_SOURCE_DIR}/test\"
  )
  target_link_libraries(unitester
    PRIVATE
      core_interface
      univalue
  )
  add_test(NAME univalue_test
    COMMAND unitester
  )

endif()
