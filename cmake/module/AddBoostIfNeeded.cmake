# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(add_boost_if_needed)
  #[=[
  TODO: Not all targets, which will be added in the future, require
        Boost. Therefore, a proper check will be appropriate here.

  Implementation notes:
  Although only Boost headers are used to build Bitcoin Core,
  we still leverage a standard CMake's approach to handle
  dependencies, i.e., the Boost::headers "library".
  A command target_link_libraries(target PRIVATE Boost::headers)
  will propagate Boost::headers usage requirements to the target.
  For Boost::headers such usage requirements is an include
  directory and other added INTERFACE properties.
  ]=]

  # We cannot rely on find_package(Boost ...) to work properly without
  # Boost_NO_BOOST_CMAKE set until we require a more recent Boost because
  # upstream did not ship proper CMake files until 1.82.0.
  # Until then, we rely on CMake's FindBoost module.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0167.html
  if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
  endif()
  set(Boost_NO_BOOST_CMAKE OFF)
  set(_boost_components atomic chrono filesystem program_options system thread)
  if(BUILD_TESTS)
    list(APPEND _boost_components unit_test_framework)
  endif()
  find_package(Boost 1.81.0 REQUIRED COMPONENTS ${_boost_components})

  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_INCLUDES ${Boost_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${Boost_LIBRARIES})
  # Test source code
  set(SLEEPTEST_SOURCE_CODE "
  #include <boost/thread/thread.hpp>
  #include <boost/version.hpp>

  int main() {
  #if BOOST_VERSION >= 105000 && (!defined(BOOST_HAS_NANOSLEEP) || BOOST_VERSION >= 105200)
      boost::this_thread::sleep_for(boost::chrono::milliseconds(0));
      return 0;
  #else
      choke me
  #endif
  }
  ")

  # Check if the test source code compiles
  check_cxx_source_compiles("${SLEEPTEST_SOURCE_CODE}" HAVE_WORKING_BOOST_SLEEP_FOR)

  # Define the macro if the test passed
  if(HAVE_WORKING_BOOST_SLEEP_FOR)
      add_compile_definitions(HAVE_WORKING_BOOST_SLEEP_FOR=1)
  else()
      # testing for boost::this_thread::sleep(boost::posix_time::milliseconds(n));
      set(SLEEPTEST_SOURCE_CODE "
      #include <boost/thread/thread.hpp>
      #include <boost/version.hpp>

      int main() {
      #if BOOST_VERSION >= 105000 && (!defined(BOOST_HAS_NANOSLEEP) || BOOST_VERSION >= 105200)
          boost::this_thread::sleep(boost::chrono::milliseconds(0));
          return 0;
      #else
          choke me
      #endif
      }
      ")
      # Check if the test source code compiles
      check_cxx_source_compiles("${SLEEPTEST_SOURCE_CODE}" HAVE_WORKING_BOOST_SLEEP)
      if(HAVE_WORKING_BOOST_SLEEP)
          add_compile_definitions(HAVE_WORKING_BOOST_SLEEP=1)
      else()
          message(FATAL_ERROR "Couldn't find a working boost sleep_for or sleep function. Please check your Boost.")
      endif()
  endif()

  mark_as_advanced(Boost_INCLUDE_DIR)
  set_target_properties(Boost::headers PROPERTIES IMPORTED_GLOBAL TRUE)
  target_compile_definitions(Boost::headers INTERFACE
    # We don't use multi_index serialization.
    BOOST_MULTI_INDEX_DISABLE_SERIALIZATION
  )
  if(DEFINED VCPKG_TARGET_TRIPLET)
    # Workaround for https://github.com/microsoft/vcpkg/issues/36955.
    target_compile_definitions(Boost::headers INTERFACE
      BOOST_NO_USER_CONFIG
    )
  endif()

  # Prevent use of std::unary_function, which was removed in C++17,
  # and will generate warnings with newer compilers for Boost
  # older than 1.80.
  # See: https://github.com/boostorg/config/pull/430.
  set(CMAKE_REQUIRED_DEFINITIONS -DBOOST_NO_CXX98_FUNCTION_BASE)
  set(CMAKE_REQUIRED_INCLUDES ${Boost_INCLUDE_DIR})
  include(CMakePushCheckState)
  cmake_push_check_state()
  include(TryAppendCXXFlags)
  set(CMAKE_REQUIRED_FLAGS ${working_compiler_werror_flag})
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  check_cxx_source_compiles("
    #include <boost/config.hpp>
    " NO_DIAGNOSTICS_BOOST_NO_CXX98_FUNCTION_BASE
  )
  cmake_pop_check_state()
  if(NO_DIAGNOSTICS_BOOST_NO_CXX98_FUNCTION_BASE)
    target_compile_definitions(Boost::headers INTERFACE
      BOOST_NO_CXX98_FUNCTION_BASE
    )
  else()
    set(CMAKE_REQUIRED_DEFINITIONS)
  endif()

  # Some package managers, such as vcpkg, vendor Boost.Test separately
  # from the rest of the headers, so we have to check for it individually.
  if(BUILD_TESTS AND DEFINED VCPKG_TARGET_TRIPLET)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DBOOST_TEST_NO_MAIN)
    include(CheckIncludeFileCXX)
    check_include_file_cxx(boost/test/included/unit_test.hpp HAVE_BOOST_INCLUDED_UNIT_TEST_H)
    if(NOT HAVE_BOOST_INCLUDED_UNIT_TEST_H)
      message(FATAL_ERROR "Building test_bitcoin executable requested but boost/test/included/unit_test.hpp header not available.")
    endif()
  endif()

endfunction()
