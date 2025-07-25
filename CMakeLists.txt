# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ubuntu 22.04 LTS Jammy Jellyfish, https://wiki.ubuntu.com/Releases, EOSS in June 2027:
#  - CMake 3.22.1, https://packages.ubuntu.com/jammy/cmake
#
# Centos Stream 9, https://www.centos.org/cl-vs-cs/#end-of-life, EOL in May 2027:
#  - CMake 3.26.5, https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/Packages/
cmake_minimum_required(VERSION 3.22)

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds are not allowed.")
endif()

#=============================
# Project / Package metadata
#=============================
set(CLIENT_NAME "Firo Core")
set(CLIENT_VERSION_MAJOR 0)
set(CLIENT_VERSION_MINOR 14)
set(CLIENT_VERSION_REVISION 14)
set(CLIENT_VERSION_BUILD 1)
set(CLIENT_VERSION_RC 0)
set(CLIENT_VERSION_IS_RELEASE "false")
set(COPYRIGHT_YEAR "2024")

# During the enabling of the CXX and CXXOBJ languages, we modify
# CMake's compiler/linker invocation strings by appending the content
# of the user-defined `APPEND_*` variables, which allows overriding
# any flag. We also ensure that the APPEND_* flags are considered
# during CMake's tests, which use the `try_compile()` command.
#
# CMake's docs state that the `CMAKE_TRY_COMPILE_PLATFORM_VARIABLES`
# variable "is meant to be set by CMake's platform information modules
# for the current toolchain, or by a toolchain file." We do our best
# to set it before the `project()` command.
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES
  CMAKE_CXX_COMPILE_OBJECT
  CMAKE_OBJCXX_COMPILE_OBJECT
  CMAKE_CXX_LINK_EXECUTABLE
)

project(FiroCore
  VERSION ${CLIENT_VERSION_MAJOR}.${CLIENT_VERSION_MINOR}.${CLIENT_VERSION_REVISION}
  DESCRIPTION "Firo client software"
  HOMEPAGE_URL "https://firo.org/"
  LANGUAGES NONE
)

set(FIRO_DAEMON_NAME firod)
set(FIRO_GUI_NAME firo-qt)
set(FIRO_CLI_NAME firo-cli)
set(FIRO_TX_NAME firo-tx)

set(CLIENT_VERSION_STRING ${PROJECT_VERSION})
if(CLIENT_VERSION_RC GREATER 0)
  string(APPEND CLIENT_VERSION_STRING "rc${CLIENT_VERSION_RC}")
endif()

set(COPYRIGHT_HOLDERS "The %s developers")
set(COPYRIGHT_HOLDERS_FINAL "The ${CLIENT_NAME} developers")
set(CLIENT_BUGREPORT "https://github.com/firoorg/firo/issues")

#=============================
# Set Project-wide output folders
#=============================
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

#=============================
# Language setup
#=============================
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT CMAKE_HOST_APPLE)
  # We do not use the install_name_tool when cross-compiling for macOS.
  # So disable this tool check in further enable_language() commands.
  set(CMAKE_PLATFORM_HAS_INSTALLNAME FALSE)
endif()
enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_language(C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/module)

#=============================
# Include utility functions
#=============================
include(cmake/utilities.cmake)

#=============================
# Configurable options
#=============================
include(CMakeDependentOption)
# When adding a new option, end the <help_text> with a full stop for consistency.
option(BUILD_DAEMON "Build ${FIRO_DAEMON_NAME} executable." ON)
option(BUILD_GUI "Build ${FIRO_GUI_NAME} executable." ON)
option(BUILD_CLI "Build ${FIRO_CLI_NAME} executable." ON)


option(BUILD_UTIL_CHAINSTATE "Build experimental firo-chainstate executable." OFF)
option(BUILD_KERNEL_LIB "Build experimental firokernel library." ${BUILD_UTIL_CHAINSTATE})

option(ENABLE_WALLET "Enable wallet." ON)
cmake_dependent_option(BUILD_TESTS "Build tests." OFF "ENABLE_WALLET" OFF)
option(BUILD_TX "Build ${FIRO_TX_NAME} executable." ${BUILD_CLI})
option(WITH_BDB "Enable Berkeley DB (BDB) wallet support." OFF)
cmake_dependent_option(WARN_INCOMPATIBLE_BDB "Warn when using a Berkeley DB (BDB) version other than 4.8." ON "WITH_BDB" OFF)
if(WITH_BDB)
  find_package(BerkeleyDB 4.8 MODULE REQUIRED)
  set(USE_BDB ON)
  if(NOT BerkeleyDB_VERSION VERSION_EQUAL 4.8)
    message(WARNING "Found Berkeley DB (BDB) other than 4.8.\n"
                    "BDB (legacy) wallets opened by this build will not be portable!"
    )
    if(WARN_INCOMPATIBLE_BDB)
      message(WARNING "If this is intended, pass \"-DWARN_INCOMPATIBLE_BDB=OFF\".\n"
                      "Passing \"-DWITH_BDB=OFF\" will suppress this warning."
      )
    endif()
  endif()
endif()

option(ENABLE_HARDENING "Attempt to harden the resulting executables." ON)
option(REDUCE_EXPORTS "Attempt to reduce exported symbols in the resulting executables." OFF)
option(WERROR "Treat compiler warnings as errors." OFF)
option(WITH_CCACHE "Attempt to use ccache for compiling." ON)
option(ENABLE_CRASH_HOOKS "Hook into exception/signal/assert handling to gather stack traces (default is off)" OFF)

if(ENABLE_CRASH_HOOKS)
  message(STATUS "Crash hooks enabled")
  # Define symbol ENABLE_CRASH_HOOKS for the compiler
  add_compile_definitions(ENABLE_CRASH_HOOKS=1)
endif()

include(CheckCXXCompilerFlag)

# Check if the linker supports wrapping __cxa_allocate_exception:
check_cxx_compiler_flag("-Wl,-wrap=__cxa_allocate_exception" LINK_WRAP_SUPPORTED)

if(LINK_WRAP_SUPPORTED)
  message(STATUS "Linker supports -Wl,-wrap flag")
  # Define symbol to use the wrapped C++ ABI for exception stacktraces
  add_compile_definitions(CRASH_HOOKS_WRAPPED_CXX_ABI=1)
  set(CRASH_HOOKS_WRAPPED_CXX_ABI ON CACHE BOOL "Use wrapped C++ ABI for exception stacktraces")
  # Wrap internal C++ ABI's so that we can attach stacktraces to exceptions
  if(WIN32)
    set(LDFLAGS_WRAP_EXCEPTIONS -Wl,-wrap,__cxa_allocate_exception -Wl,-wrap,__cxa_free_exception -Wl,-wrap,_assert -Wl,-wrap,_wassert)
  else()
    set(LDFLAGS_WRAP_EXCEPTIONS -Wl,-wrap,__cxa_allocate_exception -Wl,-wrap,__cxa_free_exception -Wl,-wrap,__assert_fail)
  endif()
  message(STATUS "Linker flags to wrap exceptions: ${LDFLAGS_WRAP_EXCEPTIONS}")
else()
  message(STATUS "Linker does not support -Wl,-wrap flag")
endif()

if(MINGW)
  # Check if the compiler supports the -Wa,-mbig-obj flag (needed on some MinGW targets)
  check_cxx_compiler_flag("-Wa,-mbig-obj" HAS_MBIGO_FLAG)
  if(HAS_MBIGO_FLAG)
    message(STATUS "Compiler supports -Wa,-mbig-obj; appending to CXX flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wa,-mbig-obj")
  else()
    message(STATUS "Compiler does not support -Wa,-mbig-obj")
  endif()
endif()

option(WITH_ZMQ "Enable ZMQ notifications." ON)
if(WITH_ZMQ)
  message(STATUS "ZMQ notifications enabled.")
  add_compile_definitions(ENABLE_ZMQ=1)
  find_package(ZeroMQ 4.0.0 MODULE REQUIRED)
else()
  message(STATUS "ZMQ notifications disabled.")
  add_compile_definitions(ENABLE_ZMQ=0)
endif()

option(WITH_USDT "Enable tracepoints for Userspace, Statically Defined Tracing." OFF)
if(WITH_USDT)
  find_package(USDT MODULE REQUIRED)
endif()

cmake_dependent_option(ENABLE_EXTERNAL_SIGNER "Enable external signer support." ON "NOT WIN32" OFF)

cmake_dependent_option(WITH_QRENCODE "Enable QR code support." ON "BUILD_GUI" OFF)
if(WITH_QRENCODE)
  find_package(QRencode MODULE REQUIRED)
  set(USE_QRCODE TRUE)
endif()

cmake_dependent_option(WITH_DBUS "Enable DBus support." ON "CMAKE_SYSTEM_NAME STREQUAL \"Linux\" AND BUILD_GUI" OFF)


cmake_dependent_option(BUILD_GUI_TESTS "Build test_firo-qt executable." ON "BUILD_GUI;BUILD_TESTS" OFF)
if(BUILD_GUI)
  set(qt_components Core Gui Widgets LinguistTools)
  if(ENABLE_WALLET)
    list(APPEND qt_components Network)
  endif()
  if(WITH_DBUS)
    if(WIN32)
      message(WARNING "Not possible to use DBUS on Windows. Not setting USE_DBUS preprocessor macro.")
    else()
      list(APPEND qt_components DBus)
      set(USE_DBUS TRUE)
      message(INFO "USE_DBUS : ${USE_DBUS}")
    endif()
  else()
    message(INFO "DBUS is off. Not setting USE_DBUS preprocessor macro.")
  endif()
  if(BUILD_GUI_TESTS)
    list(APPEND qt_components Test)
  endif()
  find_package(Qt 5.11.3 MODULE REQUIRED
    COMPONENTS ${qt_components}
  )
  unset(qt_components)
endif()

option(BUILD_BENCH "Build bench_firo executable." OFF)
option(BUILD_FUZZ_BINARY "Build fuzz binary." OFF)
option(BUILD_FOR_FUZZING "Build for fuzzing. Enabling this will disable all other targets and override BUILD_FUZZ_BINARY." OFF)

option(INSTALL_MAN "Install man pages." ON)

set(APPEND_CPPFLAGS "" CACHE STRING "Preprocessor flags that are appended to the command line after all other flags added by the build system. This variable is intended for debugging and special builds.")
set(APPEND_CFLAGS "" CACHE STRING "C compiler flags that are appended to the command line after all other flags added by the build system. This variable is intended for debugging and special builds.")
set(APPEND_CXXFLAGS "" CACHE STRING "(Objective) C++ compiler flags that are appended to the command line after all other flags added by the build system. This variable is intended for debugging and special builds.")
set(APPEND_LDFLAGS "" CACHE STRING "Linker flags that are appended to the command line after all other flags added by the build system. This variable is intended for debugging and special builds.")
# Appending to this low-level rule variables is the only way to
# guarantee that the flags appear at the end of the command line.
string(APPEND CMAKE_CXX_COMPILE_OBJECT " ${APPEND_CPPFLAGS} ${APPEND_CXXFLAGS}")
string(APPEND CMAKE_CXX_CREATE_SHARED_LIBRARY " ${APPEND_LDFLAGS}")
string(APPEND CMAKE_CXX_LINK_EXECUTABLE " ${APPEND_LDFLAGS}")

set(configure_warnings)

include(CheckPIESupported)
check_pie_supported(OUTPUT_VARIABLE check_pie_output LANGUAGES CXX)
if(CMAKE_CXX_LINK_PIE_SUPPORTED)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
elseif(NOT WIN32)
  # The warning is superfluous for Windows.
  message(WARNING "PIE is not supported at link time: ${check_pie_output}")
  list(APPEND configure_warnings "Position independent code disabled.")
endif()
unset(check_pie_output)

# The core_interface library aims to encapsulate common build flags.
# It is a usage requirement for all targets except for secp256k1, which
# gets its flags by other means.
add_library(core_interface INTERFACE)
add_library(core_interface_relwithdebinfo INTERFACE)
add_library(core_interface_debug INTERFACE)
target_link_libraries(core_interface INTERFACE
  $<$<CONFIG:RelWithDebInfo>:core_interface_relwithdebinfo>
  $<$<CONFIG:Debug>:core_interface_debug>
)
target_compile_definitions(core_interface 
  INTERFACE 
  HAVE_CONFIG_H=1)

if(BUILD_FOR_FUZZING)
  message(WARNING "BUILD_FOR_FUZZING=ON will disable all other targets and force BUILD_FUZZ_BINARY=ON.")
  set(BUILD_DAEMON OFF)
  set(BUILD_CLI OFF)
  set(BUILD_TX OFF)
  set(BUILD_UTIL OFF)
  set(BUILD_UTIL_CHAINSTATE OFF)
  set(BUILD_KERNEL_LIB OFF)
  set(BUILD_GUI OFF)
  set(ENABLE_EXTERNAL_SIGNER OFF)
  set(WITH_ZMQ OFF)
  set(BUILD_TESTS OFF)
  set(BUILD_GUI_TESTS OFF)
  set(BUILD_BENCH OFF)
  set(BUILD_FUZZ_BINARY ON)

  target_compile_definitions(core_interface INTERFACE
    FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  )
endif()

include(ProcessConfigurations)
include(CheckFunctionExists)

include(TryAppendCXXFlags)
include(TryAppendLinkerFlag)

if(WIN32)
  #[=[
  This build system supports two ways to build binaries for Windows.

  1. Building on Windows using MSVC.
  Implementation notes:
  - /DWIN32 and /D_WINDOWS definitions are included into the CMAKE_CXX_FLAGS_INIT
    and CMAKE_CXX_FLAGS_INIT variables by default.
  - A run-time library is selected using the CMAKE_MSVC_RUNTIME_LIBRARY variable.
  - MSVC-specific options, for example, /Zc:__cplusplus, are additionally required.

  2. Cross-compiling using MinGW.
  Implementation notes:
  - WIN32 and _WINDOWS definitions must be provided explicitly.
  - A run-time library must be specified explicitly using _MT definition.
  ]=]

  target_compile_definitions(core_interface INTERFACE
    _WIN32_WINNT=0x0601
    _WIN32_IE=0x0501
    WIN32_LEAN_AND_MEAN
    NOMINMAX
  )

  if(MSVC)
    if(VCPKG_TARGET_TRIPLET MATCHES "-static")
      set(msvc_library_linkage "")
    else()
      set(msvc_library_linkage "DLL")
    endif()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>${msvc_library_linkage}")
    unset(msvc_library_linkage)

    target_compile_definitions(core_interface INTERFACE
      _UNICODE;UNICODE
    )
    target_compile_options(core_interface INTERFACE
      /utf-8
      /Zc:preprocessor
      /Zc:__cplusplus
      /sdl
    )
    # Improve parallelism in MSBuild.
    # See: https://devblogs.microsoft.com/cppblog/improved-parallelism-in-msbuild/.
    list(APPEND CMAKE_VS_GLOBALS "UseMultiToolTask=true")
  endif()

  if(MINGW)
    target_compile_definitions(core_interface INTERFACE
      WIN32
      _WINDOWS
      _MT
    )
    # Avoid the use of aligned vector instructions when building for Windows.
    # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=54412.
    try_append_cxx_flags("-Wa,-muse-unaligned-vector-move" TARGET core_interface SKIP_LINK)
    try_append_linker_flag("-static" TARGET core_interface)
    # We require Windows 7 (NT 6.1) or later.
    try_append_linker_flag("-Wl,--major-subsystem-version,6" TARGET core_interface)
    try_append_linker_flag("-Wl,--minor-subsystem-version,1" TARGET core_interface)
  endif()
endif()

# Use 64-bit off_t on 32-bit Linux.
if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  # Ensure 64-bit offsets are used for filesystem accesses for 32-bit compilation.
  target_compile_definitions(core_interface INTERFACE
    _FILE_OFFSET_BITS=64
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(core_interface INTERFACE OBJC_OLD_DISPATCH_PROTOTYPES=0)
  # These flags are specific to ld64, and may cause issues with other linkers.
  # For example: GNU ld will interpret -dead_strip as -de and then try and use
  # "ad_strip" as the symbol for the entry point.
  try_append_linker_flag("-Wl,-dead_strip" TARGET core_interface)
  try_append_linker_flag("-Wl,-dead_strip_dylibs" TARGET core_interface)
  if(CMAKE_HOST_APPLE)
    try_append_linker_flag("-Wl,-headerpad_max_install_names" TARGET core_interface)
  endif()
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(core_interface INTERFACE
  Threads::Threads
)

add_library(sanitize_interface INTERFACE)
target_link_libraries(core_interface INTERFACE sanitize_interface)
if(SANITIZERS)
  # First check if the compiler accepts flags. If an incompatible pair like
  # -fsanitize=address,thread is used here, this check will fail. This will also
  # fail if a bad argument is passed, e.g. -fsanitize=undfeined
  try_append_cxx_flags("-fsanitize=${SANITIZERS}" TARGET sanitize_interface
    RESULT_VAR cxx_supports_sanitizers
    SKIP_LINK
  )
  if(NOT cxx_supports_sanitizers)
    message(FATAL_ERROR "Compiler did not accept requested flags.")
  endif()

  # Some compilers (e.g. GCC) require additional libraries like libasan,
  # libtsan, libubsan, etc. Make sure linking still works with the sanitize
  # flag. This is a separate check so we can give a better error message when
  # the sanitize flags are supported by the compiler but the actual sanitizer
  # libs are missing.
  try_append_linker_flag("-fsanitize=${SANITIZERS}" VAR SANITIZER_LDFLAGS
    SOURCE "
      #include <cstdint>
      #include <cstddef>
      extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }
      __attribute__((weak)) // allow for libFuzzer linking
      int main() { return 0; }
    "
    RESULT_VAR linker_supports_sanitizers
  )
  if(NOT linker_supports_sanitizers)
    message(FATAL_ERROR "Linker did not accept requested flags, you are missing required libraries.")
  endif()
endif()
target_link_options(sanitize_interface INTERFACE ${SANITIZER_LDFLAGS})

if(BUILD_FUZZ_BINARY)
  include(CheckSourceCompilesAndLinks)
  check_cxx_source_links_with_flags("${SANITIZER_LDFLAGS}" "
      #include <cstdint>
      #include <cstddef>
      extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }
      // No main() function.
    " FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION
  )
endif()

include(AddBoostIfNeeded)
add_boost_if_needed()

if(BUILD_DAEMON OR BUILD_GUI OR BUILD_CLI OR BUILD_TESTS OR BUILD_BENCH OR BUILD_FUZZ_BINARY)
  find_package(Libevent 2.1.8 MODULE REQUIRED)
endif()

# Find bls-dash library
find_library(BLS_DASH_LIBRARY
  NAMES bls-dash
  REQUIRED
)

if(${BLS_DASH_LIBRARY} STREQUAL "BLS_DASH_LIBRARY-NOTFOUND")
  message(FATAL_ERROR "bls-dash library not found")
else()
  message(STATUS "Found bls-dash library: ${BLS_DASH_LIBRARY}")
endif()

# Find tor library
find_library(TOR_LIBRARY
  NAMES tor
  REQUIRED
)

# Find OpenSSL library
find_package(OpenSSL 1.1.1 REQUIRED)

# Find MiniUPNP library
find_library(MINIUPNP_LIBRARY
  NAMES miniupnpc
  REQUIRED
)

# Find GMP library
find_package(GMP 6.2.1 REQUIRED)

# Find zlib library
find_library(ZLIB_LIBRARY
  NAMES z
  REQUIRED
)

if(${TOR_LIBRARY} STREQUAL "TOR_LIBRARY-NOTFOUND")
  message(FATAL_ERROR "tor library not found")
else()
  message(STATUS "Found tor library: ${TOR_LIBRARY}")
endif()

if(ENABLE_CRASH_HOOKS)
# Check for the presence of the backtrace library
find_library(BACKTRACE_LIBRARY
  NAMES backtrace
  REQUIRED
)
message(STATUS "Found backtrace library: ${BACKTRACE_LIBRARY}")
endif()

include(cmake/introspection.cmake)
####################
# Check functions and define
include(CheckIncludeFile)
include(CheckSymbolExists)

# Check for headers
CHECK_INCLUDE_FILE(endian.h HAVE_ENDIAN_H)
CHECK_INCLUDE_FILE(sys/endian.h HAVE_SYS_ENDIAN_H)

# Setup test code header section
if(HAVE_ENDIAN_H)
  set(ENDIAN_HEADER "endian.h")
  add_compile_definitions(HAVE_ENDIAN_H=1)
elseif(HAVE_SYS_ENDIAN_H)
  set(ENDIAN_HEADER "sys/endian.h")
  add_compile_definitions(HAVE_SYS_ENDIAN_H=1)
endif(HAVE_ENDIAN_H)

# Functions to check
set(ENDIAN_FUNCTIONS
    le16toh le32toh le64toh
    htole16 htole32 htole64
    be16toh be32toh be64toh
    htobe16 htobe32 htobe64
)

# Check each function
foreach(func ${ENDIAN_FUNCTIONS})
    string(TOUPPER "HAVE_DECL_${func}" var_name)
    check_symbol_exists(${func} "${ENDIAN_HEADER}" ${var_name})
    if(${var_name})
        add_compile_definitions(${var_name}=1)
    else()
        add_compile_definitions(${var_name}=0)
    endif()
endforeach()

# Check for byteswap.h header
CHECK_INCLUDE_FILE(byteswap.h HAVE_BYTESWAP_H)

# Setup test code header section
if(HAVE_BYTESWAP_H)
  set(BYTESWAP_HEADER "byteswap.h")
  add_compile_definitions(HAVE_BYTESWAP_H=1)
endif(HAVE_BYTESWAP_H)

# Functions to check
set(BSWAP_FUNCTIONS
    bswap_16 bswap_32 bswap_64
)

# Check each function
foreach(func ${BSWAP_FUNCTIONS})
    string(TOUPPER "HAVE_DECL_${func}" var_name)
    check_symbol_exists(${func} "${BYTESWAP_HEADER}" ${var_name})
    if(${var_name})
        add_compile_definitions(${var_name}=1)
    else()
        add_compile_definitions(${var_name}=0)
    endif()
endforeach()

# strnlen
CHECK_INCLUDE_FILE(string.h HAVE_STRING_H)
if(HAVE_STRING_H)
  check_function_exists_and_define(strnlen "string.h" HAVE_DECL_STRNLEN)
endif(HAVE_STRING_H)

# Functions to check
set(BUILTIN_FUNCTIONS
    __builtin_clz
    __builtin_clzl
    __builtin_clzll
)

# Check each function
foreach(func ${BUILTIN_FUNCTIONS})
    string(TOUPPER "HAVE_DECL_${func}" var_name)
    set(TEST_SOURCE_CODE "
    int main() {
        int x = 0;
        (void)${func}(x);
        return 0;
    }
    ")
    check_cxx_source_compiles("${TEST_SOURCE_CODE}" ${var_name})
    if(${var_name})
        add_compile_definitions(${var_name}=1)
    else()
        add_compile_definitions(${var_name}=0)
    endif()
endforeach()

check_cxx_source_compiles(
  "#if __cplusplus >= 201703L
  int main() {
      [[maybe_unused]] int x = 42;
      return 0;
  }
  #else
  #error \"Requires C++17\"
  #endif"
  HAVE_MAYBE_UNUSED
)
if(${HAVE_MAYBE_UNUSED})
    message(STATUS "Compiler supports maybe_unused" )
    add_compile_definitions(HAVE_MAYBE_UNUSED=1)
else()
    message(WARNING "Compiler does not support maybe_unused")
    check_cxx_source_compiles(
      "int main() {
          __attribute__((unused)) int x = 42;
          return 0;
      }"
      HAVE_ATTRIBUTE_UNUSED
    )
    if(${HAVE_ATTRIBUTE_UNUSED})
        message(STATUS "Compiler supports __attribute__((unused))" )
        add_compile_definitions(HAVE_ATTRIBUTE_UNUSED=1)
    else()
        message(WARNING "Compiler does not support __attribute__((unused))")
        message(WARNING "Please use a compiler that supports C++17 or __attribute__((unused))")
    endif()
endif()

include(cmake/ccache.cmake)

add_library(warn_interface INTERFACE)
target_link_libraries(core_interface INTERFACE warn_interface)
if(MSVC)
  try_append_cxx_flags("/W3" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4018" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4244" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4267" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4715" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4805" TARGET warn_interface SKIP_LINK)
  target_compile_definitions(warn_interface INTERFACE
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
  )
else()
  try_append_cxx_flags("-Wall" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wextra" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wgnu" TARGET warn_interface SKIP_LINK)
  # Some compilers will ignore -Wformat-security without -Wformat, so just combine the two here.
  try_append_cxx_flags("-Wformat -Wformat-security" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wvla" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wshadow-field" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wthread-safety" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wloop-analysis" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wredundant-decls" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wunused-member-function" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wdate-time" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wconditional-uninitialized" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wduplicated-branches" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wduplicated-cond" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wlogical-op" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Woverloaded-virtual" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wsuggest-override" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wimplicit-fallthrough" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wunreachable-code" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wdocumentation" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wself-assign" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wundef" TARGET warn_interface SKIP_LINK)

  # Some compilers (gcc) ignore unknown -Wno-* options, but warn about all
  # unknown options if any other warning is produced. Test the -Wfoo case, and
  # set the -Wno-foo case if it works.
  try_append_cxx_flags("-Wunused-parameter" TARGET warn_interface SKIP_LINK
    IF_CHECK_PASSED "-Wno-unused-parameter"
  )
endif()

configure_file(cmake/script/Coverage.cmake Coverage.cmake USE_SOURCE_PERMISSIONS COPYONLY)
configure_file(cmake/script/CoverageFuzz.cmake CoverageFuzz.cmake USE_SOURCE_PERMISSIONS COPYONLY)
configure_file(cmake/script/CoverageInclude.cmake.in CoverageInclude.cmake USE_SOURCE_PERMISSIONS @ONLY)

# Don't allow extended (non-ASCII) symbols in identifiers. This is easier for code review.
try_append_cxx_flags("-fno-extended-identifiers" TARGET core_interface SKIP_LINK)

try_append_cxx_flags("-ffile-prefix-map=A=B" TARGET core_interface SKIP_LINK
  IF_CHECK_PASSED "-ffile-prefix-map=${PROJECT_SOURCE_DIR}/src=."
)

# Currently all versions of gcc are subject to a class of bugs, see the
# gccbug_90348 test case (only reproduces on GCC 11 and earlier) and
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111843. To work around that, set
# -fstack-reuse=none for all gcc builds. (Only gcc understands this flag).
try_append_cxx_flags("-fstack-reuse=none" TARGET core_interface)

if(ENABLE_HARDENING)
  add_library(hardening_interface INTERFACE)
    target_link_libraries(core_interface INTERFACE hardening_interface)
  if(MSVC)
    try_append_linker_flag("/DYNAMICBASE" TARGET hardening_interface)
    try_append_linker_flag("/HIGHENTROPYVA" TARGET hardening_interface)
    try_append_linker_flag("/NXCOMPAT" TARGET hardening_interface)
  else()

    # _FORTIFY_SOURCE requires that there is some level of optimization,
    # otherwise it does nothing and just creates a compiler warning.
    try_append_cxx_flags("-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
      RESULT_VAR cxx_supports_fortify_source
      SOURCE "int main() {
              # if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0
                #error
              #endif
              }"
    )
    if(cxx_supports_fortify_source)
      target_compile_options(hardening_interface INTERFACE
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=3
      )
    endif()
    unset(cxx_supports_fortify_source)

    try_append_cxx_flags("-Wstack-protector" TARGET hardening_interface SKIP_LINK)
    try_append_cxx_flags("-fstack-protector-all" TARGET hardening_interface)
    try_append_cxx_flags("-fcf-protection=full" TARGET hardening_interface)

    if(MINGW)
      # stack-clash-protection doesn't compile with GCC 10 and earlier.
      # In any case, it is a no-op for Windows.
      # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90458 for more details.
    else()
      try_append_cxx_flags("-fstack-clash-protection" TARGET hardening_interface)
    endif()

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
      if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        try_append_cxx_flags("-mbranch-protection=bti" TARGET hardening_interface SKIP_LINK)
      else()
        try_append_cxx_flags("-mbranch-protection=standard" TARGET hardening_interface SKIP_LINK)
      endif()
    endif()

    try_append_linker_flag("-Wl,--enable-reloc-section" TARGET hardening_interface)
    try_append_linker_flag("-Wl,--dynamicbase" TARGET hardening_interface)
    try_append_linker_flag("-Wl,--nxcompat" TARGET hardening_interface)
    try_append_linker_flag("-Wl,--high-entropy-va" TARGET hardening_interface)
    try_append_linker_flag("-Wl,-z,relro" TARGET hardening_interface)
    try_append_linker_flag("-Wl,-z,now" TARGET hardening_interface)
    try_append_linker_flag("-Wl,-z,separate-code" TARGET hardening_interface)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
      try_append_linker_flag("-Wl,-fixup_chains" TARGET hardening_interface)
    endif()
  endif()
endif()

if(REDUCE_EXPORTS)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  try_append_linker_flag("-Wl,--exclude-libs,ALL" TARGET core_interface)
  try_append_linker_flag("-Wl,-no_exported_symbols" VAR CMAKE_EXE_LINKER_FLAGS)
endif()

if(WERROR)
  if(MSVC)
    set(werror_flag "/WX")
  else()
    set(werror_flag "-Werror")
  endif()
  try_append_cxx_flags(${werror_flag} TARGET core_interface SKIP_LINK RESULT_VAR compiler_supports_werror)
  if(NOT compiler_supports_werror)
    message(FATAL_ERROR "WERROR set but ${werror_flag} is not usable.")
  endif()
  unset(werror_flag)
endif()

find_package(Python3 3.10 COMPONENTS Interpreter)
if(Python3_EXECUTABLE)
  set(PYTHON_COMMAND ${Python3_EXECUTABLE})
else()
  list(APPEND configure_warnings
    "Minimum required Python not found. Utils and rpcauth tests are disabled."
  )
endif()

target_compile_definitions(core_interface INTERFACE ${DEPENDS_COMPILE_DEFINITIONS})
target_compile_definitions(core_interface_relwithdebinfo INTERFACE ${DEPENDS_COMPILE_DEFINITIONS_RELWITHDEBINFO})
target_compile_definitions(core_interface_debug INTERFACE ${DEPENDS_COMPILE_DEFINITIONS_DEBUG})

# If the {CXX,LD}FLAGS environment variables are defined during building depends
# and configuring this build system, their content might be duplicated.
if(DEFINED ENV{CXXFLAGS})
  deduplicate_flags(CMAKE_CXX_FLAGS)
endif()
if(DEFINED ENV{LDFLAGS})
  deduplicate_flags(CMAKE_EXE_LINKER_FLAGS)
endif()

if(BUILD_TESTS)
  enable_testing()
endif()

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.29)
  # have "make test" depend on "make all"
  set(CMAKE_SKIP_TEST_ALL_DEPENDENCY FALSE)
endif()

# TODO: The `CMAKE_SKIP_BUILD_RPATH` variable setting can be deleted
#       in the future after reordering Guix script commands to
#       perform binary checks after the installation step.
# Relevant discussions:
# - https://github.com/hebasto/firo/pull/236#issuecomment-2183120953
# - https://github.com/firo/firo/pull/30312#issuecomment-2191235833
set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)

if(BUILD_TESTS)
  # Create test configuration file
  # This file is used by the test framework to configure the tests.
  # It is generated in the build directory and copied to the source directory
  # so that it can be used by the test framework.
  # The test framework will use the configuration file to determine which
  # features are enabled and which tests should be run.
  # used by the test framework to determine which features are enabled
  function(create_test_config)
    set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
    set(abs_top_builddir ${PROJECT_BINARY_DIR})
    set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
    message(WARNING "CMAKE_EXECUTABLE_SUFFIX : ${CMAKE_EXECUTABLE_SUFFIX}")
    message(WARNING "WITH_ZMQ : ${WITH_ZMQ}")

    macro(set_configure_variable var conf_var)
      if(${var})
        set(${conf_var}_TRUE "")
      else()
        set(${conf_var}_TRUE "#")
      endif()
    endmacro()

    # Core binaries
    set_configure_variable(BUILD_DAEMON ENABLE_BITCOIND)
    set_configure_variable(BUILD_CLI BUILD_BITCOIN_UTIL)

    # Wallet support
    set_configure_variable(ENABLE_WALLET ENABLE_WALLET)

    # Features
    set_configure_variable(WITH_ZMQ ENABLE_ZMQ)

    configure_file(${PROJECT_SOURCE_DIR}/qa/pull-tester/tests_config.py.in ${PROJECT_SOURCE_DIR}/qa/pull-tester/tests_config.py USE_SOURCE_PERMISSIONS @ONLY)
  endfunction()

  create_test_config()

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fuzz)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/util)

  file(GLOB_RECURSE functional_tests RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} functional/*)
  foreach(script ${functional_tests} fuzz/test_runner.py util/rpcauth-test.py util/test_runner.py)
    if(CMAKE_HOST_WIN32)
      set(symlink)
    else()
      set(symlink SYMBOLIC)
    endif()
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/${script} ${CMAKE_CURRENT_BINARY_DIR}/${script} COPY_ON_ERROR ${symlink})
  endforeach()
  unset(functional_tests)
endif(BUILD_TESTS)
add_subdirectory(doc)

include(cmake/crc32c.cmake)
include(cmake/leveldb.cmake)
add_subdirectory(src)

include(cmake/tests.cmake)

include(Maintenance)
setup_split_debug_script()
add_maintenance_targets()
add_windows_deploy_target()
add_macos_deploy_target()

include_directories(${CMAKE_SOURCE_DIR}/src)

message("\n")
message("Configure summary")
message("=================")
message("Executables:")
message("  firod ............................ ${BUILD_DAEMON}")
message("  firo-qt (GUI) .................... ${BUILD_GUI}")
message("  firo-cli ......................... ${BUILD_CLI}")
message("  firo-tx .......................... ${BUILD_TX}")
message("  firo-chainstate (experimental) ... ${BUILD_UTIL_CHAINSTATE}")
message("  libfirokernel (experimental) ..... ${BUILD_KERNEL_LIB}")
message("Optional features:")
message("  wallet support ...................... ${ENABLE_WALLET}")
if(ENABLE_WALLET)
  message("   - legacy wallets (Berkeley DB) ..... ${WITH_BDB}")
endif()
message("  external signer ..................... ${ENABLE_EXTERNAL_SIGNER}")
message("  ZeroMQ .............................. ${WITH_ZMQ}")
message("  USDT tracing ........................ ${WITH_USDT}")
message("  QR code (GUI) ....................... ${WITH_QRENCODE}")
message("  DBus (GUI, Linux only) .............. ${WITH_DBUS}")
message("Tests:")
message("  test_firo ........................ ${BUILD_TESTS}")
message("  test_firo-qt ..................... ${BUILD_GUI_TESTS}")
message("  bench_firo ....................... ${BUILD_BENCH}")
message("  fuzz binary ......................... ${BUILD_FUZZ_BINARY}")
message("")
if(CMAKE_CROSSCOMPILING)
  set(cross_status "TRUE, for ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(cross_status "FALSE")
endif()
message("Cross compiling ....................... ${cross_status}")
message("C++ compiler .......................... ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}, ${CMAKE_CXX_COMPILER}")
include(FlagsSummary)
flags_summary()
message("Attempt to harden executables ......... ${ENABLE_HARDENING}")
message("Treat compiler warnings as errors ..... ${WERROR}")
message("Use ccache for compiling .............. ${WITH_CCACHE}")
message("Enable crash hooks .................... ${ENABLE_CRASH_HOOKS}")
message("\n")
if(configure_warnings)
    message("  ******\n")
    foreach(warning IN LISTS configure_warnings)
      message(WARNING "${warning}")
    endforeach()
    message("  ******\n")
endif()

# We want all build properties to be encapsulated properly.
include(WarnAboutGlobalProperties)

# Generate archive files
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Firo client software")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)