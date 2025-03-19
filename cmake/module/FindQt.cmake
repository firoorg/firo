# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

#[=======================================================================[
FindQt
------

Finds the Qt headers and libraries.

This is a wrapper around find_package() command that:
 - facilitates searching in various build environments
 - prints a standard log message

#]=======================================================================]

set(_qt_homebrew_prefix)
if(CMAKE_HOST_APPLE)
  find_program(HOMEBREW_EXECUTABLE brew)
  if(HOMEBREW_EXECUTABLE)
    execute_process(
      COMMAND ${HOMEBREW_EXECUTABLE} --prefix qt@${Qt_FIND_VERSION_MAJOR}
      OUTPUT_VARIABLE _qt_homebrew_prefix
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  endif()
endif()

# Save CMAKE_FIND_ROOT_PATH_MODE_LIBRARY state.
unset(_qt_find_root_path_mode_library_saved)
if(DEFINED CMAKE_FIND_ROOT_PATH_MODE_LIBRARY)
  set(_qt_find_root_path_mode_library_saved ${CMAKE_FIND_ROOT_PATH_MODE_LIBRARY})
endif()

# The Qt config files internally use find_library() calls for all
# dependencies to ensure their availability. In turn, the find_library()
# inspects the well-known locations on the file system; therefore, it must
# be able to find platform-specific system libraries, for example:
# /usr/x86_64-w64-mingw32/lib/libm.a or /usr/arm-linux-gnueabihf/lib/libm.a.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

find_package(Qt${Qt_FIND_VERSION_MAJOR} ${Qt_FIND_VERSION}
  COMPONENTS ${Qt_FIND_COMPONENTS}
  HINTS ${_qt_homebrew_prefix}
  PATH_SUFFIXES Qt${Qt_FIND_VERSION_MAJOR}  # Required on OpenBSD systems.
)
unset(_qt_homebrew_prefix)

# Restore CMAKE_FIND_ROOT_PATH_MODE_LIBRARY state.
if(DEFINED _qt_find_root_path_mode_library_saved)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ${_qt_find_root_path_mode_library_saved})
  unset(_qt_find_root_path_mode_library_saved)
else()
  unset(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Qt
  REQUIRED_VARS Qt${Qt_FIND_VERSION_MAJOR}_DIR
  VERSION_VAR Qt${Qt_FIND_VERSION_MAJOR}_VERSION
)

foreach(component IN LISTS Qt_FIND_COMPONENTS ITEMS "")
  mark_as_advanced(Qt${Qt_FIND_VERSION_MAJOR}${component}_DIR)
endforeach()

# Prioritize finding static libraries
set(_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${_CMAKE_FIND_LIBRARY_SUFFIXES})

find_library(LIB_QTLIBPNG NAMES qtlibpng REQUIRED)
message(STATUS "Found Qt5 dependency: qtlibpng : ${LIB_QTLIBPNG}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT MINGW)
  find_library(LIB_FONTCONFIG NAMES fontconfig REQUIRED)
  message(STATUS "Found Qt5 dependency: fontconfig : ${LIB_FONTCONFIG}")

  find_library(LIB_EXPAT NAMES expat REQUIRED)
  message(STATUS "Found Qt5 dependency: expat : ${LIB_EXPAT}")
  
  find_library(LIB_FREETYPE NAMES freetype REQUIRED)
  message(STATUS "Found Qt5 dependency: freetype : ${LIB_FREETYPE}")
  
  find_library(LIB_XCB_EWMH NAMES xcb-ewmh REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-ewmh : ${LIB_XCB_EWMH}")
  
  find_library(LIB_XCB_ICCCM NAMES xcb-icccm REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-icccm : ${LIB_XCB_ICCCM}")
  
  find_library(LIB_XCB_IMAGE NAMES xcb-image REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-image : ${LIB_XCB_IMAGE}")
  
  find_library(LIB_XCB_KEYSYMS NAMES xcb-keysyms REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-keysyms : ${LIB_XCB_KEYSYMS}")
  
  find_library(LIB_XCB_RANDR NAMES xcb-randr REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-randr : ${LIB_XCB_RANDR}")
  
  find_library(LIB_XCB_RENDER_UTIL NAMES xcb-render-util REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-render-util : ${LIB_XCB_RENDER_UTIL}")
  
  find_library(LIB_XCB_RENDER NAMES xcb-render REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-render : ${LIB_XCB_RENDER}")
  
  find_library(LIB_XCB_SHAPE NAMES xcb-shape REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-shape : ${LIB_XCB_SHAPE}")
  
  find_library(LIB_XCB_SHM NAMES xcb-shm REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-shm : ${LIB_XCB_SHM}")
  
  find_library(LIB_XCB_SYNC NAMES xcb-sync REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-sync : ${LIB_XCB_SYNC}")
  
  find_library(LIB_XCB_UTIL NAMES xcb-util REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-util : ${LIB_XCB_UTIL}")
  
  find_library(LIB_XCB_XFIXES NAMES xcb-xfixes REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-xfixes : ${LIB_XCB_XFIXES}")
  
  find_library(LIB_XCB_XINERAMA NAMES xcb-xinerama REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-xinerama : ${LIB_XCB_XINERAMA}")
  
  find_library(LIB_XCB_XKB NAMES xcb-xkb REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb-xkb : ${LIB_XCB_XKB}")
  
  find_library(LIB_XCB NAMES xcb REQUIRED)
  message(STATUS "Found Qt5 dependency: xcb : ${LIB_XCB}")

  find_library(LIB_XKBCOMMON_X11 NAMES xkbcommon-x11 REQUIRED)
  message(STATUS "Found Qt5 dependency: xkbcommon-x11 : ${LIB_XKBCOMMON_X11}")
  
  find_library(LIB_XKBCOMMON NAMES xkbcommon REQUIRED)
  message(STATUS "Found Qt5 dependency: xkbcommon : ${LIB_XKBCOMMON}")
  
  find_library(LIB_XAU NAMES Xau REQUIRED)
  message(STATUS "Found Qt5 dependency: Xau : ${LIB_XAU}")

endif()
  
find_library(LIB_QTHARFBUZZ NAMES qtharfbuzz REQUIRED)
message(STATUS "Found Qt5 dependency: qtharfbuzz : ${LIB_QTHARFBUZZ}")

find_library(LIB_QTPCR2 NAMES qtpcre2 REQUIRED)
message(STATUS "Found Qt5 dependency: qtpcre2 : ${LIB_QTPCR2}")

find_library(LIB_Z NAMES z REQUIRED)
message(STATUS "Found Qt5 dependency: z : ${LIB_Z}")

# Qt5 dependencies libraries, order is important, should be last
add_library(Qt5_Dependencies
  INTERFACE
)
target_link_libraries(Qt5_Dependencies
  INTERFACE
  ${LIB_QTLIBPNG}
  ${LIB_QTHARFBUZZ}
  ${LIB_QTPCR2}
  $<$<PLATFORM_ID:Linux>:${LIB_FONTCONFIG}>
  $<$<PLATFORM_ID:Linux>:${LIB_FREETYPE}>
  $<$<PLATFORM_ID:Linux>:${LIB_EXPAT}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_EWMH}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_ICCCM}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_IMAGE}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_KEYSYMS}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_RANDR}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_RENDER_UTIL}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_RENDER}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_SHAPE}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_SHM}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_SYNC}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_UTIL}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_XFIXES}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_XINERAMA}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB_XKB}>
  $<$<PLATFORM_ID:Linux>:${LIB_XCB}>
  $<$<PLATFORM_ID:Linux>:${LIB_XKBCOMMON_X11}>
  $<$<PLATFORM_ID:Linux>:${LIB_XKBCOMMON}>
  $<$<PLATFORM_ID:Linux>:${LIB_XAU}>
  ${LIB_Z}
)

add_library(Qt5::Dependencies ALIAS Qt5_Dependencies)

# Restore CMAKE_FIND_LIBRARY_SUFFIXES state.
set(CMAKE_FIND_LIBRARY_SUFFIXES ${_CMAKE_FIND_LIBRARY_SUFFIXES})
