find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_GMP QUIET gmp)
endif()

find_path(GMP_INCLUDES
  NAMES
  gmp.h
  HINTS
  $ENV{GMPDIR}
  ${INCLUDE_INSTALL_DIR}
  ${PC_GMP_INCLUDE_DIRS}
  /usr/include
  /usr/local/include
)

find_library(GMP_LIBRARIES
  NAMES gmp
  HINTS
  $ENV{GMPDIR}
  ${LIB_INSTALL_DIR}
  ${PC_GMP_LIBRARY_DIRS}
  /usr/lib
  /usr/local/lib
)

if(GMP_INCLUDES)
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MAJOR "${gmp_version_str}")
  
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MINOR "${gmp_version_str}")
  
  set(GMP_VERSION "${GMP_VERSION_MAJOR}.${GMP_VERSION_MINOR}")
  message(STATUS "GMP_VERSION_MAJOR : ${GMP_VERSION_MAJOR}")
  message(STATUS "GMP_VERSION_MINOR : ${GMP_VERSION_MINOR}")
endif()