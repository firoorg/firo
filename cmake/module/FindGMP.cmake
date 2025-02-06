# Try to find the GNU Multiple Precision Arithmetic Library (GMP)
# See http://gmplib.org/

if (GMP_INCLUDES AND GMP_LIBRARIES)
  set(GMP_FIND_QUIETLY TRUE)
endif (GMP_INCLUDES AND GMP_LIBRARIES)

find_path(GMP_INCLUDES
  NAMES
  gmp.h
  HINTS
  $ENV{GMPDIR}
  ${INCLUDE_INSTALL_DIR}
  ${LIB_INSTALL_DIR}
  ${PC_GMP_LIBRARY_DIRS}
  /usr/lib
  /usr/local/lib
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


if(GMP_LIBRARIES AND GMP_INCLUDES)
  message(STATUS "Found GMP: ${GMP_LIBRARIES}")
  message(STATUS "GMP includes: ${GMP_INCLUDES}")
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MAJOR "${gmp_version_str}")
  
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MINOR "${gmp_version_str}")
  
  set(GMP_VERSION "${GMP_VERSION_MAJOR}.${GMP_VERSION_MINOR}")
  message(STATUS "GMP_VERSION_MAJOR : ${GMP_VERSION_MAJOR}")
  message(STATUS "GMP_VERSION_MINOR : ${GMP_VERSION_MINOR}")
else()
  message(FATAL_ERROR "Could not find GMP")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG
                                  GMP_INCLUDES GMP_LIBRARIES)
mark_as_advanced(GMP_INCLUDES GMP_LIBRARIES)