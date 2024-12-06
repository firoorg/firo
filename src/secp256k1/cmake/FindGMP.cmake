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

# Define this symbol if libgmp is installed
add_compile_definitions(HAVE_LIBGMP=1)
# Define this symbol to use the gmp implementation for num
add_compile_definitions(USE_NUM_GMP=1)
# Define this symbol to use the num-based field inverse implementation  
add_compile_definitions(USE_FIELD_INV_NUM=1)
# Define this symbol to use the num-based scalar inverse implementation    
add_compile_definitions(USE_SCALAR_INV_NUM=1)

if(GMP_INCLUDES)
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MAJOR "${gmp_version_str}")
  
  file(STRINGS "${GMP_INCLUDES}/gmp.h" gmp_version_str REGEX "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+[0-9]+")
  string(REGEX REPLACE "^#define[\t ]+__GNU_MP_VERSION_MINOR[\t ]+([0-9]+).*" "\\1" GMP_VERSION_MINOR "${gmp_version_str}")
  
  set(GMP_VERSION "${GMP_VERSION_MAJOR}.${GMP_VERSION_MINOR}")
  message(STATUS "GMP_VERSION_MAJOR : ${GMP_VERSION_MAJOR}")
  message(STATUS "GMP_VERSION_MINOR : ${GMP_VERSION_MINOR}")
endif()