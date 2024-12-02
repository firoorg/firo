# Try to find the GNU Multiple Precision Arithmetic Library (GMP)
# See http://gmplib.org/

if (GMP_INCLUDES AND GMP_LIBRARIES)
  set(GMP_FIND_QUIETLY TRUE)
endif (GMP_INCLUDES AND GMP_LIBRARIES)

find_path(GMP_INCLUDES
  NAMES
  gmp.h
  PATHS
  $ENV{GMPDIR}
  ${INCLUDE_INSTALL_DIR}
)

find_library(GMP_LIBRARIES gmp PATHS $ENV{GMPDIR} ${LIB_INSTALL_DIR})

add_compile_definitions(HAVE_LIBGMP=1) # Define this symbol if libgmp is installed
add_compile_definitions(USE_NUM_GMP=1) # Define this symbol to use the gmp implementation for num
add_compile_definitions(USE_FIELD_INV_NUM=1) # Define this symbol to use the num-based field inverse implementation
add_compile_definitions(USE_SCALAR_INV_NUM=1) # Define this symbol to use the num-based scalar inverse implementation

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG
                                  GMP_INCLUDES GMP_LIBRARIES)
mark_as_advanced(GMP_INCLUDES GMP_LIBRARIES)