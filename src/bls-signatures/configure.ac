AC_INIT([blssig], [0.14.0])

AC_PROG_CC
AC_PROG_CXX

(source ./configure-cmake.sh)
cmake_result=$?

if test "x$cmake_result" != "x0";
then
    AC_MSG_ERROR([Cannot execute configure-cmake.sh])
fi

AC_OUTPUT

