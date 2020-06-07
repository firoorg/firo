#!/bin/bash

export AR CCACHE CC CFLAGS CXX CXXFLAGS NM OBJC RANLIB LDFLAGS LIB

cmake_osflags="-DOPSYS=LINUX -DCMAKE_SYSTEM_NAME=Linux"
case $host_alias in
  *mingw*)
    cmake_osflags="-DOPSYS=WINDOWS -DCMAKE_SYSTEM_NAME=Windows"
   ;;
  *darwin*)
    cmake_osflags="-DOPSYS=MACOSX -DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_AR=$AR -DCMAKE_RANLIB=$RANLIB"
  ;;
esac

if test "x$enable_tests" == "xyes"
then
  cmake_osflags="$cmake_osflags -DENABLE_TESTS=1"
fi

cmake -Bbuild -H. -DCMAKE_INSTALL_PREFIX=$depends_prefix -DWSIZE=64 -DMULTI=PTHREAD -DARITH=gmp $cmake_osflags
