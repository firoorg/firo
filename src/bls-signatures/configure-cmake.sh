#!/bin/bash

vars=$(set -o posix; set)
while IFS= read -r var
do
  if test "${var#*=}" == "$var"
  then
    continue
  fi
  eval $(echo "$var" | awk -F= '{ print "export " $1 }')
done <<< "$vars"


cmake_osflags="-DOPSYS=LINUX -DCMAKE_SYSTEM_NAME=Linux"
case $host_alias in
  *mingw*)
    cmake_osflags="-DOPSYS=WINDOWS -DCMAKE_SYSTEM_NAME=Windows"
   ;;
  *darwin*)
    cmake_osflags="-DOPSYS=MACOSX -DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_AR=$AR -DCMAKE_RANLIB=$RANLIB"
  ;;
esac


set -e
mkdir -p build
cd build
cmake ../ -DWSIZE=64 -DMULTI=PTHREAD -DARITH=easy $cmake_osflags
