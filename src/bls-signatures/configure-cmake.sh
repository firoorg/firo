#!/bin/bash

set -e
mkdir -p build
cd build
cmake ../ -DWSIZE=64 -DMULTI=PTHREAD -DARITH=easy
