#!/usr/bin/env bash
echo "Install libzerocoin"
cd src/libzerocoin
mkdir build
cd build
cmake ..
make
echo "Need sudo to add libzerocoin as library"
sudo make install
cd ../../..