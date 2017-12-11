#!/bin/bash

gdb --directory=$PWD/src core --args src/zcoind $1
