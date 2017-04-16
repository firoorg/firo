#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/smartcash_testnet.png
ICON_DST=../../src/qt/res/icons/smartcash_testnet.ico
convert ${ICON_SRC} -resize 16x16 smartcash_testnet-16.png
convert ${ICON_SRC} -resize 32x32 smartcash_testnet-32.png
convert ${ICON_SRC} -resize 48x48 smartcash_testnet-48.png
convert smartcash_testnet-16.png smartcash_testnet-32.png smartcash_testnet-48.png ${ICON_DST}
