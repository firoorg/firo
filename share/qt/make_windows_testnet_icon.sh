#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/zcoin_testnet.png
ICON_DST=../../src/qt/res/icons/zcoin_testnet.ico
convert ${ICON_SRC} -resize 16x16 zcoin_testnet-16.png
convert ${ICON_SRC} -resize 32x32 zcoin_testnet-32.png
convert ${ICON_SRC} -resize 48x48 zcoin_testnet-48.png
convert zcoin_testnet-16.png zcoin_testnet-32.png zcoin_testnet-48.png ${ICON_DST}
