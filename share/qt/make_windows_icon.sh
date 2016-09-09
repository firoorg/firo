#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/zcoin.png
ICON_DST=../../src/qt/res/icons/zcoin.ico
convert ${ICON_SRC} -resize 16x16 zcoin-16.png
convert ${ICON_SRC} -resize 32x32 zcoin-32.png
convert ${ICON_SRC} -resize 48x48 zcoin-48.png
convert zcoin-16.png zcoin-32.png zcoin-48.png ${ICON_DST}
