#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/smartcash.png
ICON_DST=../../src/qt/res/icons/smartcash.ico
convert ${ICON_SRC} -resize 16x16 smartcash-16.png
convert ${ICON_SRC} -resize 32x32 smartcash-32.png
convert ${ICON_SRC} -resize 48x48 smartcash-48.png
convert smartcash-16.png smartcash-32.png smartcash-48.png ${ICON_DST}
