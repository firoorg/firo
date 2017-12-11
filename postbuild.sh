#!/bin/bash

#	A helper script to aid VS2017 development with WSL (Linux subsystem on win10)
#	Called after the build finished, used to copy the output files to a given location
#	Also strips the symbols from the executables if the given configuration contains "Release"
#	./postbuild "" "/mnt/d/proj/dash" "~/projects/dash" "LinuxRelease"
#	./postbuild "win64" "/mnt/d/proj/dash" "~/projects/dash" "WindowsRelease"


#script args
TARGET="$1"
OUTDIR="$2"
REMOTE_BUILDDIR="$3"
CONFIG="$4"


EXT=""
if [ "$TARGET" = "win64" ] 
then
	EXT=".exe"
fi

COPYFROM="$REMOTE_BUILDDIR/src"
COPYTO="$OUTDIR$CONFIG"
if [ ! -d "$COPYTO" ]; then
	mkdir "$COPYTO"
fi
CRYPTONAME="zcoin"

mkdir -p $COPYTO

cp -u 											\
	"$COPYFROM/""$CRYPTONAME""d$EXT" 			\
	"$COPYFROM/""$CRYPTONAME""-cli$EXT"			\
	"$COPYFROM/""$CRYPTONAME""-tx$EXT" 			\
	"$COPYFROM/qt/""$CRYPTONAME""-qt$EXT" 		\
	"$COPYTO"

if [[ "$CONFIG" = *"Release"* ]]
then
	echo "Release config: stripping files from symbols"
	strip "$COPYTO/""$CRYPTONAME""d$EXT"
	strip "$COPYTO/""$CRYPTONAME""-cli$EXT"
	strip "$COPYTO/""$CRYPTONAME""-tx$EXT"
	strip "$COPYTO/""$CRYPTONAME""-qt$EXT"
#	strip "$COPYTO/""test_""$CRYPTONAME""$EXT"
fi
echo "Postbuild done"

#cp -R -u "" "$SRCDIR"