#!/bin/bash

#	A helper script to automate autogen for win64; does nothing special for linux 
#	Called usually to autogen/config the project
#		-once on a brand new copy of repo
#		-everytime the configuration("TARGET") or Makefile.am are changed
#	./prebuild.sh 
#	./prebuild.sh "win64"  

#script args
TARGET="$1"

if [ "$TARGET" = "win64" ] 
then
	PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
	echo $PATH
	cd depends
	make HOST=x86_64-w64-mingw32
	echo "make ok"
	cd ..
	./autogen.sh # not required when building from tarball
	./configure --prefix==$PWD/depends/x86_64-w64-mingw32
else
	./autogen.sh
	./configure
fi
#cp -R ~/projects/dash/src .


