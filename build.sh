#!/bin/bash

#	A helper script to automate remote build process
#	VS2017 "Copy Sources" function is too plain and simply copies all the 
#	source files to given destination, ignoring the directory tree structure,
#	which causes Makefile work improperly.
#
#	This script handles copying all the source files into from given SRCDIR 
#	to an arbitrary path(subject to change), while maintaining directory tree structure.
#	Only copies these extensions:
#	.c, .cc, .cpp, .h


#script args
HOST_PROJECTDIR="$1"
REMOTE_PROJECTDIR="$2"


#save current working directory
CURRENTDIR=$PWD
cd "$HOST_PROJECTDIR/src/"
echo "Copying sources(.c, .cc, .cpp, .h) from $PWD to $REMOTE_PROJECTDIR/src/"
find . -name '*.c' -name '*.cc' -o -name '*.cpp' -o -name '*.h' | cpio -pdm "$REMOTE_PROJECTDIR/src/"

echo "Sources copied"

#return to the original working directory
cd $CURRENTDIR

make


