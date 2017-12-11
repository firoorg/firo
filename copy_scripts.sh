#!/bin/bash
#copying scripts to remote project root so that VS2017 can execute them

chmod +x build.sh
chmod +x prebuild.sh
chmod +x postbuild.sh
chmod +x debug.sh
#cp -u prebuild.sh ~/build/zcoin
cp -u build.sh ~/build/zcoin
cp -u postbuild.sh ~/build/zcoin
cp -u debug.sh ~/build/zcoin



