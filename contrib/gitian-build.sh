# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Systems to build
linux=
windows=
osx=

gitRepo=https://github.com/firoorg/firo
gsigsUrl=https://github.com/bitcoin-core/gitian.sigs
detachUrl=https://github.com/bitcoin-core/bitcoin-detached-sigs.git
proc=2
mem=5000
osxSdkUrl=https://github.com/MZaf/MacOSX10.11.sdk/raw/master/MacOSX10.11.sdk.tar.gz
osslTarUrl=http://downloads.sourceforge.net/project/osslsigncode/osslsigncode/osslsigncode-1.7.1.tar.gz
osslPatchUrl=https://bitcoincore.org/cfields/osslsigncode-Backports-to-1.7.1.patch
scriptName=$(basename -- "$0")

# Check for OSX SDK
if [[ ! -e "gitian-builder/inputs/MacOSX10.11.sdk.tar.gz" && $osx == true ]]; then
  wget -NP gitian-builder/inputs $osxSdkUrl
fi

# Get version
if [[ -n "$1" ]]; then
    COMMIT=$1
else
    echo "$scriptName: Missing revision to build."
    exit 1
fi

if [[ ! -d firo ]]; then
  git clone $gitRepo
fi

# Set up build
pushd firo
git fetch
git checkout ${COMMIT}
popd

# Make output folder
mkdir -p firo-binaries/${COMMIT}

# Build Dependencies
echo ""
echo "Building Dependencies"
echo ""
pushd ./gitian-builder
mkdir -p inputs
wget -N -P inputs $osslPatchUrl
wget -N -P inputs $osslTarUrl
make -C ../firo/depends download SOURCES_PATH=`pwd`/cache/common

# Linux
if [[ $linux = true ]]
then
    echo ""
    echo "Compiling ${VERSION} Linux"
    echo ""
    ./bin/gbuild -j ${proc} -m ${mem} --commit firo=${COMMIT} --url firo=${url} ../firo/contrib/gitian-descriptors/gitian-linux.yml
fi

# Windows
if [[ $windows = true ]]
then
    echo ""
    echo "Compiling ${VERSION} Windows"
    echo ""
    ./bin/gbuild -j ${proc} -m ${mem} --commit firo=${COMMIT} --url firo=${url} ../firo/contrib/gitian-descriptors/gitian-win.yml
fi

# Mac OSX
if [[ $osx = true ]]
then
    echo ""
    echo "Compiling ${VERSION} Mac OSX"
    echo ""
    ./bin/gbuild -j ${proc} -m ${mem} --commit firo=${COMMIT} --url firo=${url} ../firo/contrib/gitian-descriptors/gitian-osx.yml
fi
popd
