#!/bin/bash
set -e

# get gitian
echo
echo "Getting Gitian"
echo

git init
echo

git remote add origin https://github.com/zcoinofficial/gitian-builder.git
git pull origin master

# create build environment
echo
echo "Setting-up Build Environment"
echo

docker image rm -f base-trusty-amd64 2> /dev/null
echo

./bin/make-base-vm --distro ubuntu --suite trusty --arch amd64 --docker

export USE_DOCKER=1

# get macOS sdk
echo
echo "Getting macOS SDK"
echo

curl -L -o inputs/MacOSX10.11.sdk.tar.gz https://bitcoincore.org/depends-sources/sdks/MacOSX10.11.sdk.tar.gz

# get dependencies patches
echo
echo "Getting patches for dependencies"
echo

pushd inputs

curl -LO https://bitcoincore.org/cfields/osslsigncode-Backports-to-1.7.1.patch
curl -LO http://downloads.sourceforge.net/project/osslsigncode/osslsigncode/osslsigncode-1.7.1.tar.gz

popd

# get dependencies
echo
echo "Getting Dependencies"
echo

make -C inputs/zcoin/depends download SOURCES_PATH=$(pwd)/cache/common

# get project properties
pushd inputs/zcoin > /dev/null

version=$(git describe --tags HEAD | cut -c 2-)

popd > /dev/null

# copy cert_server_details
cp /home/environment.conf inputs

# prepare build
mkdir zcoin-binaries

NCPU=$(nproc)

# build Linux binary
echo
echo "[$version] Building Linux Binary"
echo

./bin/gbuild -j ${NCPU} --commit zcoin=v$version inputs/zcoin/contrib/gitian-descriptors/gitian-linux.yml

mv build/out/zcoin-*.tar.gz build/out/src/zcoin-*.tar.gz zcoin-binaries

# build Windows binary
echo
echo "[$version] Building Windows Binary"
echo

./bin/gbuild -j ${NCPU} --commit zcoin=v$version inputs/zcoin/contrib/gitian-descriptors/gitian-win.yml

mv build/out/zcoin-*.zip build/out/zcoin-*.exe zcoin-binaries

# build macOS binary
echo
echo "[$version] Building macOS Binary"
echo

./bin/gbuild -j ${NCPU} --commit zcoin=v$version inputs/zcoin/contrib/gitian-descriptors/gitian-osx.yml

mv build/out/zcoin-*.tar.gz build/out/zcoin-*.dmg zcoin-binaries
