Release Process
====================

* * *

###update (commit) version in sources


	zcoin-qt.pro
	contrib/verifysfbinaries/verify.sh
	doc/README*
	share/setup.nsi
	src/clientversion.h (change CLIENT_VERSION_IS_RELEASE to true)

###tag version in git

	git tag -s v0.8.7

###write release notes. git shortlog helps a lot, for example:

	git shortlog --no-merges v0.7.2..v0.8.0

* * *

##perform gitian builds

 From a directory containing the zcoin source, gitian-builder and gitian.sigs
  
	export SIGNER=(your gitian key, ie bluematt, sipa, etc)
	export VERSION=0.8.7
	cd ./gitian-builder

 Fetch and build inputs: (first time, or when dependency versions change)

	mkdir -p inputs; cd inputs/
	wget 'http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.9.20140401.tar.gz' -O miniupnpc-1.9.20140401.tar.gz
	wget 'http://www.openssl.org/source/openssl-1.0.2g.tar.gz'
	wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
	wget 'https://www.zlib.net/fossils/zlib-1.2.8.tar.gz'
	wget 'ftp://ftp.simplesystems.org/pub/libpng/png/src/history/libpng16/libpng-1.6.8.tar.gz'
	wget 'http://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.bz2'
	wget 'http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2'
	wget -q 'https://svn.boost.org/trac/boost/raw-attachment/ticket/7262/boost-mingw.patch' -O boost-mingw-gas-cross-compile-2013-03-03.patch
	wget 'http://download.qt.io/archive/qt/5.2/5.2.0/single/qt-everywhere-opensource-src-5.2.0.tar.gz'
	wget 'ftp://ftp.fi.debian.org/gentoo/distfiles/protobuf-2.5.0.tar.bz2'
	cd ..
	cd gitian-builder/
	./bin/gbuild ../zcoin/contrib/gitian-descriptors/boost-win.yml
	mv build/out/boost-*.zip inputs/
	./bin/gbuild ../zcoin/contrib/gitian-descriptors/deps-win.yml
	mv build/out/zcoin-*.zip inputs/
	./bin/gbuild ../zcoin/contrib/gitian-descriptors/qt-win.yml
	mv build/out/qt-*.zip inputs/
	./bin/gbuild ../zcoin/contrib/gitian-descriptors/protobuf-win.yml
	mv build/out/protobuf-*.zip inputs/

 Build zcoind and zcoin-qt on Linux32, Linux64, and Win32:
  
	./bin/gbuild --commit zcoin=v${VERSION} ../zcoin/contrib/gitian-descriptors/gitian.yml
	./bin/gsign --signer $SIGNER --release ${VERSION} --destination ../gitian.sigs/ ../zcoin/contrib/gitian-descriptors/gitian.yml
	pushd build/out
	zip -r zcoin-${VERSION}-linux-gitian.zip *
	mv zcoin-${VERSION}-linux-gitian.zip ../../
	popd
	./bin/gbuild --commit zcoin=v${VERSION} ../zcoin/contrib/gitian-descriptors/gitian-win.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-win32 --destination ../gitian.sigs/ ../zcoin/contrib/gitian-descriptors/gitian-win32.yml
	pushd build/out
	zip -r zcoin-${VERSION}-win32-gitian.zip *
	mv zcoin-${VERSION}-win32-gitian.zip ../../
	popd

  Build output expected:

  1. linux 32-bit and 64-bit binaries + source (zcoin-${VERSION}-linux-gitian.zip)
  2. windows 32-bit binary, installer + source (zcoin-${VERSION}-win32-gitian.zip)
  3. Gitian signatures (in gitian.sigs/${VERSION}[-win32]/(your gitian key)/

repackage gitian builds for release as stand-alone zip/tar/installer exe

**Linux .tar.gz:**

	unzip zcoin-${VERSION}-linux-gitian.zip -d zcoin-${VERSION}-linux
	tar czvf zcoin-${VERSION}-linux.tar.gz zcoin-${VERSION}-linux
	rm -rf zcoin-${VERSION}-linux

**Windows .zip and setup.exe:**

	unzip zcoin-${VERSION}-win32-gitian.zip -d zcoin-${VERSION}-win32
	mv zcoin-${VERSION}-win32/zcoin-*-setup.exe .
	zip -r zcoin-${VERSION}-win32.zip zcoin-${VERSION}-win32
	rm -rf zcoin-${VERSION}-win32

**Perform Mac build:**

  OSX binaries are created on a dedicated 32-bit, OSX 10.6.8 machine.
  zcoin 0.8.x is built with MacPorts.  0.9.x will be Homebrew only.

	qmake RELEASE=1 USE_UPNP=1 USE_QRCODE=1 zcoin-qt.pro
	make
	export QTDIR=/opt/local/share/qt4  # needed to find translations/qt_*.qm files
	T=$(contrib/qt_translations.py $QTDIR/translations src/qt/locale)
	python2.7 share/qt/clean_mac_info_plist.py
	python2.7 contrib/macdeploy/macdeployqtplus zcoin-Qt.app -add-qt-tr $T -dmg -fancy contrib/macdeploy/fancy.plist

 Build output expected: zcoin-Qt.dmg

###Next steps:

* Code-sign Windows -setup.exe (in a Windows virtual machine) and
  OSX zcoin-qt.app (Note: only Gavin has the code-signing keys currently)

* upload builds to SourceForge

* create SHA256SUMS for builds, and PGP-sign it

* update zcoin.org version
  make sure all OS download links go to the right versions

* update forum version

* update wiki download links



Commit your signature to gitian.sigs:

	pushd gitian.sigs
	git add ${VERSION}/${SIGNER}
	git add ${VERSION}-win32/${SIGNER}
	git commit -a
	git push  # Assuming you can push to the gitian.sigs tree
	popd

