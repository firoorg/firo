Release Process
====================

* * *

###update (commit) version in sources


	smartcash-qt.pro
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

 From a directory containing the smartcash source, gitian-builder and gitian.sigs
  
	export SIGNER=(your gitian key, ie bluematt, sipa, etc)
	export VERSION=0.8.7
	cd ./gitian-builder

 Fetch and build inputs: (first time, or when dependency versions change)

	mkdir -p inputs; cd inputs/
	wget 'http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.9.20140401.tar.gz' -O miniupnpc-1.9.20140401.tar.gz'
	wget 'http://www.openssl.org/source/openssl-1.0.1j.tar.gz'
	wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
	wget 'http://zlib.net/fossils/zlib-1.2.8.tar.gz'
	wget 'ftp://ftp.simplesystems.org/pub/libpng/png/src/history/libpng16/libpng-1.6.10.tar.gz'
	wget 'http://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.bz2'
	wget 'http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2'
	wget 'http://download.qt-io/archive/qt/4.8/4.8.5/qt-everywhere-opensource-src-4.8.5.tar.gz'
	wget --no-check-certificate 'https://svn.boost.org/trac/boost/raw-attachment/ticket/7262/boost-mingw.patch' -O boost-mingw-gas-cross-compile-2013-03-03.patch
	cd ..
       ./bin/make-base-vm --lxc --arch amd64 --suite trusty

 Build Windows 32bit QT wallet:
 
	./bin/gbuild ../smartcash/contrib/gitian-descriptors/boost-win32.yml
	mv build/out/boost-win32-1.55.0-gitian-r6.zip inputs/
        ./bin/gbuild ../smartcash/contrib/gitian-descriptors/deps-win32.yml
        mv build/out/smartcash-deps-win32-gitian-r3.zip inputs/
	./bin/gbuild ../smartcash/contrib/gitian-descriptors/qt-win32.yml
	mv build/out/qt-win32-4.8.5-gitian-r5.zip inputs/
        ./bin/gbuild --commit smartcash=v${VERSION} ../smartcash/contrib/gitian-descriptors/gitian-win32.yml
        ./bin/gsign --signer $SIGNER --release ${VERSION}-win32 --destination ../gitian.sigs/ ../smartcash/contrib/gitian-descriptors$
        pushd build/out
        zip -r smartcash-${VERSION}-win32-gitian.zip *
        mv smartcash-${VERSION}-win32-gitian.zip ../../
        popd
	cd ../../

 Build smartcashd and smartcash-qt on Linux32 and Linux64:
 
	./bin/gbuild --commit smartcash=master_lyra ../smartcash/contrib/gitian-descriptors/boost-linux.yml
	mv build/out/boost-linux32-1.55.0-gitian-r1.zip inputs/
	mv build/out/boost-linux64-1.55.0-gitian-r1.zip inputs/
	./bin/gbuild --commit smartcash=master_lyra ../smartcash/contrib/gitian-descriptors/deps-linux.yml
	mv build/out/smartcash-deps-linux32-gitian-r2.zip inputs/
	mv build/out/smartcash-deps-linux64-gitian-r2.zip inputs/
        ./bin/gbuild --commit smartcash=v${VERSION} ../smartcash/contrib/gitian-descriptors/gitian-linux.yml
	./bin/gsign --signer $SIGNER --release ${VERSION} --destination ../gitian.sigs/ ../smartcash/contrib/gitian-descriptors/gitian.yml
	pushd build/out
	zip -r smartcash-${VERSION}-linux-gitian.zip *
	mv smartcash-${VERSION}-linux-gitian.zip ../../
	popd

  Build output expected:

  1. linux 32-bit and 64-bit binaries + source (smartcash-${VERSION}-linux-gitian.zip)
  2. windows 32-bit binary, installer + source (smartcash-${VERSION}-win32-gitian.zip)
  3. Gitian signatures (in gitian.sigs/${VERSION}[-win32]/(your gitian key)/

 repackage gitian builds for release as stand-alone zip/tar/installer exe

**Linux .tar.gz:**

	unzip smartcash-${VERSION}-linux-gitian.zip -d smartcash-${VERSION}-linux
	tar czvf smartcash-${VERSION}-linux.tar.gz smartcash-${VERSION}-linux
	rm -rf smartcash-${VERSION}-linux

**Windows .zip and setup.exe:**

	unzip smartcash-${VERSION}-win32-gitian.zip -d smartcash-${VERSION}-win32
	mv smartcash-${VERSION}-win32/smartcash-*-setup.exe .
	zip -r smartcash-${VERSION}-win32.zip bitcoin-${VERSION}-win32
	rm -rf smartcash-${VERSION}-win32

**Perform Mac build:**

  OSX binaries are created on a dedicated 32-bit, OSX 10.6.8 machine.
  smartcash 0.8.x is built with MacPorts.  0.9.x will be Homebrew only.

	qmake RELEASE=1 USE_UPNP=1 USE_QRCODE=1 smartcash-qt.pro
	make
	export QTDIR=/opt/local/share/qt4  # needed to find translations/qt_*.qm files
	T=$(contrib/qt_translations.py $QTDIR/translations src/qt/locale)
	python2.7 share/qt/clean_mac_info_plist.py
	python2.7 contrib/macdeploy/macdeployqtplus smartcash-Qt.app -add-qt-tr $T -dmg -fancy contrib/macdeploy/fancy.plist

 Build output expected: smartcash-Qt.dmg

###Next steps:

* Code-sign Windows -setup.exe (in a Windows virtual machine) and
  OSX Bitcoin-Qt.app (Note: only Gavin has the code-signing keys currently)

* upload builds to SourceForge

* create SHA256SUMS for builds, and PGP-sign it

* update smartcash.org version
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

