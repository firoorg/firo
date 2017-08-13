
Linux
====================================

Dependencies
----------------------

Build
----------------------
1.  Build Zcoin-core:

    Configure and build the headless bitcoin binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.
        
        ./autogen.sh
        CFLAGS=“-fPIC” CPPFLAGS=“-fPIC” ./configure
        make

2.  It is recommended to build and run the unit tests:

        make check

3.  You can also create a .dmg that contains the .app bundle (optional):

        make deploy



Mac OS X Build Instructions and Notes
====================================
The commands in this guide should be executed in a Terminal application.
The built-in one is located in `/Applications/Utilities/Terminal.app`.

Preparation
-----------
Install the OS X command line tools:

`xcode-select --install`

When the popup appears, click `Install`.

Then install [Homebrew](http://brew.sh).

Dependencies
----------------------

    brew install automake berkeley-db4 libtool boost --c++11 miniupnpc openssl pkg-config homebrew/versions/protobuf260 --c++11 qt5 libevent

NOTE: Building with Qt4 is still supported, however, could result in a broken UI. Building with Qt5 is recommended.

Build Zcoin Core
----------------------
1.  Build Zcoin-core:

    Configure and build the headless bitcoin binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.
        
        ./autogen.sh
        ./configure
        make

2.  It is recommended to build and run the unit tests:

        make check

3.  You can also create a .dmg that contains the .app bundle (optional):

        make deploy
