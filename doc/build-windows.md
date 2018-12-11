WINDOWS BUILD NOTES
====================

Some notes on how to build Zcoin Core for Windows.

Most developers use cross-compilation from Ubuntu to build executables for
Windows. This is also used to build the release binaries.

Building on Windows itself is possible (for example using msys / mingw-w64),
but no one documented the steps to do this. If you are doing this, please contribute them.

Cross-compilation
-------------------

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

Make sure you install the build requirements mentioned in
[build-unix.md](/doc/build-unix.md).

Then, install the toolchains and curl:

    sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev g++-mingw-w64-x86-64 mingw-w64-x86-64-dev curl


Before starting to compile you need to update mingw alternatives
    
        sudo update-alternatives --all

    There are 3 choices for the alternative x86_64-w64-mingw32-gcc (providing /usr/bin/x86_64-w64-mingw32-gcc) - we need to select - **1** and press enter

        Selection    Path                                   Priority   Status
        ------------------------------------------------------------
        0            /usr/bin/x86_64-w64-mingw32-gcc-win32   60        auto mode
        * 1          /usr/bin/x86_64-w64-mingw32-gcc-posix   30        manual mode
        2            /usr/bin/x86_64-w64-mingw32-gcc-win32   60        manual mode

Need to resolve **all mingw alternatives** in such a way.

To build executables for Windows 32-bit:

    cd depends
    make HOST=i686-w64-mingw32 -j4
    cd ..
    ./configure --prefix=`pwd`/depends/i686-w64-mingw32
    make

To build executables for Windows 64-bit:

    cd depends
    make HOST=x86_64-w64-mingw32 -j4
    cd ..
    ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32
    make

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.

