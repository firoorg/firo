# Using CMake to build libzerocoin

CMake version 2.8 or newer is required.

Create a build directory wherever you like:

$ mkdir build
$ cd build

Run CMake, pointing it to the source directory:

$ cmake ..

Now run the make command to compile the library:

$ make

Install the library into the system to use:

$ sudo make install

Finally, tell the system to rescan the shared library directories:

$ sudo ldconfig

The test, benchmark, tutorial, and paramgen utilites are compiled but
not installed into the system.

# CMake build options

If you wish to install libzerocoin into a non-default prefix (that is,
not to /usr/local/* ), then run cmake with this option:

$ cmake -DCMAKE_INSTALL_PREFIX=<path-to-install-prefix> <path-to-source-tree>

e.g., to install to /opt/zerocoin, run:

$ cmake -DCMAKE_INSTALL_PREFIX=/opt/zerocoin ..

To make a debug version of the library, add -DCMAKE_BUILD_TYPE=DEBUG
to the cmake command line:

$ cmake -DCMAKE_BUILD_TYPE=DEBUG ..

When compiling the library with 'make' you can set VERBOSE=1 to show
the process in more detail:

$ make VERBOSE=1
