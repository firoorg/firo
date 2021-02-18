# How to compile and execute Firo code on Windows 10

There are two possibilities of compiling Firo code on Windows 10.
 Both of them are based on using [WSL/Ubuntu](https://msdn.microsoft.com/en-us/commandline/wsl/install_guide).
 The main difference is in execution, using first method you will get .exe files, otherwise you need to use [Xming](http://www.straightrunning.com/XmingNotes/) to start **GUI**.
 
 **We recommend using the first method**.

 Prerequisites:
 
 * Windows 10 x64
 * [WSL/Ubuntu](https://msdn.microsoft.com/en-us/commandline/wsl/install_guide) installed
---
For the more complex second execution method, you need to install
 * [Xming](http://www.straightrunning.com/XmingNotes/) latest version, if you are planning to compile using [unix compiling instruction](https://github.com/firoorg/firo/blob/master/doc/build-unix.md)


## Pre common steps

1. Launch Ubuntu shell (search for Bash in the "Type here to search" box)
2. Upgrade outdated packages. This applies even if you just installed WSL.
      
```
  sudo apt-get update
  sudo apt-get dist-upgrade
  sudo apt-get autoremove
```
3.   Install build tools 

        `sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils git`

4. Make shared folder between two locations

    Generally it's OK to read these files from generic Windows app, but Unix file permissions are stored in extended
    attributes which are not properly updated by usual applications. For example, if you create a file/directory inside
    WSL subsystem from Explorer it won't be visible by WSL program.

    **To share files between two locations** we need to create a directory for the repository in your Windows home directory
    and then create a link from the WSL to it:

    * From Explorer create a directory named:

            C:\Users\<username>\firo
    * From Ubuntu bash window create a link to it:
  
            ln -s /mnt/c/Users/<username>/firo firo   
    
    After creating link, please check that linked directory has blue font color, which means that is was successfully linked. Otherwise check path symbols. Error can be because of spaces, uppercase symbols e.t.c...

5. Clone git repository into newly created directory and go to the right branch
   
            git clone https://github.com/firoorg/firo.git
            cd firo
    If you are not authorized in git, configure git to always use LF and (optionally) specify your name/email. Global Windows git settings (if set)
    won't be inherited if git is invoked from Ubuntu shell.

            git config core.autocrlf input
            git config user.name "Your Name"
            git config user.email "your.email"
---
## First method - Windows execution files
 1. Install cross-compilation tools

        sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev g++-mingw-w64-x86-64 mingw-w64-x86-64-dev curl

1. Build fails when there are special symbols (space, parentheses etc) in path directories. Reset path to the simple one

        export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    Also if WSL interop is enabled some parts might not get configured for cross-compilation and will ultimately fail.
    Disable it for the WSL session:

        sudo bash -c 'echo 0 > /proc/sys/fs/binfmt_misc/WSLInterop'

2. Dependencies won't compile in a directory shared with Windows. We need to copy everything to the space private to
    WSL. Do not use .. here as it will lead you into different directory

        cp -r depends ~/firo-depends

3. Go to depends folder and build dependencies (you may wish to build only 32-bit or 64-bit version)

        cd ~/firo-depends
        make HOST=i686-w64-mingw32 -j`nproc`
        make HOST=x86_64-w64-mingw32 -j`nproc`
        cd ~/firo
    It takes a while. You need to do it only once unless you delete firo-depends directory

4. Generate configure script

        ./autogen.sh

5. Before starting to compile you need to update mingw alternatives
    
        sudo update-alternatives --all

    There are 3 choices for the alternative x86_64-w64-mingw32-gcc (providing /usr/bin/x86_64-w64-mingw32-gcc) - we need to select - **1** and press enter

        Selection    Path                                   Priority   Status
        ------------------------------------------------------------
        0            /usr/bin/x86_64-w64-mingw32-gcc-win32   60        auto mode
        * 1          /usr/bin/x86_64-w64-mingw32-gcc-posix   30        manual mode
        2            /usr/bin/x86_64-w64-mingw32-gcc-win32   60        manual mode

    Need to resolve **all mingw alternatives** in such a way.

    Now do either step **7** OR step **8**, not both.

6. Build 32-bit debug build (from the Firo root directory)
    
        ./configure --prefix=$HOME/firo-depends/i686-w64-mingw32
        make -j`nproc`

7. Build 64-bit debug build (from the Firo root directory)
     
        ./configure --prefix=$HOME/firo-depends/x86_64-w64-mingw32
        make -j`nproc`

8. After check the directory to run GUI with __firo-qt.exe__
    
        C:\Users\<username>\firo\src\qt
----
## Second method - Ubuntu + Xming
1. Use existing paper [build-unix](https://github.com/firoorg/firo/blob/master/doc/build-unix.md) and
    * Install all dependencies
    * Build app
2. Start installed Xming in Windows
3. From Ubuntu bash window start output to Xming:
   
        export DISPLAY=localhost:0.0
4. From Ubuntu bash window start firo-qt:

        cd /mnt/c/Users/<username>/firo/src/qt
        ./firo-qt 

