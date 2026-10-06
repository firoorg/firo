macOS Build Instructions and Notes
====================================
The commands in this guide should be executed in a Terminal application.
The built-in one is located in `/Applications/Utilities/Terminal.app`.

## Preparation
1. Install macOS Command Line Tools (if not already installed):
   ```bash
   xcode-select --install
   ```
   When the popup appears, click `Install`.


2. Install Homebrew (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```


## Dependencies
Install the required dependencies using Homebrew:
```bash
brew install automake berkeley-db4 libtool boost miniupnpc openssl protobuf python qt libevent qrencode python-setuptools m4
```

In case you want to build the disk image with `make deploy` (.dmg / optional), you need RSVG:
```bash
brew install librsvg
```

### Ensure `m4` is Found
After installing `m4`, it is important to note that `m4` is a `keg-only` formula in Homebrew. This means it is not symlinked into `/usr/local` by default. To make sure `m4` is available in your PATH, you'll need to link it manually with the `--force` flag:
```bash
brew link m4 --force
```

You can verify that `m4` is properly linked and available by running:
```bash
which m4
```
This should output the path to the `m4` binary, typically `/opt/homebrew/bin/m4` on Apple Silicon Macs. If you do not use the `--force` flag, `which m4` will likely output `/usr/bin/m4`, which is the system version and not the one installed via Homebrew.

### Troubleshooting `m4` Issues
If `m4` is not found even after installation and linking with `--force`, you may need to install Xcode to ensure that `m4` is recognized:

1. Install Xcode from the Mac App Store.
2. Once installed, open Xcode at least once to complete the setup.

#### Berkeley DB
It is recommended to use Berkeley DB 4.8. If you have to build it yourself, you can use [the installation script included in contrib/](https://github.com/bitcoin/bitcoin/blob/master/contrib/install_db4.sh) like so:
```bash
./contrib/install_db4.sh 
```
from the root of the repository.

*Note*: You only need Berkeley DB if the wallet is enabled (see Disable-wallet mode).

## Build Instructions

#### Download the Source
Before building, download the Firo source code:
```bash
git clone https://github.com/firoorg/firo
cd firo
```

#### Build Firo Core
1. **Prepare the build environment**:
   ```bash
   cd depends
   make
   cd ..
   ```

2. **Configure and build Firo-core**:
   ```bash
   ./autogen.sh
   ./configure --prefix=`pwd`/depends/`depends/config.guess`
   make
   ```

3. (optional) **It is recommended to build and run the unit tests**:
   ```bash
   ./configure --prefix=`pwd`/depends/`depends/config.guess` --enable-tests
   make check
   ```
        
4. (optional) **You can also create a .dmg that contains the .app bundle**:
    ```bash
    make deploy
    ```


Running
-------

Firo Core is now available at `./src/firod`

Before running, it's recommended you create an RPC configuration file.

    echo -e "rpcuser=bitcoinrpc\nrpcpassword=$(xxd -l 16 -p /dev/urandom)" > "/Users/${USER}/Library/Application Support/firo/firo.conf"

    chmod 600 "/Users/${USER}/Library/Application Support/firo/firo.conf"

The first time you run firod, it will start downloading the blockchain. This process could take several hours.

You can monitor the download process by looking at the debug.log file:

    tail -f $HOME/Library/Application\ Support/firo/debug.log

Other commands:
-------

    ./src/firod -daemon # Starts the Firo daemon.
    ./src/firo-cli --help # Outputs a list of command-line options.
    ./src/firo-cli help # Outputs a list of RPC commands when the daemon is running.

Using Qt Creator as IDE
------------------------
You can use Qt Creator as an IDE, for bitcoin development.
Download and install the community edition of [Qt Creator](https://www.qt.io/download/).
Uncheck everything except Qt Creator during the installation process.

1. Make sure you installed everything through Homebrew mentioned above
2. Properly configure the build environment:
   ```bash
   ./configure --prefix=`pwd`/depends/`depends/config.guess` --enable-debug
   ```
3. In Qt Creator do "New Project" -> Import Project -> Import Existing Project
4. Enter "bitcoin-qt" as project name, enter `src/qt` as location
5. Leave the file selection as it is
6. Confirm the "summary page"
7. In the "Projects" tab select "Manage Kits..."
8. Select the default "Desktop" kit and select "Clang (x86 64bit in /usr/bin)" as compiler
9. Select LLDB as debugger (you might need to set the path to your installation)
10. Start debugging with Qt Creator

Notes
-----

* Tested on macOS 10.11 through 10.14 on 64-bit Intel processors, and on macOS 14.5 on an M2 chip.

* Building with downloaded Qt binaries is not officially supported. See the notes in [#7714](https://github.com/bitcoin/bitcoin/issues/7714)
