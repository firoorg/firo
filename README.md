Firo
===============

[![Financial Contributors on Open Collective](https://opencollective.com/firo/all/badge.svg?label=financial+contributors)](https://opencollective.com/firo) [![latest-release](https://img.shields.io/github/release/firoorg/firo)](https://github.com/firoorg/firo/releases)
[![GitHub last-release](https://img.shields.io/github/release-date/firoorg/firo)](https://github.com/firoorg/firo/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/firoorg/firo/total)](https://github.com/firoorg/firo/releases)
[![GitHub commits-since-last-version](https://img.shields.io/github/commits-since/firoorg/firo/latest/master)](https://github.com/firoorg/firo/graphs/commit-activity)
[![GitHub commits-per-month](https://img.shields.io/github/commit-activity/m/firoorg/firo)](https://github.com/firoorg/firo/graphs/code-frequency)
[![GitHub last-commit](https://img.shields.io/github/last-commit/firoorg/firo)](https://github.com/firoorg/firo/commits/master)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/firoorg/firo.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/firoorg/firo/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/firoorg/firo.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/firoorg/firo/context:cpp)

What is Firo?
--------------

[Firo](https://firo.org) formerly known as Zcoin, is a privacy focused cryptocurrency that utilizes zero-knowledge proofs which allows users to destroy coins and then redeem them later for brand new ones with no transaction history.

Our research created the [Lelantus privacy protocol](https://eprint.iacr.org/2019/373) which supports high anonymity sets without requiring trusted setup and relying only on standard cryptographic assumptions. The Lelantus cryptographic library was audited by [Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/zcoin-lelantus-summary.pdf) and funded by Firo's CCS. Lelantus' cryptography was also audited by [ABDK Consulting](https://www.abdk.consulting/).

Firo also utilises [Dandelion++](https://arxiv.org/abs/1805.11060) to obscure the originating IP of transactions without relying on any external services such as Tor/i2P.

Firo developed and utilizes [Merkle Tree Proofs (MTP)](https://arxiv.org/pdf/1606.03588.pdf) as its Proof-of-Work algorithm which aims to be memory hard with fast verification to encourage mining using commodity hardware.

How Firo’s Privacy Technology Compares to the Competition
--------------
![A comparison chart of Firo’s solutions with other leading privacy technologies can be found below](https://firo.org/guide/assets/privacy-technology-comparison/comparison-table-firo-updated.png) 
read more https://firo.org/guide/privacy-technology-comparison.html

Running with Docker
===================

If you are already familiar with Docker, then running Firo with Docker might be the the easier method for you. To run Firo using this method, first install [Docker](https://store.docker.com/search?type=edition&offering=community). After this you may
continue with the following instructions.

Please note that we currently don't support the GUI when running with Docker. Therefore, you can only use RPC (via HTTP or the `firo-cli` utility) to interact with Firo via this method.

Pull our latest official Docker image:

```sh
docker pull firoorg/firod
```

Start Firo daemon:

```sh
docker run -d --name firod -v "${HOME}/.firo:/home/firod/.firo" firoorg/firod
```

View current block count (this might take a while since the daemon needs to find other nodes and download blocks first):

```sh
docker exec firod firo-cli getblockcount
```

View connected nodes:

```sh
docker exec firod firo-cli getpeerinfo
```

Stop daemon:

```sh
docker stop firod
```

Backup wallet:

```sh
docker cp firod:/home/firod/.firo/wallet.dat .
```

Start daemon again:

```sh
docker start firod
```

Linux Build Instructions and Notes
==================================

Firo contains build scripts for its dependencies to ensure all component versions are compatible. For additional options
such as cross compilation, read the [depends instructions](depends/README.md)

Alternatively, you can build dependencies manually. See the full [unix build instructions](doc/build-unix.md).

Bootstrappable builds can [be achieved with Guix.](contrib/guix/README.md)

Development Dependencies (compiler and build tools)
----------------------

- Debian/Ubuntu/Mint:

    ```
    sudo apt-get update
    sudo apt-get install git curl python build-essential libtool automake pkg-config cmake
    # Also needed for GUI wallet only:
    sudo apt-get install qttools5-dev qttools5-dev-tools libxcb-xkb-dev bison
    ```

- Redhat/Fedora:

    ```
    sudo dnf update
    sudo dnf install bzip2 perl-lib perl-FindBin gcc-c++ libtool make autoconf automake cmake patch which
    # Also needed for GUI wallet only:
    sudo dnf install qt5-qttools-devel qt5-qtbase-devel xz bison
    sudo ln /usr/bin/bison /usr/bin/yacc
    ```
- Arch:

    ```
    sudo pacman -Sy
    sudo pacman -S git base-devel python cmake
    ```

Build Firo
----------------------

1.  Download the source:

        git clone https://github.com/firoorg/firo
        cd firo

2.  Build dependencies and firo:

    Headless (command-line only for servers etc.):

        cd depends
        NO_QT=true make -j`nproc`
        cd ..
        ./autogen.sh
        ./configure --prefix=`pwd`/depends/`depends/config.guess` --without-gui
        make -j`nproc`

    Or with GUI wallet as well:

        cd depends
        make -j`nproc`
        cd ..
        ./autogen.sh
        ./configure --prefix=`pwd`/depends/`depends/config.guess`
        make -j`nproc`

3.  *(optional)* It is recommended to build and run the unit tests:

        ./configure --prefix=`pwd`/depends/`depends/config.guess` --enable-tests
        make check


macOS Build Instructions and Notes
=====================================
See (doc/build-macos.md) for instructions on building on macOS.



Windows (64/32 bit) Build Instructions and Notes
=====================================
See (doc/build-windows.md) for instructions on building on Windows 64/32 bit.

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].
<a href="https://github.com/firoorg/firo/graphs/contributors"><img src="https://opencollective.com/firo/contributors.svg?width=890&button=false" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/firo/contribute)]

#### Individuals

<a href="https://opencollective.com/firo"><img src="https://opencollective.com/firo/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/firo/contribute)]

<a href="https://opencollective.com/firo/organization/0/website"><img src="https://opencollective.com/firo/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/1/website"><img src="https://opencollective.com/firo/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/2/website"><img src="https://opencollective.com/firo/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/3/website"><img src="https://opencollective.com/firo/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/4/website"><img src="https://opencollective.com/firo/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/5/website"><img src="https://opencollective.com/firo/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/6/website"><img src="https://opencollective.com/firo/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/7/website"><img src="https://opencollective.com/firo/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/8/website"><img src="https://opencollective.com/firo/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/firo/organization/9/website"><img src="https://opencollective.com/firo/organization/9/avatar.svg"></a>
