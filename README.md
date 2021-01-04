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

[Firo](https://firo.org) is a privacy focused cryptocurrency that uses the [Lelantus Technology](https://eprint.iacr.org/2019/373) which allows users to burn their coins, which hides them in an anonymity set of over 65,000. The receiver can redeem it from this anonymity pool, which breaks the links from your transaction and all the previous ones it has been through. It was the first project to implement the Zerocoin protocol and then transitioned to the [Sigma protocol](https://firo.org/2019/03/20/what-is-sigma.html) which has no trusted setup and small proof sizes. Firo also utilises [Dandelion++](https://arxiv.org/abs/1805.11060) to obscure the originating IP of transactions without relying on any external services such as Tor/i2P.

Firo developed and utilizes [Merkle Tree Proofs (MTP)](https://arxiv.org/pdf/1606.03588.pdf) as its Proof-of-Work algorithm which aims to be memory hard with fast verification.

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
docker run --detach --name firod firoorg/firod
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

Dependencies
----------------------
1.  Update packages

        sudo apt-get update

2.  Install required packages

        sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev libgmp-dev cmake

3.  Install Berkeley DB 4.8

        sudo apt-get install software-properties-common
        sudo add-apt-repository ppa:bitcoin/bitcoin
        sudo apt-get update
        sudo apt-get install libdb4.8-dev libdb4.8++-dev

4.  Install QT 5

        sudo apt-get install libminiupnpc-dev libzmq3-dev
        sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev

Build
----------------------
1.  Clone the source:

        git clone https://github.com/firoorg/firo

2.  Build Firo-core:

    Configure and build the headless Firo binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.
        
        ./autogen.sh
        ./configure
        make

3.  It is recommended to build and run the unit tests:

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
