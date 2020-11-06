Firo
===============

[![Financial Contributors on Open Collective](https://opencollective.com/firo/all/badge.svg?label=financial+contributors)](https://opencollective.com/firo) [![latest-release](https://img.shields.io/github/release/zcoinofficial/zcoin)](https://github.com/firoorg/firo/releases)
[![GitHub last-release](https://img.shields.io/github/release-date/zcoinofficial/zcoin)](https://github.com/firoorg/firo/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/zcoinofficial/zcoin/total)](https://github.com/firoorg/firo/releases)
[![GitHub commits-since-last-version](https://img.shields.io/github/commits-since/zcoinofficial/zcoin/latest/master)](https://github.com/firoorg/firo/graphs/commit-activity)
[![GitHub commits-per-month](https://img.shields.io/github/commit-activity/m/zcoinofficial/zcoin)](https://github.com/firoorg/firo/graphs/code-frequency)
[![GitHub last-commit](https://img.shields.io/github/last-commit/zcoinofficial/zcoin)](https://github.com/firoorg/firo/commits/master)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/zcoinofficial/zcoin.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/firoorg/firo/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/zcoinofficial/zcoin.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/zcoinofficial/zcoin/context:cpp)

What is Firo?
--------------

[Firo](https://Firo.org) is a privacy focused cryptocurrency that utilizes zero-knowledge proofs which allows users to destroy coins and then redeem them later for brand new ones with no transaction history. It was the first project to implement the Zerocoin protocol and has now transitioned to the [Sigma protocol](https://zcoin.io/what-is-sigma-and-why-is-it-replacing-zerocoin-in-zcoin/) which has no trusted setup and small proof sizes. Firo also utilises [Dandelion++](https://arxiv.org/abs/1805.11060) to obscure the originating IP of transactions without relying on any external services such as Tor/i2P.

Firo developed and utilizes [Merkle Tree Proofs (MTP)](https://arxiv.org/pdf/1606.03588.pdf) as its Proof-of-Work algorithm which aims to be memory hard with fast verification.

How Firo’s Privacy Technology Compares to the Competition
--------------
![A comparison chart of Zcoin’s solutions with other leading privacy technologies can be found below](https://zcoin.io/wp-content/uploads/2019/04/zcoin_table_coloured5-01.png) 
read more https://zcoin.io/zcoins-privacy-technology-compares-competition/

Running with Docker
===================

If you are already familiar with Docker, then running Firo with Docker might be the the easier method for you. To run Firo using this method, first install [Docker](https://store.docker.com/search?type=edition&offering=community). After this you may
continue with the following instructions.

Please note that we currently don't support the GUI when running with Docker. Therefore, you can only use RPC (via HTTP or the `zcoin-cli` utility) to interact with Firo via this method.

Pull our latest official Docker image:

```sh
docker pull zcoinofficial/zcoind
```

Start Zcoin daemon:

```sh
docker run --detach --name zcoind zcoinofficial/zcoind
```

View current block count (this might take a while since the daemon needs to find other nodes and download blocks first):

```sh
docker exec zcoind zcoin-cli getblockcount
```

View connected nodes:

```sh
docker exec zcoind zcoin-cli getpeerinfo
```

Stop daemon:

```sh
docker stop zcoind
```

Backup wallet:

```sh
docker cp zcoind:/home/zcoind/.zcoin/wallet.dat .
```

Start daemon again:

```sh
docker start zcoind
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

2.  Build Zcoin-core:

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
<a href="https://github.com/zcoinofficial/zcoin/graphs/contributors"><img src="https://opencollective.com/zcoin/contributors.svg?width=890&button=false" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/firo/contribute)]

#### Individuals

<a href="https://opencollective.com/zcoin"><img src="https://opencollective.com/firo/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/zcoin/contribute)]

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
