Zcoin v0.13.6.9
=============

[![Build Status](https://travis-ci.com/zcoinofficial/zcoin.svg?branch=CI)](https://travis-ci.com/zcoinofficial/zcoin)

What is Zcoin?
--------------

[Zcoin](https://zcoin.io) is the first full implementation of the Zerocoin Protocol, which allows users to have complete privacy via Zero-Knowledge cryptographic proofs. It is worth noting that Zcoin is unrelated to other cryptocurrencies utilizing the Zerocash Protocol. Although Zerocash is a development from Zerocoin, their respective implementations are not simple forks of each other, but rely on different cryptographic assumptions with various tradeoffs. Both approaches supplement each other quite nicely, and a good way to describe them would be sibling projects.

The Zerocoin Protocol is being actively researched and improved, such as removing the trustless setup and reducing proof sizes.

Running with Docker
===================

If you are already familiar with Docker, then running Zcoin with Docker might be the the easier method for you. To run Zcoin using this method, first install [Docker](https://store.docker.com/search?type=edition&offering=community). After this you may
continue with the following instructions.

Please note that we currently don't support the GUI when running with Docker. Therefore, you can only use RPC (via HTTP or the `zcoin-cli` utility) to interact with Zcoin via this method.

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

        sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev libzmq3-dev

3.  Install Berkeley DB 4.8

        sudo apt-get install software-properties-common
        sudo add-apt-repository ppa:bitcoin/bitcoin
        sudo apt-get update
        sudo apt-get install libdb4.8-dev libdb4.8++-dev

4.  Install QT 5

        sudo apt-get install libminiupnpc-dev
        sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev

Build
----------------------
1.  Clone the source:

        git clone https://github.com/zcoinofficial/zcoin

2.  Build Zcoin-core:

    Configure and build the headless Zcoin binaries as well as the GUI (if Qt is found).

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
