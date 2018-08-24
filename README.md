[![Build Status](https://travis-ci.com/zcoinofficial/zcoin.svg?branch=CI)](https://travis-ci.com/zcoinofficial/zcoin)
[![CircleCI](https://circleci.com/gh/zcoinofficial/zcoin/tree/CI.svg?style=svg)](https://circleci.com/gh/zcoinofficial/zcoin/tree/CI)

# Zcoin

**Private financial transactions,
enabled by the Zerocoin Protocol**

## Get Zcoin
* :arrow_double_down: Binary downloads for Windows, Linux and macOS are available in the [Releases](https://github.com/zcoinofficial/zcoin/releases) section 

## Zcoin Features
* :bust_in_silhouette: Mint and spend coins anonymously using the [Zerocoin protocol](https://zcoin.io/wp-content/uploads/2016/11/zerocoinwhitepaper.pdf)
* :globe_with_meridians: Added network-layer anonymity through [Tor](https://www.torproject.org) (fully implemented) and [Dandelion++](https://arxiv.org/pdf/1805.11060.pdf) (coming soon)
* :pick: Fair distribution of coins thanks to our ASIC-resistant Proof-of-Work algorithm [MTP](https://zcoin.io/wp-content/uploads/2018/02/mtpv12.pdf) (coming soon)

## Talk to Us 
* :baby_chick: Tweet to [@zcoinofficial](https://twitter.com/zcoinofficial)
* :speech_balloon: Join our Telegram group at https://t.me/zcoinproject
* :video_game: Talk to us on [Discord](https://discordapp.com/invite/4FjnQ2q)
* :alien: Join the conversation on [Reddit](https://www.reddit.com/r/zcoin/)


Linux Build Instructions and Notes
==================================

Dependencies
----------------------
1.  Update packages

        sudo apt-get update

2.  Install required packagages

        sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev

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

        git clone https://github.com/zcoinofficial/zcoin

2.  Build Zcoin-core:

    Configure and build the headless zcoin binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure. Include `--enable-tests` if you want to run those.
        
        ./autogen.sh
        ./configure
        make

3.  It is recommended to build and run the unit tests:

        make check


macOS Build Instructions and Notes
=====================================
See [doc/build-macos.md](doc/build-macos.md) for instructions on building on macOS.



Windows (64/32 bit) Build Instructions and Notes
=====================================
See [doc/build-windows.md](doc/build-windows.md) for instructions on building on Windows 64/32 bit.
