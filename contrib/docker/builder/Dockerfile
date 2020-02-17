FROM ubuntu:18.04

# install required packages
RUN apt-get update && apt-get install -y software-properties-common

RUN add-apt-repository ppa:bitcoin/bitcoin

RUN apt-get update && apt-get install -y \
    autoconf automake bsdmainutils ccache cmake curl g++ g++-mingw-w64-x86-64 gcc gcc-mingw-w64-x86-64 git \
    libboost-all-dev libbz2-dev libcap-dev libdb4.8-dev libdb4.8++-dev libevent-dev libminiupnpc-dev libprotobuf-dev \
    libqrencode-dev libssl-dev libtool make pkg-config protobuf-compiler python-pip qtbase5-dev \
    qttools5-dev-tools python3-zmq zlib1g-dev build-essential minizip lcov default-jre libzmq3-dev

RUN pip install ez_setup

# create user to use
RUN useradd -m -U zcoin-builder

# create a volume for home directory
VOLUME [ "/home/zcoin-builder" ]

# start shell with created user
USER zcoin-builder
WORKDIR /home/zcoin-builder
