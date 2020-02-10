FROM ubuntu:18.04

# install required packages
RUN apt-get update && apt-get install -y software-properties-common

RUN add-apt-repository ppa:bitcoin/bitcoin

# install packages
RUN apt-get update && apt-get install -y \
    autoconf automake bsdmainutils ccache cmake curl g++ g++-mingw-w64-x86-64 gcc gcc-mingw-w64-x86-64 git \
    libboost-all-dev libbz2-dev libcap-dev libdb4.8-dev libdb4.8++-dev libevent-dev libminiupnpc-dev libprotobuf-dev \
    libqrencode-dev libtool make pkg-config protobuf-compiler python-pip qtbase5-dev \
    qttools5-dev-tools python3-zmq zlib1g-dev build-essential minizip libzmq3-dev vim nodejs-dev node-gyp libssl1.0-dev npm wget


RUN pip install ez_setup

# Install Wine for win32 package
RUN dpkg --add-architecture i386
RUN wget -nc https://dl.winehq.org/wine-builds/winehq.key
RUN apt-key add winehq.key
RUN apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ bionic main'
RUN add-apt-repository ppa:cybermax-dexter/sdl2-backport
RUN apt update && apt install -y --install-recommends winehq-stable

# create user to use
RUN useradd -m -U zcoin-client-builder

# create a volume for home directory
VOLUME [ "/home/zcoin-client-builder" ]

RUN cd /home/zcoin-client-builder

# get repos
RUN git clone https://github.com/zcoinofficial/zcoin-client/ && \
    git clone -b client-api https://github.com/zcoinofficial/zcoin

# create directories for daemon
RUN mkdir zcoin-client/assets/core/darwin && \
    mkdir zcoin-client/assets/core/win32 && \
    mkdir zcoin-client/assets/core/linux

# get Mac SDK
RUN mkdir zcoin/depends/SDKs
RUN cd zcoin/depends/SDKs
RUN wget https://github.com/phracker/MacOSX-SDKs/releases/download/10.13/MacOSX10.11.sdk.tar.xz
RUN tar -xf MacOSX10.11.sdk.tar.xz
RUN rm -rf MacOSX10.11.sdk.tar.xz

# make daemon dependances for each OS
RUN make -C zcoin/depends -j`nproc` HOST=x86_64-apple-darwin11
RUN make -C zcoin/depends -j`nproc` HOST=x86_64-unknown-linux-gnu
RUN make -C zcoin/depends -j`nproc` HOST=x86_64-w64-mingw32

# start shell with created user
USER zcoin-client-builder
WORKDIR /home/zcoin-client-builder