FROM ubuntu:14.04

# install required packages
RUN apt-get update && apt-get install -y software-properties-common

RUN add-apt-repository ppa:bitcoin/bitcoin

RUN apt-get update && apt-get install -y \
    autoconf automake bsdmainutils ccache cmake curl g++ g++-mingw-w64-x86-64 gcc gcc-mingw-w64-x86-64 git \
    libboost-all-dev libbz2-dev libcap-dev libdb4.8-dev libdb4.8++-dev libevent-dev libminiupnpc-dev libprotobuf-dev \
    libqrencode-dev libssl-dev libtool libzmq3-dev make pkg-config protobuf-compiler python-pip qtbase5-dev \
    qttools5-dev-tools python3-zmq \
    zlib1g-dev \ # minizip build deps
    build-essential uuid-dev libsodium-dev \ # zmq buid deps


# Install minizip from source (unavailable from apt)
RUN curl -L http://www.zlib.net/zlib-1.2.11.tar.gz | tar -xzvf -C /tmp && \
    cd tmp/zlib-1.2.11/contrib/minizip && \
    autoreconf -fi && \
    ./configure --enable-shared=no --with-pic && \
    make -j$(nproc) && make -j$(nproc) install && \
    cd / && rm -rf /tmp/zlib-1.2.11

# Install zmq from source (outdated version on apt)
RUN curl -L http://download.zeromq.org/zeromq-4.1.4.tar.gz | tar -xzvf -C /tmp && \
    cd tmp/zeromq-4.1.4/ && ./configure && make -j$(nproc) install && \
    cd / && rm -rf /tmp/zeromq-4.1.4/

RUN pip install ez_setup

# create user to use
RUN useradd -m -U zcoin-builder

# create a volume for home directory
VOLUME [ "/home/zcoin-builder" ]

# start shell with created user
USER zcoin-builder
WORKDIR /home/zcoin-builder
