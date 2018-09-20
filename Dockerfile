# This is a Dockerfile for zcoind.
FROM debian:stretch

# Install required system packages
RUN apt-get update && apt-get install -y \
    automake \
    bsdmainutils \
    curl \
    g++ \
    libboost-all-dev \
    libevent-dev \
    libssl-dev \
    libtool \
    libzmq3-dev \
    make \
    openjdk-8-jdk \
    pkg-config \
    zlib1g-dev

# Install Berkeley DB 4.8
RUN curl -L http://download.oracle.com/berkeley-db/db-4.8.30.tar.gz | tar -xz -C /tmp && \
    cd /tmp/db-4.8.30/build_unix && \
    ../dist/configure --enable-cxx --includedir=/usr/include/bdb4.8 --libdir=/usr/lib && \
    make && make install && \
    cd / && rm -rf /tmp/db-4.8.30

# Create user to run daemon
RUN useradd -m -U zcoind

# Build Zcoin
COPY . /tmp/zcoin/

RUN cd /tmp/zcoin && \
    ./autogen.sh && \
    ./configure --without-gui --prefix=/usr && \
    make && \
    make check && \
    make install && \
    cd / && rm -rf /tmp/zcoin

# Remove unused packages
RUN apt-get remove -y \
    automake \
    bsdmainutils \
    curl \
    g++ \
    libboost-all-dev \
    libevent-dev \
    libssl-dev \
    libtool \
    libzmq3-dev \
    make

# Start Zcoin Daemon
USER zcoind

RUN mkdir /home/zcoind/.zcoin
VOLUME [ "/home/zcoind/.zcoin" ]

EXPOSE 8168
EXPOSE 8888
EXPOSE 18444

ENTRYPOINT [ "/usr/bin/zcoind" ]
