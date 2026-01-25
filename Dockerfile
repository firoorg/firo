# This is a Dockerfile for firod.
FROM debian:bookworm AS build-image

# Install required system packages
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    bsdmainutils \
    build-essential \
    cmake \
    curl \
    file \
    g++ \
    libtool \
    m4 \
    make \
    pkg-config \
    rsync \
    patch

# Build Firo
COPY . /tmp/firo/

WORKDIR /tmp/firo

RUN cd depends && \
    NO_QT=true make HOST=$(uname -m)-linux-gnu -j$(nproc)

RUN cmake -B build -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/$(uname -m)-linux-gnu/toolchain.cmake -DBUILD_GUI=OFF -DBUILD_TESTS=ON && \
    cmake --build build -j$(nproc) && \
    cd build && make test && \
    cmake --install . --prefix /tmp/firo/depends/$(uname -m)-linux-gnu

# extract shared dependencies of firod and firo-cli
# copy relevant binaries to /usr/bin, the COPY --from cannot use $(uname -m) variable in argument
RUN mkdir /tmp/ldd && \
    ./depends/ldd_copy.sh -b "./depends/$(uname -m)-linux-gnu/bin/firod" -t "/tmp/ldd" && \
    ./depends/ldd_copy.sh -b "./depends/$(uname -m)-linux-gnu/bin/firo-cli" -t "/tmp/ldd" && \
    cp ./depends/$(uname -m)-linux-gnu/bin/* /usr/bin/

FROM debian:bookworm

COPY --from=build-image /usr/bin/firod /usr/bin/firod
COPY --from=build-image /usr/bin/firo-cli /usr/bin/firo-cli
COPY --from=build-image /tmp/ldd /tmp/ldd

# use rsync to copy shared libraries to root filesystem
RUN apt-get update && apt-get install -y --no-install-recommends rsync && \
    rsync -av --ignore-existing /tmp/ldd/ / && \
    apt-get purge -y rsync && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/ldd && \
    ldd /usr/bin/firod

# Create user to run daemon
RUN useradd -m -U firod
USER firod

RUN mkdir /home/firod/.firo
VOLUME [ "/home/firod/.firo" ]

# Main network ports
EXPOSE 8168
EXPOSE 8888

# Test network ports
EXPOSE 18168
EXPOSE 18888

# Regression test network ports
EXPOSE 18444
EXPOSE 28888

ENTRYPOINT ["/usr/bin/firod", "-printtoconsole"]

