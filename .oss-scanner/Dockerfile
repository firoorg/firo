FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake bsdmainutils build-essential bzip2 ca-certificates \
    cmake curl file git libtool m4 meson ninja-build patch pkg-config \
    python3 python3-zmq xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN make -C depends NO_QT=1 -j"$(nproc)"

RUN cmake -S /src -B /src/build -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE="/src/depends/$(depends/config.guess)/toolchain.cmake" \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-g -fno-omit-frame-pointer" \
      -DBUILD_GUI=OFF \
      -DBUILD_DAEMON=ON \
      -DBUILD_CLI=ON \
      -DBUILD_TESTS=ON \
      -DENABLE_WALLET=ON \
    && cmake --build /src/build -j"$(nproc)"

ENV FIROD=/src/build/bin/firod \
    FIROCLI=/src/build/bin/firo-cli \
    PATH=/src/build/bin:$PATH
