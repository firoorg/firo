#!/bin/bash
set -euo pipefail

# Only run in remote (Cloud) environments
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-/home/user/firo}"
BUILD_DIR="${PROJECT_DIR}/build"

# Skip if already fully built
if [ -f "${BUILD_DIR}/bin/firod" ] && [ -f "${BUILD_DIR}/bin/test_firo" ]; then
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "export PATH=\"${BUILD_DIR}/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  fi
  exit 0
fi

########################################
# 1. Configure apt proxy for Cloud env
########################################
if [ -n "${HTTP_PROXY:-}" ] && [ ! -f /etc/apt/apt.conf.d/99proxy ]; then
  echo "Acquire::http::Proxy \"${HTTP_PROXY}\";" | sudo tee /etc/apt/apt.conf.d/99proxy >/dev/null
  echo "Acquire::https::Proxy \"${HTTP_PROXY}\";" | sudo tee -a /etc/apt/apt.conf.d/99proxy >/dev/null
fi

########################################
# 2. Install system packages
########################################
PACKAGES=(
  # Build tools
  ccache
  ninja-build
  pkg-config
  autoconf
  automake
  libtool
  bsdmainutils

  # Core libraries
  libboost-system-dev
  libboost-filesystem-dev
  libboost-program-options-dev
  libboost-thread-dev
  libboost-chrono-dev
  libboost-atomic-dev
  libboost-test-dev
  libssl-dev
  libevent-dev
  libgmp-dev
  libzmq3-dev
  libsqlite3-dev
  libdb5.3++-dev
  libminiupnpc-dev
  zlib1g-dev

  # Linting
  clang-format

  # Python test dependencies
  python3-zmq
)

MISSING=()
for pkg in "${PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" &>/dev/null; then
    MISSING+=("$pkg")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends "${MISSING[@]}"
fi

########################################
# 3. Build bls-dash from source
#    (github.com is accessible via proxy)
########################################
BLS_PREFIX="/usr/local"
if [ ! -f "${BLS_PREFIX}/lib/libbls-dash.a" ]; then
  TMPDIR=$(mktemp -d)

  BLS_VERSION="1.1.0"
  RELIC_COMMIT="3a23142be0a5510a3aa93cd6c76fc59d3fc732a5"

  curl -sL "https://github.com/dashpay/bls-signatures/archive/${BLS_VERSION}.tar.gz" \
    -o "${TMPDIR}/bls.tar.gz"
  curl -sL "https://github.com/relic-toolkit/relic/archive/${RELIC_COMMIT}.tar.gz" \
    -o "${TMPDIR}/relic.tar.gz"

  mkdir -p "${TMPDIR}/bls-signatures"
  tar -xzf "${TMPDIR}/bls.tar.gz" -C "${TMPDIR}/bls-signatures" --strip-components=1

  # Apply Firo's patches first (before URL substitution)
  cd "${TMPDIR}/bls-signatures"
  if [ -f "${PROJECT_DIR}/depends/patches/bls-dash/bls-signatures.patch" ]; then
    patch -p1 < "${PROJECT_DIR}/depends/patches/bls-dash/bls-signatures.patch"
  fi

  # Point CMake at local relic tarball instead of git
  sed -i "s|GIT_REPOSITORY https://github.com/relic-toolkit/relic.git|URL \"${TMPDIR}/relic.tar.gz\"|" \
    src/CMakeLists.txt
  sed -i 's|GIT_TAG.*RELIC_GIT_TAG.*|URL_HASH SHA256=ddad83b1406985a1e4703bd03bdbab89453aa700c0c99567cf8de51c205e5dde|' \
    src/CMakeLists.txt

  # Build with Unix Makefiles (Ninja has globbing issues with the combined archive step)
  cmake -G "Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX="${BLS_PREFIX}" \
    -DCMAKE_PREFIX_PATH="${BLS_PREFIX}" \
    -DSTLIB=ON -DSHLIB=OFF -DSTBIN=ON \
    -DBUILD_BLS_PYTHON_BINDINGS=0 \
    -DBUILD_BLS_TESTS=0 \
    -DBUILD_BLS_BENCHMARKS=0 \
    -DOPSYS=LINUX -DCMAKE_SYSTEM_NAME=Linux \
    -DWSIZE=64 \
    "-DCMAKE_C_FLAGS=-DUBLSALLOC_SODIUM" \
    "-DCMAKE_CXX_FLAGS=-DUBLSALLOC_SODIUM" \
    -S"${TMPDIR}/bls-signatures" -B"${TMPDIR}/bls-build"

  make -C "${TMPDIR}/bls-build" -j"$(nproc)"
  sudo cmake --install "${TMPDIR}/bls-build"
  sudo ldconfig

  rm -rf "${TMPDIR}"
  cd "${PROJECT_DIR}"
fi

########################################
# 4. Build libbacktrace from source
#    (needed for ENABLE_CRASH_HOOKS)
########################################
if [ ! -f "${BLS_PREFIX}/lib/libbacktrace.a" ]; then
  TMPDIR=$(mktemp -d)

  curl -sL "https://github.com/ianlancetaylor/libbacktrace/archive/refs/heads/master.tar.gz" \
    -o "${TMPDIR}/libbacktrace.tar.gz"
  mkdir -p "${TMPDIR}/libbacktrace"
  tar -xzf "${TMPDIR}/libbacktrace.tar.gz" -C "${TMPDIR}/libbacktrace" --strip-components=1

  cd "${TMPDIR}/libbacktrace"
  ./configure --prefix="${BLS_PREFIX}" --enable-static --disable-shared CFLAGS="-fPIC"
  make -j"$(nproc)"
  sudo make install

  rm -rf "${TMPDIR}"
  cd "${PROJECT_DIR}"
fi

########################################
# 5. Configure CMake
#    Note: WITH_TOR=OFF because
#    archive.torproject.org is blocked
#    by the cloud egress proxy.
#    Tor integration is not needed for
#    development/testing workflows.
########################################
if [ ! -f "${BUILD_DIR}/build.ninja" ]; then
  cmake -G Ninja \
    -DBUILD_DAEMON=ON \
    -DBUILD_CLI=ON \
    -DBUILD_TX=ON \
    -DBUILD_GUI=OFF \
    -DBUILD_TESTS=ON \
    -DENABLE_WALLET=ON \
    -DWITH_BDB=ON \
    -DWITH_ZMQ=ON \
    -DENABLE_CRASH_HOOKS=ON \
    -DWITH_TOR=OFF \
    -DBoost_USE_STATIC_RUNTIME=OFF \
    -DWARN_INCOMPATIBLE_BDB=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -S"${PROJECT_DIR}" -B"${BUILD_DIR}"
fi

########################################
# 6. Build
########################################
if [ ! -f "${BUILD_DIR}/bin/firod" ]; then
  cmake --build "${BUILD_DIR}" -j"$(nproc)"
fi

########################################
# 7. Set environment variables
########################################
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export PATH=\"${BUILD_DIR}/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi
