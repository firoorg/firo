#!/bin/bash
set -euo pipefail

# Only run in remote (Cloud) environments
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-/home/user/firo}"
BUILD_DIR="${CLAUDE_BUILD_DIR:-${PROJECT_DIR}/build}"
BLS_PREFIX="${CLAUDE_PREFIX_DIR:-/usr/local}"
HOOK_STATE_DIR="${CLAUDE_HOOK_STATE_DIR:-${BLS_PREFIX}/share/firo-cloud-session-start}"
BUILD_STAMP_FILE="${BUILD_DIR}/.build_stamp"
BLS_STAMP_FILE="${HOOK_STATE_DIR}/bls-dash.stamp"
LIBBACKTRACE_STAMP_FILE="${HOOK_STATE_DIR}/libbacktrace.stamp"
LIBTOR_STAMP_FILE="${HOOK_STATE_DIR}/libtor.stamp"
PATH_EXPORT_LINE="export PATH=\"${BUILD_DIR}/bin:\$PATH\""

REQUIRED_BUILD_BINS=(
  firod
  firo-cli
  firo-tx
  test_firo
)

BLS_VERSION="1.1.0"
BLS_SHA256="276c8573104e5f18bb5b9fd3ffd49585dda5ba5f6de2de74759dda8ca5a9deac"
RELIC_COMMIT="3a23142be0a5510a3aa93cd6c76fc59d3fc732a5"
RELIC_SHA256="ddad83b1406985a1e4703bd03bdbab89453aa700c0c99567cf8de51c205e5dde"

# Pin to the same commit and hash used by depends/packages/backtrace.mk
LIBBACKTRACE_COMMIT="b9e40069c0b47a722286b94eb5231f7f05c08713"
LIBBACKTRACE_SHA256="81b37e762965c676b3316e90564c89f6480606add446651c785862571a1fdbca"
LIBTOR_STUB_VERSION="1"

ensure_path_export()
{
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    if ! grep -qF "${PATH_EXPORT_LINE}" "$CLAUDE_ENV_FILE" 2>/dev/null; then
      echo "${PATH_EXPORT_LINE}" >> "$CLAUDE_ENV_FILE"
    fi
  fi
}

stamp_matches()
{
  local stamp_path="$1"
  local expected="$2"
  local current

  [ -f "${stamp_path}" ] || return 1
  current=$(<"${stamp_path}")
  [ "${current}" = "${expected}" ]
}

write_stamp()
{
  local stamp_path="$1"
  local content="$2"
  local stamp_dir tmp_file

  stamp_dir="$(dirname "${stamp_path}")"
  tmp_file="$(mktemp)"
  printf '%s\n' "${content}" > "${tmp_file}"

  if mkdir -p "${stamp_dir}" 2>/dev/null && install -m 644 "${tmp_file}" "${stamp_path}" 2>/dev/null; then
    rm -f "${tmp_file}"
    return 0
  fi

  sudo install -d "${stamp_dir}"
  sudo install -m 644 "${tmp_file}" "${stamp_path}"
  rm -f "${tmp_file}"
}

build_outputs_present()
{
  local bin_name

  for bin_name in "${REQUIRED_BUILD_BINS[@]}"; do
    [ -f "${BUILD_DIR}/bin/${bin_name}" ] || return 1
  done
}

build_stamp_content()
{
  local git_head git_status_hash

  git_head="$(git -C "${PROJECT_DIR}" rev-parse HEAD)"
  git_status_hash="$(git -C "${PROJECT_DIR}" status --porcelain --untracked-files=no | sha256sum | cut -d' ' -f1)"

  cat <<EOF
schema=1
git_head=${git_head}
git_status_hash=${git_status_hash}
build_daemon=ON
build_cli=ON
build_tx=ON
build_gui=OFF
build_tests=ON
enable_wallet=ON
with_bdb=ON
with_zmq=ON
enable_crash_hooks=ON
warn_incompatible_bdb=OFF
cmake_build_type=Release
boost_use_static_runtime=OFF
required_bins=${REQUIRED_BUILD_BINS[*]}
EOF
}

bls_stamp_content()
{
  cat <<EOF
schema=1
bls_version=${BLS_VERSION}
bls_sha256=${BLS_SHA256}
relic_commit=${RELIC_COMMIT}
relic_sha256=${RELIC_SHA256}
EOF
}

libbacktrace_stamp_content()
{
  cat <<EOF
schema=1
libbacktrace_commit=${LIBBACKTRACE_COMMIT}
libbacktrace_sha256=${LIBBACKTRACE_SHA256}
EOF
}

libtor_stamp_content()
{
  cat <<EOF
schema=1
libtor_stub_version=${LIBTOR_STUB_VERSION}
EOF
}

ensure_boost_runtime_override()
{
  local boost_cmake

  boost_cmake="${PROJECT_DIR}/cmake/module/AddBoostIfNeeded.cmake"
  if grep -q 'set(Boost_USE_STATIC_RUNTIME ON)' "${boost_cmake}"; then
    sed -i 's/set(Boost_USE_STATIC_RUNTIME ON)/set(Boost_USE_STATIC_RUNTIME OFF)/' "${boost_cmake}"
    # Hide this local-only workaround from git so it doesn't show up in diffs.
    # A cleaner alternative would be to pass -DBoost_USE_STATIC_RUNTIME=OFF via
    # CMake cache variables, but the upstream CMakeLists.txt unconditionally
    # overrides it with set(), so patching the file is the only option for now.
    git -C "${PROJECT_DIR}" update-index --assume-unchanged "${boost_cmake}"
  fi
}

BLS_STAMP_CONTENT="$(bls_stamp_content)"
LIBBACKTRACE_STAMP_CONTENT="$(libbacktrace_stamp_content)"
LIBTOR_STAMP_CONTENT="$(libtor_stamp_content)"
BUILD_STAMP_CONTENT="$(build_stamp_content)"

# Skip only when dependencies and build outputs match the current workspace state.
if [ -f "${BLS_PREFIX}/lib/libbls-dash.a" ] \
  && stamp_matches "${BLS_STAMP_FILE}" "${BLS_STAMP_CONTENT}" \
  && [ -f "${BLS_PREFIX}/lib/libbacktrace.a" ] \
  && stamp_matches "${LIBBACKTRACE_STAMP_FILE}" "${LIBBACKTRACE_STAMP_CONTENT}" \
  && [ -f "${BLS_PREFIX}/lib/libtor.a" ] \
  && stamp_matches "${LIBTOR_STAMP_FILE}" "${LIBTOR_STAMP_CONTENT}" \
  && [ -f "${BUILD_DIR}/build.ninja" ] \
  && build_outputs_present \
  && stamp_matches "${BUILD_STAMP_FILE}" "${BUILD_STAMP_CONTENT}"; then
  ensure_path_export
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
if [ ! -f "${BLS_PREFIX}/lib/libbls-dash.a" ] \
  || ! stamp_matches "${BLS_STAMP_FILE}" "${BLS_STAMP_CONTENT}"; then
  WORK_DIR=$(mktemp -d)

  curl -sL "https://github.com/dashpay/bls-signatures/archive/${BLS_VERSION}.tar.gz" \
    -o "${WORK_DIR}/bls.tar.gz"
  curl -sL "https://github.com/relic-toolkit/relic/archive/${RELIC_COMMIT}.tar.gz" \
    -o "${WORK_DIR}/relic.tar.gz"

  # Verify downloaded tarballs against known hashes
  echo "${BLS_SHA256}  ${WORK_DIR}/bls.tar.gz" | sha256sum -c - || \
    { echo "ERROR: bls-signatures tarball SHA256 mismatch"; rm -rf "${WORK_DIR}"; exit 1; }
  echo "${RELIC_SHA256}  ${WORK_DIR}/relic.tar.gz" | sha256sum -c - || \
    { echo "ERROR: relic tarball SHA256 mismatch"; rm -rf "${WORK_DIR}"; exit 1; }

  mkdir -p "${WORK_DIR}/bls-signatures"
  tar -xzf "${WORK_DIR}/bls.tar.gz" -C "${WORK_DIR}/bls-signatures" --strip-components=1

  # Apply Firo's patches first (before URL substitution)
  cd "${WORK_DIR}/bls-signatures"
  if [ -f "${PROJECT_DIR}/depends/patches/bls-dash/bls-signatures.patch" ]; then
    patch -p1 < "${PROJECT_DIR}/depends/patches/bls-dash/bls-signatures.patch"
  fi

  # Point CMake at local relic tarball instead of git
  sed -i "s|GIT_REPOSITORY https://github.com/relic-toolkit/relic.git|URL \"${WORK_DIR}/relic.tar.gz\"|" \
    src/CMakeLists.txt
  sed -i "s|GIT_TAG.*RELIC_GIT_TAG.*|URL_HASH SHA256=${RELIC_SHA256}|" \
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
    "-DCMAKE_C_FLAGS=-UBLSALLOC_SODIUM" \
    "-DCMAKE_CXX_FLAGS=-UBLSALLOC_SODIUM" \
    -S"${WORK_DIR}/bls-signatures" -B"${WORK_DIR}/bls-build"

  make -C "${WORK_DIR}/bls-build" -j"$(nproc)"
  sudo cmake --install "${WORK_DIR}/bls-build"
  sudo ldconfig
  write_stamp "${BLS_STAMP_FILE}" "${BLS_STAMP_CONTENT}"

  rm -rf "${WORK_DIR}"
  cd "${PROJECT_DIR}"
fi

########################################
# 4. Build libbacktrace from source
#    (needed for ENABLE_CRASH_HOOKS)
########################################
if [ ! -f "${BLS_PREFIX}/lib/libbacktrace.a" ] \
  || ! stamp_matches "${LIBBACKTRACE_STAMP_FILE}" "${LIBBACKTRACE_STAMP_CONTENT}"; then
  WORK_DIR=$(mktemp -d)
  curl -sL "https://github.com/ianlancetaylor/libbacktrace/archive/${LIBBACKTRACE_COMMIT}.tar.gz" \
    -o "${WORK_DIR}/libbacktrace.tar.gz"
  echo "${LIBBACKTRACE_SHA256}  ${WORK_DIR}/libbacktrace.tar.gz" | sha256sum -c - || \
    { echo "ERROR: libbacktrace tarball SHA256 mismatch"; rm -rf "${WORK_DIR}"; exit 1; }
  mkdir -p "${WORK_DIR}/libbacktrace"
  tar -xzf "${WORK_DIR}/libbacktrace.tar.gz" -C "${WORK_DIR}/libbacktrace" --strip-components=1

  cd "${WORK_DIR}/libbacktrace"
  ./configure --prefix="${BLS_PREFIX}" --enable-static --disable-shared CFLAGS="-fPIC"
  make -j"$(nproc)"
  sudo make install
  write_stamp "${LIBBACKTRACE_STAMP_FILE}" "${LIBBACKTRACE_STAMP_CONTENT}"

  rm -rf "${WORK_DIR}"
  cd "${PROJECT_DIR}"
fi

########################################
# 5. Create stub libtor.a
#    archive.torproject.org is blocked
#    by the cloud egress proxy, so we
#    create a stub with the symbols
#    referenced by src/init.cpp.
#    The embedded Tor is not needed for
#    development/testing workflows.
########################################
if [ ! -f "${BLS_PREFIX}/lib/libtor.a" ] \
  || ! stamp_matches "${LIBTOR_STAMP_FILE}" "${LIBTOR_STAMP_CONTENT}"; then
  WORK_DIR=$(mktemp -d)

  cat > "${WORK_DIR}/tor_stub.c" << 'STUBEOF'
#include <stdio.h>
int tor_main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    fprintf(stderr, "tor: stub library - embedded Tor not available in this build\n");
    return 1;
}
void tor_cleanup(void) {}
STUBEOF

  gcc -c -fPIC "${WORK_DIR}/tor_stub.c" -o "${WORK_DIR}/tor_stub.o"
  ar rcs "${WORK_DIR}/libtor.a" "${WORK_DIR}/tor_stub.o"
  sudo install -m 644 "${WORK_DIR}/libtor.a" "${BLS_PREFIX}/lib/libtor.a"
  write_stamp "${LIBTOR_STAMP_FILE}" "${LIBTOR_STAMP_CONTENT}"

  rm -rf "${WORK_DIR}"
fi

########################################
# 6. Configure CMake
#    The upstream AddBoostIfNeeded.cmake
#    hardcodes Boost_USE_STATIC_RUNTIME=ON.
#    Cloud uses system shared Boost, so we
#    patch the local copy and hide the
#    change from git with assume-unchanged.
########################################
if [ ! -f "${BUILD_DIR}/build.ninja" ] \
  || ! stamp_matches "${BUILD_STAMP_FILE}" "${BUILD_STAMP_CONTENT}"; then
  ensure_boost_runtime_override
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
    -DWARN_INCOMPATIBLE_BDB=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -S"${PROJECT_DIR}" -B"${BUILD_DIR}"
fi

########################################
# 7. Build
########################################
if ! build_outputs_present \
  || ! stamp_matches "${BUILD_STAMP_FILE}" "${BUILD_STAMP_CONTENT}"; then
  cmake --build "${BUILD_DIR}" -j"$(nproc)"
fi

if build_outputs_present; then
  write_stamp "${BUILD_STAMP_FILE}" "${BUILD_STAMP_CONTENT}"
fi

########################################
# 8. Set environment variables
########################################
ensure_path_export
