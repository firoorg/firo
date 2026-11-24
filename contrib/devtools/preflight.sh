#!/usr/bin/env bash
# Check that the current branch is ready for review: committed, based on the
# latest master, no whitespace errors or agent tags in added lines; then the
# CI Linux Debug build, the unit tests and the RPC tests named on the command line.
#
# Usage: contrib/devtools/preflight.sh [RPC test scripts ...] [-extended]
#   BASE=origin/<branch>  branch the PR targets (default origin/master)
#   BUILD_DIR=<dir>       build directory (default build); its CMake cache is reset
#   TOOLCHAIN=<file>      depends toolchain (default depends/<host>/toolchain.cmake)
#   JOBS=<n>              parallel build jobs (default: ninja's choice)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BASE=${BASE:-origin/master}
BUILD_DIR=${BUILD_DIR:-build}
TOOLCHAIN=${TOOLCHAIN:-$PWD/depends/$(depends/config.guess)/toolchain.cmake}
fail=0

if [ -n "$(git status --porcelain)" ]; then
    git status --short
    echo "FAIL: uncommitted changes (above); the checks cover commits only"
    fail=1
fi
git fetch --quiet origin "${BASE#origin/}"
MERGE_BASE=$(git merge-base "$BASE" HEAD)
if [ "$MERGE_BASE" != "$(git rev-parse "$BASE")" ]; then
    echo "FAIL: not based on the latest $BASE; rebase first"
    fail=1
fi
if ! git diff --check "$MERGE_BASE" HEAD; then
    echo "FAIL: whitespace errors in added lines (above)"
    fail=1
fi
# Coding agents tag shortcuts like this; the tags must not reach the tree.
if git diff "$MERGE_BASE" HEAD -- src qa | grep -n '^+.*ponytail:'; then
    echo "FAIL: agent tags in added lines (above)"
    fail=1
fi
# Advice only: master is not fully formatted and CI does not check formatting.
if git clang-format -h >/dev/null 2>&1; then
    git clang-format --diff "$MERGE_BASE" -- src || true
else
    echo "note: git clang-format not installed; formatting not checked"
fi
[ "$fail" -eq 0 ] || exit 1

echo "== build: the Linux Debug job of .github/workflows/ci-master.yml (keep the flags in sync)"
# Start from an empty cache as CI does: options cached by another configuration
# can drop tests from the build or leave an old firod for the RPC tests to run.
rm -f "$BUILD_DIR/CMakeCache.txt"
PKG_CONFIG_PATH="$(dirname "$TOOLCHAIN")/lib/pkgconfig:${PKG_CONFIG_PATH:-}" \
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DBUILD_CLI=ON -DBUILD_TESTS=ON -DENABLE_CRASH_HOOKS=ON -DBUILD_GUI=ON \
    -DCMAKE_BUILD_TYPE=Debug -DCLIENT_VERSION_IS_RELEASE=false -DBUILD_FUZZ_BINARY=ON \
    -S . -B "$BUILD_DIR"
ninja -C "$BUILD_DIR" ${JOBS:+-j "$JOBS"}

echo "== unit tests"
if ! ctest --test-dir "$BUILD_DIR" --output-on-failure; then
    echo "FAIL: unit tests (above)"
    fail=1
fi
if [ "$#" -gt 0 ]; then
    echo "== RPC tests: $*"
    cp -f "$BUILD_DIR"/bin/* "$BUILD_DIR"/src/
    # rpc-tests.py prefers an exported FIROD or FIROCLI to the binaries copied above.
    if ! env -u FIROD -u FIROCLI qa/pull-tester/rpc-tests.py "$@"; then
        echo "FAIL: RPC tests (above)"
        fail=1
    fi
fi
[ "$fail" -eq 0 ] || exit 1
echo "preflight: all checks passed"
