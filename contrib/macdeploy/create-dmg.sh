#!/bin/sh
# Copyright (c) 2014-2025 The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
set -e

# Check for required commands
command -v xorrisofs >/dev/null 2>&1 || { echo >&2 "xorrisofs not found."; exit 1; }
command -v dmg >/dev/null 2>&1 || { echo >&2 "dmg not found."; exit 1; }

# Check for dist directory
[ -d dist ] || { echo "dist directory not found!"; exit 1; }

# Check for firo-qt binary
[ -f dist/Firo-Qt.app/Contents/MacOS/Firo-Qt ] || { echo "firo-qt binary not found in \"dist/Firo-Qt.app/Contents/MacOS/\" directory!"; exit 1; }

current_dir=$(basename "$PWD")
case "$current_dir" in
    *arm64*|*aarch64*)
        output_dmg=firo-qt-arm64.dmg
        ;;
    *x86_64*)
        output_dmg=firo-qt-x86_64.dmg
        ;;
    *)
        output_dmg=firo-qt.dmg
        ;;
esac

# Main commands
xorrisofs -D -l -V Firo-Core -no-pad -r -dir-mode 0755 -o uncompressed.dmg dist
dmg dmg uncompressed.dmg "$output_dmg"
[ -f uncompressed.dmg ] && rm -f uncompressed.dmg
