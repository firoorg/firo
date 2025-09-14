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

# Main commands
xorrisofs -D -l -V Firo-Core -no-pad -r -dir-mode 0755 -o uncompressed.dmg dist
dmg dmg uncompressed.dmg firo-qt.dmg
[ -f uncompressed.dmg ] && rm -f uncompressed.dmg
