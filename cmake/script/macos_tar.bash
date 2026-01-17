#!/usr/bin/env bash
set -exo pipefail
export LC_ALL=C

if [[ -n "$SOURCE_DATE_EPOCH" ]]; then
  find . -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
fi

# Create deterministic tar.gz preserving symlinks
# $1 = tar command path
# $2 = output filename
find . | sort | "$1" --create --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH:-0}" --files-from=- | gzip -9n > "$2"
