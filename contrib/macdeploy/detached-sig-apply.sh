#!/bin/sh
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -e

UNSIGNED="$1"
SIGNED="$2"
ROOTDIR=dist
OUTDIR=signed-app
SIGNAPPLE=signapple

if [ -z "$UNSIGNED" ]; then
  echo "usage: $0 <unsigned app> <signed app>"
  exit 1
fi

if [ -z "$SIGNED" ]; then
  echo "usage: $0 <unsigned app> <signed app>"
  exit 1
fi

${SIGNAPPLE} apply ${UNSIGNED} ${SIGNED}
mv ${ROOTDIR} ${OUTDIR}
echo "Signed: ${OUTDIR}"
