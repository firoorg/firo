#!/bin/sh
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -e

UNSIGNED="$1"
SIGNED="$2"
APPLE_API_KEY="$3"
APPLE_ISSUER_ID="$4"
ROOTDIR=dist
OUTDIR=signed-app
SIGNAPPLE=signapple

if [ -z "$UNSIGNED" ] || [ -z "$SIGNED" ]; then
  echo "usage: $0 <unsigned app> <signed app> [apple_api_key] [apple_issuer_id]"
  exit 1
fi

${SIGNAPPLE} apply ${UNSIGNED} ${SIGNED}

# Notarize if Apple API key and Issuer ID are provided
if [ -n "$APPLE_API_KEY" ] && [ -n "$APPLE_ISSUER_ID" ]; then
  stty -echo
  printf "Enter the passphrase for %s: " ${APPLE_API_KEY}
  read api_key_pass
  printf "\n"
  stty echo
  ${SIGNAPPLE} notarize --passphrase "$api_key_pass" ${APPLE_API_KEY} ${APPLE_ISSUER_ID} ${UNSIGNED}
  echo "Notarization requested."
fi

mv ${ROOTDIR} ${OUTDIR}
echo "Signed: ${OUTDIR}"
