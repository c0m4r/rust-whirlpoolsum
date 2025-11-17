#!/bin/bash

set -e

BASEDIR=$(dirname "$0")
CMD="$BASEDIR/../target/debug/whirlpoolsum"

# Colors
ORANGE='\e[1;33m'
GREEN='\e[1;32m'
RED='\e[1;31m'
ENDCOLOR="\e[0m"

pass() {
    echo -e "${GREEN}${1}${ENDCOLOR}"
}

fail() {
    echo -e "${RED}${1}${ENDCOLOR}"
}

TMPFILE=$(mktemp)
TMPWRLFILE=$(mktemp)

trap 'rm -f "$TMPFILE" "$TMPWRLFILE"' EXIT

cleanup() {
    rm -f "$TMPFILE" "$TMPWRLFILE"
}

echo -e "${ENDCOLOR}Running: $0$"
