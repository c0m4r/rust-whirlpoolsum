#!/bin/bash

set -e

BASEDIR=$(dirname "$0")
source "${BASEDIR}"/functions.sh

B=$("$CMD" --benchmark)
LINES=$(echo "$B" | wc -l)
LINES_EXP=23 # expected lines count
HASH=$(echo "$B" | grep ^Hash | awk '{print $2}')

if [ $LINES -ne $LINES_EXP ]; then
    fail "FAILED: expected $LINES_EXP lines, got $LINES" ; cleanup ; exit 1
elif [ "$HASH" != "137d9a9a30e812ceae66d3bde5df1896b10406b4c62622450c9bc99556e7e91b5f11b66d70695ec3f3c45295c95487a86bc03da9cf3d302eb7c84def9fa6f2fb" ]; then
    fail "FAILED: wrong hash" ; cleanup ; exit 1
else
    pass PASS ; cleanup ; exit 0
fi
