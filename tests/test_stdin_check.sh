#!/bin/bash

set -e

BASEDIR=$(dirname "$0")
source "${BASEDIR}"/functions.sh

trap 'rm -f "$TMPFILE"' EXIT

TMPFILE=$(mktemp)

echo "You may say I'm a dreamer But I'm not the only one" > "$TMPFILE"

CHECKSUM=$(whirlpoolsum "$TMPFILE")

if [ "$CHECKSUM" == "1ae8fde50fcf4a117f0207164be4f95ffc004fec335e557f7492e3844d520b5b136aa9eacf4fa1cd6559196eb1182d98db04f92727bb1489ed0d0e49452b5149  $TMPFILE" ] ; then
    echo "$CHECKSUM" | whirlpoolsum -c && pass PASS || fail FAILED
else
    fail "FAILED: wrong checksum"
    exit 1
fi
