#!/bin/bash

set -e

BASEDIR=$(dirname "$0")
source "${BASEDIR}"/functions.sh

echo "You may say I'm a dreamer But I'm not the only one" > "$TMPFILE"

CHECKSUM=$("$CMD" "$TMPFILE")

if [ "$CHECKSUM" == "1ae8fde50fcf4a117f0207164be4f95ffc004fec335e557f7492e3844d520b5b136aa9eacf4fa1cd6559196eb1182d98db04f92727bb1489ed0d0e49452b5149  $TMPFILE" ] ; then
    "$CMD" --json "$TMPFILE" 2>&1 | jq -e .hash_results > /dev/null
    if [ $? -eq 0 ]; then
        pass PASS ; cleanup ; exit 0
    else
        fail FAILED ; cleanup ; exit 1
    fi
else
    fail "FAILED: wrong checksum" ; cleanup ; exit 1
fi
