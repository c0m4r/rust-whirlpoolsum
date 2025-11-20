#!/bin/bash

set -e

BASEDIR=$(dirname "$0")

source "${BASEDIR}/tests/functions.sh"

if ! command -v unshare &>/dev/null 2>&1 ; then
    echo "FAILED: you have to install unshare for network sandboxing"
    exit 1
fi

if [ -d tests ]; then
    find ${BASEDIR}/tests/ -maxdepth 1 -name 'test*.sh' -type f | while read -r test ; do
        unshare --net --map-root-user bash "$test" || fail FAILED
    done
else
    echo "FAILED: tests not found"
    exit 1
fi
