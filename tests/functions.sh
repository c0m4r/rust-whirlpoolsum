#!/bin/bash

BASEDIR=$(dirname "$0")
CMD="$BASEDIR/../target/debug/whirlpoolsum"

# Colors
GREEN='\e[1;32m'
RED='\e[1;31m'
ENDCOLOR="\e[0m"

pass() {
    echo -e "${GREEN}${1}${ENDCOLOR}"
}

fail() {
    echo -e "${RED}${1}${ENDCOLOR}"
}
