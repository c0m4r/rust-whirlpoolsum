#!/bin/bash

set -e

BASEDIR=$(dirname "$0")
source "${BASEDIR}"/functions.sh

CHECKSUM=$(echo -n "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion, too" | "$CMD")
if [ "$CHECKSUM" == "eb18ac766158e72f1b7eb89e329f454497056b891f8606a50ce4d7fbff95a97a08f4d6cc75ba3b58fd3d58945509ed3be3042fbe0d8629200cd7145eff62439c  -" ] ; then
    pass "PASS"
else
    fail "FAILED: wrong checksum"
    exit 1
fi
