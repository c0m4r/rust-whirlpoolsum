#!/bin/bash

set -e

if [ -d tests ]; then
    find tests/ -maxdepth 1 -name 'test*.sh' -type f -exec bash {} \;
else
    echo "FAILED: tests not found"
    exit 1
fi
