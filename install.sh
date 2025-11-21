#!/bin/bash

SUDO=""

if [ $(whoami) != "root" ]; then
    if command -v sudo >/dev/null 2>&1 ; then
        SUDO="sudo"
    elif command -v doas >/dev/null 2>&1 ; then
        SUDO="doas"
    else
        echo "no sudo/doas found, make sure you run that script as root"
    fi
fi

echo "Installing to /usr/local/bin/whirlpoolsum"
$SUDO cp -v target/release/whirlpoolsum /usr/local/bin/ || $SUDO cp -v dist/whirlpoolsum /usr/local/bin/
$SUDO ln -sfv whirlpoolsum /usr/local/bin/wrl512sum
