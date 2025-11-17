#!/bin/sh

echo "Installing to /usr/local/bin/whirlpoolsum"
cp -v target/release/whirlpoolsum /usr/local/bin/
ln -s whirlpoolsum /usr/local/bin/wrl512sum
