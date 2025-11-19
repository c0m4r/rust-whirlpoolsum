#!/bin/bash

BASEDIR=$(dirname "$0")

cargo fmt
cargo update
cargo audit
export RUSTFLAGS="-C target-cpu=native -C link-arg=-Wl,-z,relro,-z,now"
cargo clippy
cargo build
cargo build --release
./test.sh
cargo test
./target/release/whirlpoolsum --benchmark
mkdir -p "$BASEDIR"/dist
cp ./target/release/whirlpoolsum "$BASEDIR"/dist/
sha256sum "$BASEDIR"/dist/whirlpoolsum > "$BASEDIR"/dist/whirlpoolsum.sha256
whirlpoolsum "$BASEDIR"/dist/whirlpoolsum > "$BASEDIR"/dist/whirlpoolsum.wrl
