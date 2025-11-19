#!/bin/sh

cargo fmt
cargo update
cargo audit
export RUSTFLAGS="-C target-cpu=native -C link-arg=-Wl,-z,relro,-z,now"
cargo clippy
cargo build
cargo build --release
./test.sh
