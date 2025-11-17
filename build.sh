#!/bin/sh

RUSTFLAGS="-C target-cpu=native -C link-arg=-Wl,-z,relro,-z,now" cargo build --release
