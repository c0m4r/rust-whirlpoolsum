#!/bin/bash

BASEDIR=$(dirname "$0")

cross clean

targets=(
    aarch64-unknown-linux-gnu
    riscv64gc-unknown-linux-gnu
    x86_64-pc-windows-gnu
)

for target in "${targets[@]}"; do

    cross build --target "$target" --release

    case "$target" in
        "aarch64-unknown-linux-gnu") name="whirlpoolsum-aarch64-glibc" ;;
        "riscv64gc-unknown-linux-gnu") name="whirlpoolsum-riscv64-glibc" ;;
        "x86_64-pc-windows-gnu") name="whirlpoolsum.exe" ;;
        *) name="whirlpoolsum-${target}"
    esac

    mkdir -p "$BASEDIR"/dist
    binary="./target/${target}/release/whirlpoolsum"
    if [ "$(echo "${target}" | grep windows)" ]; then binary="./target/${target}/release/whirlpoolsum.exe" ; fi
    cp -v "$binary" "${BASEDIR}/dist/${name}"
    sha256sum "$BASEDIR"/dist/"$name" > "$BASEDIR"/dist/"$name".sha256
    whirlpoolsum "$BASEDIR"/dist/"$name" > "$BASEDIR"/dist/"$name".wrl

done
