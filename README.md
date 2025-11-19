# rust-whirlpoolsum

![Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust&amp;logoColor=ffffff)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3 (Max+Coder) / Claude Sonnet 4.5 (Thinking+Extended) / Gemini 3 Pro (High)

Deps: [whirlpool](https://crates.io/crates/whirlpool) | [colored](https://crates.io/crates/colored)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.6.0/whirlpoolsum
echo "27ea4072255ac9d9243d127d3f7daa3076c85b456cf366366ddbed60dfeb37a3  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
sudo mv whirlpoolsum /usr/local/bin/
sudo chmod +x /usr/local/bin/whirlpoolsum
echo "83673d9086cadde52990f132be0de1ef27845a67ec4e0ebb5f6c596a524f3d08aecb7f5878970fca836014069d1a93649de58afd45c1c2fb23cd1e711cb05362  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
whirlpoolsum --help
```

On Alpine install [gcompat](https://git.adelielinux.org/adelie/gcompat) with `apk add gcompat`

## Usage

Text checksum (stdin)

```bash
echo -n "All your base are belong to us" | whirlpoolsum
```

File checksum

```bash
whirlpoolsum example.txt
```

Multiple files checksums (with multithreading)

```bash
whirlpoolsum --max-files 1000 /usr/sbin/*
```

Verify file checksum (stdin)

```bash
echo -n "abcdef12345(...)  example.txt" | whirlpoolsum -c
```

Verify file checksum with a checksum file

```bash
whirlpoolsum -c example.txt.wrl
```

Print program version

```bash
whirlpoolsum --version
```

## Benchmarking

Benchmark (measure time and throughput for a given filename(s))

```bash
whirlpoolsum --benchmark example.txt
```

Benchmark (system test with score)

```bash
whirlpoolsum --benchmark
```

## License

Public Domain / CC0 1.0 Universal
