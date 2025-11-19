# rust-whirlpoolsum

![Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust&amp;logoColor=ffffff)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3 (Max+Coder) / Claude Sonnet 4.5 (Thinking+Extended) / Gemini 3 Pro (High)

Deps: [whirlpool](https://crates.io/crates/whirlpool) | [colored](https://crates.io/crates/colored)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.7.1/whirlpoolsum
echo "886d187755d68af6f83be9c1bfc5983ba1675e4f4ad273f5c29cbd8fc159ccce  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
sudo mv whirlpoolsum /usr/local/bin/
sudo chmod +x /usr/local/bin/whirlpoolsum
echo "ff2f8a19646b510ab85f5a585c0074213812de665c7ecf86c45b4afd218e294a3f069fedd4127941d6b40f2f620a8d31e35717dc776fa6fc5add1c87071bfd30  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
whirlpoolsum -V
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
whirlpoolsum --max-files 1000 --max-file-size 100M /usr/sbin/*
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

## Configuration options

```
--max-file-size <MAX_FILE_SIZE>  Maximum file size (e.g., 1G, 512M) [default: 10G]
--max-files <MAX_FILES>          Maximum number of files to process [default: 10000]
```

## License

Public Domain / CC0 1.0 Universal
