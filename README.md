# rust-whirlpoolsum

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3-Max (Thinking @ 81,920 tokens) / Qwen3-Coder / Claude Sonnet 4.5 (Extended Thinking)

Deps: [whirlpool](https://crates.io/crates/whirlpool) | [colored](https://crates.io/crates/colored)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.6.0/whirlpoolsum
echo "9dcc2e84f766440dbc36d1941aa1ef975604f309cb3f41370d67ed705437ca71  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
sudo mv whirlpoolsum /usr/local/bin/
sudo chmod +x /usr/local/bin/whirlpoolsum
echo "339d39a0a713c56b65f081f118e5d100223c7afaada93a546e20f04c2f155ed3e13bb9c9cf3d592dba00fc8af49e3dfacc1c5b0f2b114a4873980a0cfe612f02  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
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
