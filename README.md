# rust-whirlpoolsum

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3-Max (Thinking @ 81,920 tokens)

## Deps (crates)

* [whirlpool](https://crates.io/crates/whirlpool)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.4.0/whirlpoolsum
echo "60e0e56a40dbe209f1d0362cd1398c1dcf85507dd1f44743610c34da2597e681  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
mv whirlpoolsum /usr/local/bin/
chmod +x /usr/local/bin/whirlpoolsum
echo "fedf4b3ac86b21c2a268e25ce658ac8e0406d19010986bdbf124c1ee70b20c360b9b9decdadc06f39fa35cea86c249508498c8bda9727ac4aa7f5274c14b040c  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
whirlpoolsum --help
```

On Alpine install [gcompat](https://git.adelielinux.org/adelie/gcompat) with `apk add gcompat`

## Usage

### text checksum

`echo -n "All your base are belong to us" | whirlpoolsum`

### file checksum

`whirlpoolsum example.txt`

### verify file checksum (stdin)

`echo -n "abcdef12345(...)  example.txt" | whirlpoolsum -c`

## verify file checksum (checksum file)

`whirlpoolsum -c example.txt.wrl`

## License

Public Domain / CC0 1.0 Universal
