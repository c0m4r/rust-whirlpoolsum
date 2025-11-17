# rust-whirlpoolsum

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3-Max (Thinking @ 81,920 tokens) / Qwen3-Coder

## Deps (crates)

* [whirlpool](https://crates.io/crates/whirlpool)
* [colored](https://crates.io/crates/colored)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.5.0/whirlpoolsum
echo "6f35abaf094c54348fa46a83be701be32c8a4046863eca784323410ca834cbe9  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
sudo mv whirlpoolsum /usr/local/bin/
sudo chmod +x /usr/local/bin/whirlpoolsum
echo "fed9865dfa9dbf5dcd300a8716817c873b4b200a0b08c60144a4aa38c68118a5027c0de53c406ccfb83c04d83fc14dd706029fe1713bdb9d5d10eaaaedb93d71  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
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

Verify file checksum (stdin)

```bash
echo -n "abcdef12345(...)  example.txt" | whirlpoolsum -c
```

Verify file checksum with a checksum file

```bash
whirlpoolsum -c example.txt.wrl
```

## License

Public Domain / CC0 1.0 Universal
