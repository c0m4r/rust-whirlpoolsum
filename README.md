# rust-whirlpoolsum

Rust version of the whirlpoolsum that prints and checks WHIRLPOOL 512-bit checksums.

Vibe-coded with Qwen3-Max (Thinking @ 81,920 tokens)

## Deps (crates)

* [whirlpool](https://crates.io/crates/whirlpool)

## Quick install (x86_64/glibc)

```bash
wget https://github.com/c0m4r/rust-whirlpoolsum/releases/download/0.4.1/whirlpoolsum
echo "3b3c0c7a219313912e03fa55562b3131ab055971128d1209d7b489d1da01de2f  whirlpoolsum" | sha256sum -c || rm -f whirlpoolsum
mv whirlpoolsum /usr/local/bin/
chmod +x /usr/local/bin/whirlpoolsum
echo "716283fde066d99766cd8faa6a0821c523e0b04dfaa92327c58303a9f7d22f1020b8ea38b87741a61b698cd57376628209732fbe473ec4733845135682254f0f  /usr/local/bin/whirlpoolsum" | whirlpoolsum -c
whirlpoolsum --help
```

On Alpine install [gcompat](https://git.adelielinux.org/adelie/gcompat) with `apk add gcompat`

## Usage

Text checksum (stdin)

`echo -n "All your base are belong to us" | whirlpoolsum`

File checksum

`whirlpoolsum example.txt`

Verify file checksum (stdin)

`echo -n "abcdef12345(...)  example.txt" | whirlpoolsum -c`

Verify file checksum with a checksum file

`whirlpoolsum -c example.txt.wrl`

## License

Public Domain / CC0 1.0 Universal
