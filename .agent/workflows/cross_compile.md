---
description: Cross-compile the project for AArch64 and Windows using `cross`
---

1. Install `cross` if you haven't already:
   ```bash
   cargo install cross --git https://github.com/cross-rs/cross
   ```

2. Build for AArch64 (Linux):
   ```bash
   cross build --target aarch64-unknown-linux-gnu --release
   ```

3. Build for Windows (x86_64):
   ```bash
   cross build --target x86_64-pc-windows-gnu --release
   ```

4. The binaries will be available in `target/aarch64-unknown-linux-gnu/release/` and `target/x86_64-pc-windows-gnu/release/` respectively.


---

```bash
rustc --print=target-list
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-gnu
cross build --target aarch64-unknown-linux-gnu --release
```

In case of errors:

```bash
cross clean || rm -rf target
```

