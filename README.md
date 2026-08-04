# carapace

A cryptographically composed, read-only block-device layering mechanism.

A **scute** is one layer (a dm-snapshot COW + a dm-verity tree); a **carapace**
is a salt-chain-bound stack of scutes presented as a single integrity-protected
read-only block device, validated by one trust anchor (the top scute's verity
root). See [`carapace/SPEC.md`](carapace/SPEC.md).

## Crates

- **`carapace`** — the read library (`Chain`/`Layer`/`FromGpt`/`assemble`) +
  the `carapace` CLI (`mount` verb).
- **`devmap`** — the device-mapper ioctl layer (chain-agnostic).
- **`lodown`** — safe loop-device wrapper for file-backed layers.

## Library API

```rust
use carapace::{Chain, FromGpt};

// Discover and assemble the dm-verity + dm-snapshot stack from a trusted root.
let root: Vec<u8> = hex::decode(root_hex)?;
let chain = Chain::from_gpt(&root)?;   // PARTUUID walk (feature `gpt`, default on)
let removed = chain.assemble()?;       // builds dm stack, returns top device guard

// Mount the top device read-only.
let dev = format!("/dev/dm-{}", removed.id().minor());
// … run mount(8) on `dev` …

// Drop the guard after mounting — the mount anchors the stack.
// DM_DEFERRED_REMOVE is scheduled; `umount` cascades teardown.
drop(removed);
```

`Chain` can also be constructed directly when the layer paths are already known:

```rust
use carapace::{Chain, Layer};
use std::path::PathBuf;

let chain = Chain {
    root: root_bytes.into_boxed_slice(),
    layers: vec![
        Layer { data: PathBuf::from("/dev/sda1"), hash: PathBuf::from("/dev/sda2") },
        // … base → top …
    ],
};
let removed = chain.assemble()?;
```

Errors are `std::io::Error`. Validation failures (bad algorithm, wrong block
size, broken salt chain) use `ErrorKind::InvalidData`; operator misuse (e.g.
a trusted root that is too short) uses `ErrorKind::InvalidInput`.

## CLI

```
# Assemble a carapace chain and mount it at <dir>.
carapace mount <root-hex> <dir> [--type <fs>]

# Teardown is a plain unmount — deferred-remove cascades the dm stack.
umount <dir>
```

`<root-hex>` is the trusted chain root, hex-encoded (≥ 64 hex chars for
sha256). The CLI discovers partitions from `/sys/class/block/*/uevent`
(PARTUUID lookup); the image must already be loop-attached with `--partscan`
so the kernel exposes the partitions.

## License

Apache-2.0 — see [LICENSE](LICENSE). Source files carry an
`SPDX-License-Identifier` header (checked in CI by
[hawkeye](https://github.com/korandoru/hawkeye)).
