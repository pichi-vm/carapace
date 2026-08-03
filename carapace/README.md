# carapace

**Carapace is OverlayFS for block devices.** Where OverlayFS composes filesystem layers in userspace, carapace composes cryptographically-bound block device layers underneath the filesystem. Each layer is a pair of content-addressable files; the composed stack presents as a unified, integrity-protected, read-only block device validated by a single trust anchor.

This crate is the read-only consumer. The on-disk and chain composition format is specified normatively in [SPEC.md](SPEC.md); producer paths live elsewhere.

## Library API

```rust
use carapace::{Chain, FromGpt};

// Walk the PARTUUID chain and build the dm-verity + dm-snapshot stack.
let root: Vec<u8> = hex::decode(root_hex)?;
let chain = Chain::from_gpt(&root)?;   // feature `gpt`, default on
let removed = chain.assemble()?;       // returns the top device guard

// Mount the top device read-only.
let dev = format!("/dev/dm-{}", removed.id().minor());
// … run mount(8) on `dev` …

// Drop the guard after mounting — the mount anchors the dm stack.
// DM_DEFERRED_REMOVE is scheduled; `umount` cascades teardown.
drop(removed);
```

Errors are `std::io::Error`. Validation failures (bad algorithm, wrong block
size, broken salt chain) produce `ErrorKind::InvalidData`; operator misuse
(e.g. a trusted root that is too short) produces `ErrorKind::InvalidInput`.

## CLI

```sh
# Assemble a chain and mount it at <dir> (requires CAP_SYS_ADMIN).
carapace mount <root-hex> <dir> [--type <fs>]

# Teardown is a plain unmount — deferred-remove cascades the dm stack.
umount <dir>
```

`<root-hex>` is the trusted chain root, hex-encoded (≥ 64 hex chars for
sha256). `from_gpt` discovers partitions by walking `/sys/class/block/*/uevent`
for `PARTUUID=` entries — no GPT parser in userspace. For loop-mounted images,
run `losetup --partscan IMAGE` first; the kernel populates sysfs synchronously.

## Building

```sh
cargo build --release   # produces target/release/carapace
```

The toolchain is pinned via `rust-toolchain.toml`. All dependencies are
resolved via `Cargo.lock`; reproducible builds are a goal.

## Testing

```sh
cargo test --bins                                # unit tests (~1 s)
sudo cargo test --tests -- --test-threads=1     # integration (~45 s, root-required)
```

Integration tests build a real layered ext4 carapace via
`tests/fixtures/build_carapace.sh` (a shell + python pipeline using `sgdisk` +
`veritysetup` + `dmsetup`), then assemble, mount, and verify per-scute file
content.

## Runtime requirements

- Linux kernel ≥ 5.8 (`LOOP_CONFIGURE`, dm-verity, dm-snapshot)
- `devtmpfs` (universal on modern distros)
- For test/dev: `cryptsetup-bin`, `gdisk`, `dmsetup`, `e2fsprogs`, `python3`

`udev` is NOT required at runtime — partition discovery is sysfs-driven.

## License

Apache-2.0. See [LICENSE](../LICENSE).
