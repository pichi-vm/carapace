# carapace

A cryptographically composed, read-only block-device layering mechanism.

A **scute** is one layer (a dm-snapshot COW + a dm-verity tree); a **carapace**
is a salt-chain-bound stack of scutes presented as a single integrity-protected
read-only block device, validated by one trust anchor: the top scute's verity
root. See the [format specification](carapace/SPEC.md).

The workspace contains the `carapace` library and CLI. It uses the external
`devmap-linux`, `devmap-verity`, and optional `lodown` crates.

## Library API

```rust,no_run
use carapace::{Assemble, Chain, DevId, FromGpt};

fn attach(root: &[u8]) -> std::io::Result<std::fs::File> {
    let chain = Chain::from_gpt(root)?;
    let device = chain.assemble()?;
    let id = DevId::try_from(device.metadata()?)?;
    println!("assembled /dev/dm-{}", id.minor());
    Ok(device)
}
```

`Chain` can also be constructed directly from a trusted root and ordered
`Layer { data, hash }` paths, base to top. Assembly returns a read-only file
with deferred removal already scheduled. The file, clones, mounts, and upper
mappings retain the stack until their last holder closes.

With features `gpt` and `tokio`, `AsyncFromGpt` provides async discovery.
Assembly is synchronous; async callers can run it with `spawn_blocking`.
`gpt` is enabled by default; `loop`
(file-backed layers) and `tokio` are optional.

See the [crate documentation](carapace/README.md) for the full API, async
cancellation contract, writable snapshot example, migration notes, and tests.

## CLI

```sh
carapace mount <root-hex> <dir> [--type <fs>]
umount <dir>
```

GPT image partitions must already be exposed to the kernel, for example with
`losetup --partscan`. Discovery uses sysfs PARTUUIDs and does not require udev.

## License

Apache-2.0 — see [LICENSE](LICENSE). Source files carry SPDX headers.
