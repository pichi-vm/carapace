# carapace

Carapace composes cryptographically linked block-device layers into one
integrity-protected, read-only device. Each layer (a **scute**) contains a
persistent dm-snapshot exception store and a dm-verity hash volume. The top
layer's independently trusted root binds the entire chain.

This crate is the Linux read-side consumer. The format is specified in
[SPEC.md](SPEC.md); image production lives elsewhere.

## Library API

Discovery returns a `Chain`: an owned root and a list of `Layer { data, hash }`
paths, ordered base to top. Callers that already know the paths can construct
that description directly. Assembly validates it and returns an open block
device file. Both `Chain` and `Layer` implement `Debug` and `Clone`.

```rust,no_run
use carapace::{Assemble, Chain, DevId, FromGpt};

fn mount(root: &[u8], directory: &std::path::Path) -> std::io::Result<()> {
    let chain = Chain::from_gpt(root)?;
    let device: std::fs::File = chain.assemble()?;
    let id = DevId::try_from(device.metadata()?)?;
    let status = std::process::Command::new("mount")
        .args(["-o", "ro"])
        .arg(format!("/dev/dm-{}", id.minor()))
        .arg(directory)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("mount failed"));
    }
    // The mount now retains the stack; closing this file is safe.
    drop(device);
    Ok(())
}
```

Assembly returns a read-only `std::fs::File` at offset zero, with deferred
removal already scheduled. The file, its clones, mounts, and upper block-device
mappings can retain the device. Closing the last holder permits the kernel to
tear down the stack. Dropping a file does not forcibly unmount anything.

The file supports ordinary reads, seeks, metadata, and FD-based consumers.
`DevId::try_from(device.metadata()?)` obtains its device number without closing
it. `Removed` is no longer exported, and `assemble` is now a trait method:
synchronous callers import `Assemble`.

## Async API

With `gpt` and `tokio`, `AsyncFromGpt` provides discovery through Tokio's
blocking pool. Assembly is synchronous; the caller chooses how to schedule it:

```rust,no_run
use carapace::{Assemble, AsyncFromGpt, Chain};

async fn attach(root: &[u8]) -> std::io::Result<std::fs::File> {
    let chain = Chain::from_gpt(root).await?;
    tokio::task::spawn_blocking(move || chain.assemble())
        .await
        .map_err(std::io::Error::other)?
}
```

The closure owns the chain and returns the same device file without reopening
it. Callers wanting Tokio file I/O can wrap it with `tokio::fs::File::from_std`
using Tokio's `fs` feature. `AsyncAssemble` is no longer exported.

Dropping a Tokio blocking task's join handle does not stop work that has
started; runtime shutdown may wait for it to finish.

Async discovery requires a Tokio runtime. Work starts when its future is
polled and copies the root into the worker. Dropping the future does not
interrupt a running worker. IO errors retain their kind, while runtime and
worker failures are reported as contextual `std::io::Error`s. If both discovery
traits are imported, select `<Chain as AsyncFromGpt>::from_gpt(root)` explicitly.

## Writable snapshots

An assembled file can be the read-only origin of a writable snapshot, using
`devmap-linux` directly. Writes go to a separate writable COW block device.
For example, given an assembled `origin`, prepared `cow` block-device file,
and a sector count no larger than the origin:

```rust,no_run
use devmap_linux::{Control, DevId};
use devmap_linux::target::snapshot::{ChunkSize, Persistence, SnapshotTarget};
use std::{fs::{File, OpenOptions}, io, num::NonZero};

fn snapshot(origin: &File, cow: &File, name: &str, sectors: u64) -> io::Result<File> {
    let target = SnapshotTarget::new(
        DevId::try_from(origin.metadata()?)?,
        DevId::try_from(cow.metadata()?)?,
        Persistence::Persistent,
        ChunkSize::new(NonZero::new(8).unwrap()).unwrap(),
    );
    let control = Control::open()?;
    let device = control.create(name)?.guard();
    device.builder().add(0, sectors, target)?.load()?;
    device.resume()?;
    device.defer(OpenOptions::new().read(true).write(true))
}
```

Keep the input files alive through setup. The returned writable file retains
the snapshot, which in turn retains the origin and COW device. A regular-file
COW needs loop attachment first; lodown provides that separately.

## Features and dependencies

| Feature | Default | Purpose |
|---|---|---|
| `gpt` | On | `FromGpt` discovery through kernel-visible PARTUUIDs; CLI mounting |
| `loop` | Off | Read-only, autoclearing loop attachment of regular-file layers |
| `tokio` | Off | `AsyncFromGpt` (also requires `gpt`) |

The default build needs no async runtime. The library is empty on non-Linux
targets. Rust 1.89 or newer is required. `devmap-linux` handles device control,
`devmap-verity` handles the standard header/target format, and optional lodown
handles loop attachment. Carapace itself forbids unsafe Rust.

Validation failures use `InvalidData`; invalid caller inputs use `InvalidInput`.
Regular-file layers without `loop` return `Unsupported`. The shared verity
header decoder rejects noncanonical nonzero padding, which older Carapace
versions accepted. Carapace additionally enforces its own parameter whitelist
and chain rules, including for directly constructed chains.

Assemblers coordinate publication with an advisory lock on
`/dev/mapper/control`. Mappings are reused only when their active, read-only
tables match. Names include root prefixes and backing device IDs; independent
loop attachments of identical files may create separate mappings. Existing
active tables are never reloaded during reuse.

## CLI

```sh
carapace mount <root-hex> <dir> [--type <fs>]
umount <dir>
```

The trusted root must match the chain's digest size: 32 bytes for SHA-256 or
64 bytes for SHA-512. For GPT discovery, expose the outer image's partitions
first with `losetup --partscan`. Discovery reads `/sys/class/block/*/uevent`;
it does not require udev. Mounting requires device-mapper privileges and
`mount(8)`.

## Building and testing

```sh
cargo build --release
cargo test --lib --bins
cargo test --no-default-features --lib --bins
cargo test --all-features --lib --bins
sudo cargo test --all-features --tests -- --test-threads=1
```

Kernel integration tests require loop devices, dm-zero, dm-verity,
dm-snapshot, mount privileges, `cryptsetup-bin`, `gdisk`, `dmsetup`,
`e2fsprogs`, and `python3`. Run them on an isolated test host: fixture cleanup
uses the `CARAPACE-*` device namespace. They verify composition, tampering,
file lifetimes, shared mappings, async cleanup, and writable snapshots.

## License

Apache-2.0. See [LICENSE](../LICENSE).
