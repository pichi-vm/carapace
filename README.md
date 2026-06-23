# carapace

A cryptographically composed, read-only block-device layering mechanism, plus a
producer that packages layers as registry-native OCI artifacts.

A **scute** is one layer (a dm-snapshot COW + a dm-verity tree); a **carapace**
is a salt-chain-bound stack of scutes presented as a single integrity-protected
read-only block device, validated by one trust anchor (the top scute's verity
root). See [`carapace/SPEC.md`](carapace/SPEC.md).

## Crates

- **`carapace`** — the read library (`attach`/`detach`) + the `carapace` CLI,
  which also gains an `import` verb (raw image → carapace OCI artifact).
- **`carapace-dm`** — the device-mapper ioctl layer (chain-agnostic).
- **`carapace-import`** — producer primitives: dm-snapshot COW + dm-verity
  emission, and OCI image-layout packaging.

## CLI

```
# Read: assemble a carapace into /dev/mapper/<name> from its trusted root.
carapace attach --name root --root <hex>

# Produce: convert a raw image into a single-scute base carapace as an OCI
# image layout, then push it with skopeo (no extra tooling required).
carapace import --image fedora.raw --out layout --tag 43
skopeo copy oci:layout:43 docker://ghcr.io/pichi-vm/fedora:43
```

The OCI artifact ships scute **cow** blobs + salt annotations; verity trees are
reconstructed by the consumer (SPEC.md, "Distribution Without Verity Files").

## License

Apache-2.0 — see [LICENSE](LICENSE). Source files carry an
`SPDX-License-Identifier` header (checked in CI by
[hawkeye](https://github.com/korandoru/hawkeye)).
