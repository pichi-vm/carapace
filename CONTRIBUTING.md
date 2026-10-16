# Contributing

## Commit messages

Commits follow Conventional Commits and standard git formatting, enforced by
gitlint (see `.gitlint`) in CI.

- Subject: `type(scope): summary` — lowercase, imperative, no trailing period,
  at most 50 characters. Types: `feat`, `fix`, `docs`, `style`, `refactor`,
  `perf`, `test`, `build`, `ci`, `chore`, `revert`, `spec`.
- One blank line, then a body wrapped at 72 characters explaining what changed
  and why (not how — the diff shows how).
- Write each message to stand on its own: describe the change and its rationale
  for a reader with no knowledge of the project's history or how the work was
  produced. Do not reference internal process, prior iterations, or review
  back-and-forth. (gitlint cannot check this — it is a review responsibility.)

## Block-device benchmarks

The Criterion benchmark requires Linux, root/device-mapper access, loop devices,
GPT partition support, and the `zero`, `snapshot`, and `verity` kernel targets.
It fails if these are unavailable. On an x86-64 Linux host, run:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -n' \
  cargo bench --target x86_64-unknown-linux-gnu --bench block_device
```

This builds as your normal user and runs only the benchmark executable as root.
Replace the target and runner variable for another architecture. Alternatively,
use `cargo bench --bench block_device --no-run`, then run the executable printed
by Cargo with `sudo <executable> --bench`. Criterion writes results under
`carapace/target/criterion` (owned by root when run through Cargo). Add `-- --test` to the Cargo command for a
single-iteration smoke test, including fixture validation at every depth.

Two independent measurements cover 1, 2, 4, 8, 16, and 32 layers:

- `block_device/discovery/N`: `Chain::from_gpt`, excluding destruction of the
  returned chain.
- `block_device/fresh_activation/N`: `Chain::assemble`, following untimed
  discovery. Destruction and waiting for deferred mapping removal are excluded.

There is no combined or reuse benchmark. Each activation starts with no
`CARAPACE-*` mappings. Run on an otherwise idle host without other Carapace users;
preexisting mappings cause a timeout rather than being removed. Discovery scans
host sysfs, so other attached devices affect its cost. Record the host/kernel and
block-device inventory when comparing runs.

All benchmark fixtures are generated in Rust: lodown attaches temporary loop
storage, devmap creates persistent snapshot COW stores and formats their verity
hashes, and the gpt crate writes partition tables. The measured inputs are GPT
partitions on an already attached block device; Carapace's `loop` feature is not
required. No filesystem formatter, cryptsetup, or other setup command is invoked.
The temporary image needs about 162 MiB at maximum depth.

Each layer has a 4 MiB COW partition and a 1 MiB hash partition. It overwrites one
shared 4 KiB block and writes 32 disjoint blocks. Full-chunk writes allow setup to
use a zero origin for each store; the final assembled chain is checked for both
inherited data and overwrites, plus an untouched zero block, before timing.
This fixes exception count per layer and avoids filesystem-dependent workloads.
Fixtures and loop attachment are outside timing. Caches are warmed by setup and
validation; fresh activation means fresh device-mapper mappings, not cold storage.
This measures host loop-backed block-device behavior, not physical-device or VM
latency. Criterion reports timing estimates and confidence intervals; compare the
depth series to assess marginal cost rather than assuming linear scaling.

The existing `tests/fixtures/build_carapace.sh` remains necessary for the separate
ext4 mount/interoperability tests. Those use cryptsetup as an independent formatter
and exercise filesystem contents; the raw benchmark fixture does not replace that
coverage.
