// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recursive assembler that builds the dm-verity + dm-snapshot read stack
//! from an ordered `&[Layer]` slice (BASE → TOP) and a trusted root hash.
//!
//! Content-addressed dm device names:
//!   dm-zero  → `CARAPACE-z`
//!   verity Vᵢ → `CARAPACE-v{hex(Rᵢ[0..16])}`
//!   snapshot Sᵢ → `CARAPACE-s{hex(Rᵢ[16..32])}`
//!
//! The recursion peels layers with `split_last` (TOP first, recurse on LOWER
//! with the parent root = this layer's salt prefix). Base case = dm-zero.
//! Interior `Removed`s drop at frame exit → `DM_DEFERRED_REMOVE`; they're
//! busy (held by the device above), so removal just schedules. The outermost
//! frame's `Removed` is returned to the caller (the mount bridge).

use crate::snapshot::{ValidatedSnapshotHeader, SNAPSHOT_HEADER_SIZE};
use crate::util::hex_lower;
use crate::verity::ValidatedVeritySuperblock;
use crate::Layer;
use devmap::targets::snapshot::Snapshot;
use devmap::targets::{Verity, Zero};
use devmap::{Control, DevId, Removed};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// dm-zero virtual length = 64 GiB in sectors. Every snapshot inherits
/// this length (kernel: snapshot.length ≤ origin.length).
pub(crate) const ZERO_COUNT_SECTORS: u64 = 64u64 * 1024 * 1024 * 1024 / 512;

/// Sector count for a verity device given data_blocks (each 4096 bytes).
fn verity_sectors(data_blocks: u64) -> u64 {
    data_blocks * 4096 / 512
}

/// Content-addressed name: verity Vᵢ.
fn v_name(root: &[u8]) -> String {
    format!("CARAPACE-v{}", hex_lower(&root[..root.len().min(16)]))
}

/// Content-addressed name: snapshot Sᵢ.
fn s_name(root: &[u8]) -> String {
    let start = root.len().min(16);
    let end = root.len().min(32);
    format!("CARAPACE-s{}", hex_lower(&root[start..end]))
}

/// Create-or-reuse a dm device by content-addressed name.
///
/// Safety reasoning: names are content-addressed (CARAPACE-v/s prefix +
/// hex of a cryptographic root prefix). Only carapace/corium create
/// `CARAPACE-*` devices, and doing so requires CAP_SYS_ADMIN. A collision
/// means an identical layer is already active — safe to reuse.
fn create_or_reuse(ctl: &Control, name: &str) -> io::Result<Removed> {
    match ctl.create(name) {
        Ok(removed) => Ok(removed),
        Err(e)
            if e.kind() == io::ErrorKind::AlreadyExists
                || e.kind() == io::ErrorKind::ResourceBusy =>
        {
            let (device, _status) = ctl.by_name(name)?;
            Ok(Removed::from(device))
        }
        Err(e) => Err(e),
    }
}

/// Resolve a path to its `DevId`.
///
/// - Block device → stat and decode rdev.
/// - Regular file → loop-attach (feature `loop`).
#[cfg_attr(not(feature = "loop"), allow(unused_variables))]
fn resolve(
    path: &Path,
    #[cfg(feature = "loop")] loops: &mut Vec<lodown::LoopDevice>,
    #[cfg(not(feature = "loop"))] _loops: &mut Vec<()>,
    ctl: &Control,
) -> io::Result<DevId> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(path)?;
    if meta.file_type().is_block_device() {
        let dev = ctl.by_node(path)?;
        return Ok(dev.id());
    }
    if meta.file_type().is_file() {
        #[cfg(feature = "loop")]
        {
            use lodown::{Config, LoopDevice};
            let lctl = lodown::Control::open()?;
            let backing = File::open(path)?;
            let config = Config::new().autoclear(true).read_only(true);
            // Retry on ResourceBusy: get_free races with other processes.
            let detached = loop {
                match lctl.attach(&backing, &config) {
                    Ok(d) => break d,
                    Err(e) if e.kind() == io::ErrorKind::ResourceBusy => continue,
                    Err(e) => return Err(e),
                }
            };
            let number = detached.number();
            let loop_dev: LoopDevice = detached.into();
            // DevId for loop devices: major=7, minor=number (default max_part=0).
            let id = DevId::new(7, number).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "loop device number out of range",
                )
            })?;
            loops.push(loop_dev);
            return Ok(id);
        }
        #[cfg(not(feature = "loop"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("file-backed layers need feature `loop`: {}", path.display()),
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "path is not a block device or regular file: {}",
            path.display()
        ),
    ))
}

/// Recursive core. Returns the top `Removed` of the sub-stack.
fn assemble_from(
    layers: &[Layer],
    root: &[u8],
    ctl: &Control,
    #[cfg(feature = "loop")] loops: &mut Vec<lodown::LoopDevice>,
    #[cfg(not(feature = "loop"))] loops: &mut Vec<()>,
) -> io::Result<Removed> {
    let Some((top, lower)) = layers.split_last() else {
        // Base case: dm-zero origin.
        let z = create_or_reuse(ctl, "CARAPACE-z")?;
        z.builder()
            .add(0, ZERO_COUNT_SECTORS, Zero)?
            .load()
            .map_err(|e| io::Error::new(e.kind(), format!("dm-zero table load: {e}")))?;
        z.resume()
            .map_err(|e| io::Error::new(e.kind(), format!("dm-zero resume: {e}")))?;
        return Ok(z);
    };

    // Absolute BASE→TOP index of this frame's top layer, for error
    // attribution only. Slices are always base-anchored prefixes, so the
    // top's index is simply the number of layers below it.
    let scute_index = lower.len();

    // Read and validate the hash superblock for this layer.
    let sb = {
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new().read(true).open(&top.hash)?;
        let mut buf = [0u8; crate::verity::superblock::VERITY_SUPERBLOCK_SIZE];
        f.read_exact(&mut buf)?;
        ValidatedVeritySuperblock::parse(&buf, scute_index)?
    };

    // Derive Rᵢ from the salt prefix (salt[..digest_size] = parent root for
    // non-base; base sentinel = all zero prefix checked by superblock parser).
    let digest_size = sb.algorithm.digest_size();

    // Re-derive the parent root from the salt prefix (= Rᵢ₋₁).
    let parent_root = &sb.full_salt()[..digest_size];

    // Recurse on lower layers with the parent root.
    let origin = assemble_from(lower, parent_root, ctl, loops)?;

    // Resolve data and hash paths to DevIds.
    let data_id = resolve(&top.data, loops, ctl)?;
    let hash_id = resolve(&top.hash, loops, ctl)?;

    let vi = create_or_reuse(ctl, &v_name(root))?;
    vi.builder()
        .read_only() // dm-verity refuses a writable table
        .add(
            0,
            verity_sectors(sb.data_blocks),
            Verity::new(
                data_id,
                hash_id,
                sb.data_blocks,
                sb.algorithm.name(),
                root.to_vec(),
                sb.full_salt().to_vec(),
            ),
        )?
        .load()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("scute {scute_index} verity table load: {e}"),
            )
        })?;
    vi.resume()
        .map_err(|e| io::Error::new(e.kind(), format!("scute {scute_index} verity resume: {e}")))?;

    // Validate snapshot header through the activated dm-verity device
    // (reads integrity-checked bytes, not raw data partition).
    {
        let verity_path = format!("/dev/dm-{}", vi.id().minor());
        let mut f = File::open(&verity_path)?;
        let mut buf = [0u8; SNAPSHOT_HEADER_SIZE];
        f.read_exact(&mut buf)?;
        ValidatedSnapshotHeader::parse(&buf, scute_index)?;
    }

    let si = create_or_reuse(ctl, &s_name(root))?;
    si.builder()
        .read_only() // read-only composition: never writes exceptions to the verity cow
        .add(
            0,
            ZERO_COUNT_SECTORS,
            Snapshot::new(origin.id(), vi.id(), 8),
        )?
        .load()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("scute {scute_index} snapshot table load: {e}"),
            )
        })?;
    si.resume().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("scute {scute_index} snapshot resume: {e}"),
        )
    })?;

    // `origin` (dm-zero or lower snapshot) and `vi` (verity) drop here.
    // Removed::drop issues DM_DEFERRED_REMOVE; they're busy (si holds them),
    // so the kernel only schedules removal — no EBUSY.
    Ok(si)
}

/// Assemble the full read stack for `layers` (BASE → TOP) anchored by
/// `trusted_root`. Returns the top snapshot `Removed` guard.
pub(crate) fn assemble(layers: &[Layer], root: &[u8]) -> io::Result<Removed> {
    let ctl = Control::open()?;
    #[cfg(feature = "loop")]
    let mut loops: Vec<lodown::LoopDevice> = Vec::new();
    #[cfg(not(feature = "loop"))]
    let mut loops: Vec<()> = Vec::new();

    // `loops` (the file-backed layers' loop handles) must outlive every resume
    // in the recursion, so it stays in scope until this call returns. It then
    // drops (closing the fds), but each loop is still held by its resumed
    // dm-verity device, so nothing detaches until the chain is torn down — at
    // which point LO_FLAGS_AUTOCLEAR releases each backing file.
    assemble_from(layers, root, &ctl, &mut loops)
}
