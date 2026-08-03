// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! carapace — read-side library for carapace block-device chains.
//!
//! Assembles a cryptographically-bound chain of content-addressable
//! block-device layers ("scutes") into a unified, integrity-protected,
//! read-only device anchored by a single trusted root. Given a trusted
//! chain root, this library walks the partitions the kernel exposes via
//! `/sys/class/block/*/uevent` (PARTUUID lookup), validates every scute's
//! parameters against the RDP whitelist, and builds the dm-verity +
//! dm-snapshot stack. The on-disk format is specified in `SPEC.md`; this
//! crate is read-only at the operator surface.
//!
//! # Library API
//!
//! - [`Chain`] — an ordered list of layers (base → top) plus a trusted root.
//! - [`Layer`] — a data/hash path pair for one scute.
//! - [`Chain::assemble`] — build the dm stack and return a [`Removed`] guard.
//! - [`FromGpt`] — discover a `Chain` by PARTUUID walk (feature `gpt`).
//!
//! Re-exports: [`devmap::DevId`], [`devmap::Removed`].

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

mod assemble;
#[cfg(feature = "gpt")]
mod chain;
#[cfg(feature = "gpt")]
mod partition;
mod snapshot;
mod util;
mod verity;

pub use devmap::{DevId, Removed};

use std::io;
use std::path::PathBuf;

/// One scute's data + hash partition paths (owned).
#[derive(Debug)]
pub struct Layer {
    /// Block-device or file path for the data partition.
    pub data: PathBuf,
    /// Block-device or file path for the hash partition.
    pub hash: PathBuf,
}

/// An ordered chain of scutes, base → top, plus the operator-supplied
/// trusted root hash. Produced by [`FromGpt::from_gpt`] or constructed
/// directly by an in-process caller that already knows the layer paths.
#[derive(Debug)]
pub struct Chain {
    /// The trusted chain root (operator-supplied, out-of-band).
    pub root: Box<[u8]>,
    /// Layers in BASE → TOP order.
    pub layers: Vec<Layer>,
}

impl Chain {
    /// Assemble the dm-verity + dm-snapshot stack for this chain and
    /// return the top snapshot as a [`Removed`] guard. While the guard
    /// is alive the stack is present; dropping it issues
    /// `DM_DEFERRED_REMOVE` on the top device (the lower devices cascade
    /// as they become un-busy). After mounting, drop the guard to anchor
    /// teardown to `umount`.
    pub fn assemble(&self) -> io::Result<Removed> {
        assemble::assemble(&self.layers, &self.root)
    }
}

/// Discover a [`Chain`] from GPT partitions visible to the kernel, given
/// a trusted root hash. Enabled by the `gpt` feature (default on).
#[cfg(feature = "gpt")]
pub trait FromGpt: Sized {
    /// Walk the PARTUUID chain starting from `root`, validate parameters,
    /// and return an ordered [`Chain`] (base → top).
    fn from_gpt(root: &[u8]) -> io::Result<Self>;
}

#[cfg(feature = "gpt")]
impl FromGpt for Chain {
    fn from_gpt(root: &[u8]) -> io::Result<Self> {
        let map = partition::PartitionMap::scan()?;
        let paths = chain::walk_chain(root, &map)?;
        let layers = paths
            .into_iter()
            .map(|(data, hash)| Layer { data, hash })
            .collect();
        Ok(Chain {
            root: root.to_vec().into_boxed_slice(),
            layers,
        })
    }
}
