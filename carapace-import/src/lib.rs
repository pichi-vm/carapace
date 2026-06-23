// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! carapace scute-format emission primitives.
//!
//! - [`cow`]: the dm-snapshot persistent COW writer (byte-exact per
//!   `drivers/md/dm-snap-persistent.c`).
//! - [`verity`]: the dm-verity v1 hash-tree builder.
//!
//! Both are pure format code — no blob store, no OCI manifest, no tagging.
//! `pichi-import` (host `pichi import`) and `conglobate` (in-guest build
//! driver) compose these into higher-level flows.

pub mod cow;
pub mod oci;
pub mod verity;

/// The dm-snapshot COW chunk size every carapace scute MUST use: 8 sectors
/// (4096 bytes). Fixed by the carapace spec's parameter whitelist (carapace
/// `SPEC.md`, "Parameter Whitelist") — the carapace read side rejects any
/// other value. Both producers (`pichi import`, `conglobate`) emit scutes at
/// this size; it is NOT a tunable (the generic
/// [`cow::DEFAULT_CHUNK_SIZE_SECTORS`] reflects dm's own default and is wrong
/// for carapaces).
pub const SCUTE_CHUNK_SIZE_SECTORS: u32 = 8;
