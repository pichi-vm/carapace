// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A validated partition extent in 512-byte sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    /// Offset within the assembled carapace or standalone disk image.
    pub start: u64,
    /// Number of sectors belonging to the partition.
    pub sectors: u64,
}
