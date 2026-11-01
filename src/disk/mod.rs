// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Partitioned disk images stored inside an assembled carapace.
//!
//! This is separate from outer scute PARTUUID discovery. A disk occupies a
//! bounded prefix of the backing device: its primary GPT header identifies
//! the final sector, which contains the backup header. Both headers and tables
//! must agree. No kernel partition scan, repair, or filesystem probing occurs.
//! Only 512-byte sectors and GPT 1.0 with 128-byte entries are supported.

mod architecture;
mod bounded;
mod layout;
mod partition;

pub use architecture::Architecture;
pub use layout::Layout;
pub use partition::Partition;

use gpt::{disk::LogicalBlockSize, header::Header};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

const SECTOR_SIZE: u64 = 512;
const BLOCK_SIZE: LogicalBlockSize = LogicalBlockSize::Lb512;
const NO_AUTO: u64 = 1 << 63;
const MAX_ENTRIES: u32 = 8192;

/// A validated logical disk, independent of its larger backing device.
#[derive(Debug)]
pub struct Disk {
    sectors: u64,
    partitions: BTreeMap<u32, gpt::partition::Partition>,
}

impl Disk {
    /// Read and validate both copies of a disk's partition metadata.
    ///
    /// `capacity` is the backing extent in bytes, not the filesystem size.
    /// Use [`crate::ZERO_SIZE_BYTES`] for an assembled carapace, or the actual
    /// file length for a standalone disk image. Reads change the stream cursor.
    /// Metadata is bounded to 8192 entries (1 MiB per table) before allocation.
    pub fn read(reader: &mut (impl Read + Seek), capacity: u64) -> io::Result<Self> {
        if capacity > crate::ZERO_SIZE_BYTES || !capacity.is_multiple_of(SECTOR_SIZE) {
            return Err(Self::invalid("invalid disk backing capacity"));
        }
        if capacity < 68 * SECTOR_SIZE {
            return Err(Self::invalid("backing device is too small for GPT"));
        }
        let primary = Self::header(reader, 1)?;
        if primary.current_lba != 1
            || primary.backup_lba < 67
            || primary.backup_lba >= capacity / SECTOR_SIZE
        {
            return Err(Self::invalid("GPT disk extent exceeds its backing device"));
        }
        let sectors = primary.backup_lba + 1;
        let backup = Self::header(reader, primary.backup_lba)?;
        Self::validate_headers(&primary, &backup)?;
        Self::protective_mbr(reader, sectors)?;

        let table = Self::table(reader, &primary)?;
        let other = Self::table(reader, &backup)?;
        if table != other {
            return Err(Self::invalid("GPT partition tables disagree"));
        }
        // Decode the bounded, snapshotted bytes and verify the table CRC. Both
        // copies have identical bytes and declared CRCs, so this verifies both.
        // The decoder assumes 128-byte entries, proven by header validation.
        let mut header = primary.clone();
        header.part_start = 0;
        let mut partitions =
            gpt::partition::file_read_partitions(&mut Cursor::new(table), &header, BLOCK_SIZE)?;
        partitions.retain(|_, entry| !entry.part_type_guid.guid.is_nil());
        let mut identities = BTreeSet::new();
        let mut ranges = Vec::with_capacity(partitions.len());
        for entry in partitions.values() {
            if entry.first_lba < primary.first_usable
                || entry.last_lba > primary.last_usable
                || entry.last_lba < entry.first_lba
            {
                return Err(Self::invalid("GPT partition is outside the usable extent"));
            }
            if entry.part_guid.is_nil()
                || entry.part_guid == primary.disk_guid
                || !identities.insert(entry.part_guid)
            {
                return Err(Self::invalid(
                    "GPT partition identifiers must be unique and nonzero",
                ));
            }
            ranges.push((entry.first_lba, entry.last_lba));
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 >= pair[1].0) {
            return Err(Self::invalid("GPT partitions overlap"));
        }
        Ok(Self {
            sectors,
            partitions,
        })
    }

    /// Logical disk size, including both partition tables, in 512-byte sectors.
    pub fn sectors(&self) -> u64 {
        self.sectors
    }

    /// Select exactly one discoverable root for the target architecture.
    /// Partitions marked no-auto are not candidates.
    pub fn root(&self, architecture: Architecture) -> io::Result<Partition> {
        self.select(&architecture.partition_type())?
            .ok_or_else(|| Self::invalid("no discoverable root for the target architecture"))
    }

    /// Select the optional EFI System Partition. Multiple candidates are errors.
    pub fn esp(&self) -> io::Result<Option<Partition>> {
        self.select(&gpt::partition_types::EFI)
    }

    fn select(&self, kind: &gpt::partition_types::Type) -> io::Result<Option<Partition>> {
        let mut entries = self
            .partitions
            .values()
            .filter(|entry| entry.part_type_guid.guid == kind.guid && entry.flags & NO_AUTO == 0);
        let result = entries.next().map(|entry| Partition {
            start: entry.first_lba,
            sectors: entry.last_lba - entry.first_lba + 1,
        });
        if entries.next().is_some() {
            return Err(Self::invalid(
                "multiple discoverable partitions of the selected type",
            ));
        }
        Ok(result)
    }

    fn header(reader: &mut (impl Read + Seek), sector: u64) -> io::Result<Header> {
        // Read a single sector before interpreting any on-disk length. Placing
        // it at offset 512 lets the library decode either copy as a header.
        let mut bytes = [0; 1024];
        reader.seek(SeekFrom::Start(sector * SECTOR_SIZE))?;
        reader.read_exact(&mut bytes[512..])?;
        if bytes[604..].iter().any(|byte| *byte != 0) {
            return Err(Self::invalid(
                "unsupported GPT header extension or reserved bytes",
            ));
        }
        let header =
            gpt::header::read_header_from_arbitrary_device(&mut Cursor::new(bytes), BLOCK_SIZE)
                .map_err(Self::invalid)?;
        if header.revision != (1, 0)
            || header.header_size_le != 92
            || header.reserved != 0
            || header.part_size != 128
            || !(128..=MAX_ENTRIES).contains(&header.num_parts)
            || header.disk_guid.is_nil()
        {
            return Err(Self::invalid("unsupported GPT header or entry geometry"));
        }
        Ok(header)
    }

    fn validate_headers(primary: &Header, backup: &Header) -> io::Result<()> {
        let table_sectors = (u64::from(primary.num_parts) * 128).div_ceil(SECTOR_SIZE);
        if backup.current_lba != primary.backup_lba
            || backup.backup_lba != primary.current_lba
            || backup.disk_guid != primary.disk_guid
            || backup.first_usable != primary.first_usable
            || backup.last_usable != primary.last_usable
            || backup.num_parts != primary.num_parts
            || backup.crc32_parts != primary.crc32_parts
        {
            return Err(Self::invalid("GPT headers disagree"));
        }
        if primary.part_start < 2
            || primary.part_start > primary.backup_lba
            || primary.part_start + table_sectors > primary.first_usable
            || primary.first_usable > primary.last_usable
            || primary.last_usable >= backup.part_start
            || backup.part_start > backup.current_lba
            || backup.part_start + table_sectors > backup.current_lba
        {
            return Err(Self::invalid(
                "GPT metadata overlaps usable sectors or exceeds the disk",
            ));
        }
        Ok(())
    }

    fn table(reader: &mut (impl Read + Seek), header: &Header) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; header.num_parts as usize * 128];
        reader.seek(SeekFrom::Start(header.part_start * SECTOR_SIZE))?;
        reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn protective_mbr(reader: &mut (impl Read + Seek), sectors: u64) -> io::Result<()> {
        let mut bytes = [0; 512];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut bytes)?;
        let mbr = gpt::mbr::ProtectiveMBR::from_bytes(&bytes, BLOCK_SIZE).map_err(Self::invalid)?;
        let mut protective = 0;
        for index in 0..4 {
            let entry = mbr.partition(index).expect("four MBR entries");
            if entry.os_type == 0xee
                && entry.boot_indicator == 0
                && entry.lb_start == 1
                && u64::from(entry.lb_size) == (sectors - 1).min(u64::from(u32::MAX))
            {
                protective += 1;
            } else if entry.to_bytes() != [0; 16] {
                return Err(Self::invalid("invalid or hybrid protective MBR"));
            }
        }
        if protective != 1 {
            return Err(Self::invalid("GPT requires one protective MBR entry"));
        }
        Ok(())
    }

    fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

#[cfg(test)]
mod tests;
