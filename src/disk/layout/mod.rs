// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{bounded::Bounded, Architecture, Disk, Partition, SECTOR_SIZE};
use std::io::{self, Read, Seek, Write};

const ALIGNMENT: u64 = 2048;
const BACKUP_SECTORS: u64 = 33;

/// A root partition and optional EFI System Partition with 1 MiB alignment.
/// Capacities describe partition contents; table and alignment space is extra.
#[derive(Debug, Clone)]
pub struct Layout {
    architecture: Architecture,
    root: Partition,
    esp: Option<Partition>,
    sectors: u64,
}

impl Layout {
    /// Plan a new disk without acquiring storage or writing bytes.
    /// Capacities must be positive multiples of 4096 bytes. Filesystem-specific
    /// minimum sizes are the formatter's responsibility, not a GPT property.
    pub fn new(
        architecture: Architecture,
        root_bytes: u64,
        esp_bytes: Option<u64>,
    ) -> io::Result<Self> {
        let esp = esp_bytes
            .map(Self::partition_sectors)
            .transpose()?
            .map(|sectors| Partition {
                start: ALIGNMENT,
                sectors,
            });
        let root = Partition {
            start: match esp {
                Some(esp) => Self::align(esp.start + esp.sectors)?,
                None => ALIGNMENT,
            },
            sectors: Self::partition_sectors(root_bytes)?,
        };
        let end = root
            .start
            .checked_add(root.sectors)
            .and_then(|end| end.checked_add(BACKUP_SECTORS))
            .ok_or_else(|| Self::invalid("disk layout size overflow"))?;
        let sectors = Self::align(end)?;
        if sectors > crate::ZERO_SIZE_SECTORS {
            return Err(Self::invalid(
                "disk layout exceeds the carapace backing extent",
            ));
        }
        Ok(Self {
            architecture,
            root,
            esp,
            sectors,
        })
    }

    /// Entire logical disk size, including both GPT copies, in bytes.
    pub fn bytes(&self) -> u64 {
        self.sectors * SECTOR_SIZE
    }

    /// Write partition metadata into a new disk or snapshot, then validate it.
    ///
    /// `capacity` is the available backing extent in bytes. It may be larger
    /// than the planned disk. The writer touches only the protective MBR,
    /// headers and partition tables; it does not format or clear partitions.
    /// It creates fresh disk and partition UUIDs. The caller must discard the
    /// new output on any error and flush storage before publishing it.
    pub fn write<D: Read + Write + Seek + std::fmt::Debug>(
        &self,
        writer: &mut D,
        capacity: u64,
    ) -> io::Result<Disk> {
        if capacity < self.bytes()
            || capacity > crate::ZERO_SIZE_BYTES
            || !capacity.is_multiple_of(SECTOR_SIZE)
        {
            return Err(Self::invalid(
                "disk layout does not fit the backing capacity",
            ));
        }
        let mut device = Bounded::new(writer, self.bytes())?;
        gpt::mbr::ProtectiveMBR::with_lb_size(u32::try_from(self.sectors - 1).unwrap_or(u32::MAX))
            .overwrite_lba0(&mut device)
            .map_err(io::Error::other)?;
        let mut disk = gpt::GptConfig::new()
            .writable(true)
            .create_from_device(device, None)
            .map_err(io::Error::other)?;
        if let Some(esp) = self.esp {
            disk.add_partition_at(
                "esp",
                1,
                esp.start,
                esp.sectors,
                gpt::partition_types::EFI,
                0,
            )
            .map_err(io::Error::other)?;
        }
        disk.add_partition_at(
            "root",
            if self.esp.is_some() { 2 } else { 1 },
            self.root.start,
            self.root.sectors,
            self.architecture.partition_type(),
            0,
        )
        .map_err(io::Error::other)?;
        disk.write().map_err(io::Error::other)?.flush()?;
        Disk::read(writer, capacity)
    }

    fn partition_sectors(bytes: u64) -> io::Result<u64> {
        if bytes == 0 || !bytes.is_multiple_of(4096) || bytes > crate::ZERO_SIZE_BYTES {
            return Err(Self::invalid(
                "partition capacity must be positive, 4096-byte aligned and fit a carapace",
            ));
        }
        Ok(bytes / SECTOR_SIZE)
    }

    fn align(sectors: u64) -> io::Result<u64> {
        sectors
            .checked_add(ALIGNMENT - 1)
            .map(|rounded| rounded / ALIGNMENT * ALIGNMENT)
            .ok_or_else(|| Self::invalid("disk alignment overflow"))
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }
}

#[cfg(test)]
mod tests;
