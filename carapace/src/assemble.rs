// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Assemble read-only mappings with open files as their lifetime anchors.

use crate::snapshot::{ValidatedSnapshotHeader, SNAPSHOT_HEADER_SIZE};
use crate::util::hex_lower;
use crate::verity::superblock::VERITY_SUPERBLOCK_SIZE;
use crate::verity::ValidatedVeritySuperblock;
use crate::{Chain, Layer};
use devmap_linux::device::Status;
use devmap_linux::target::snapshot::{ChunkSize, Persistence, SnapshotTarget};
use devmap_linux::target::zero::ZeroTarget;
use devmap_linux::target::Target;
use devmap_linux::{Control, DevId};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::num::NonZero;
use std::os::unix::fs::FileTypeExt;

/// Preserve the existing 64 GiB virtual origin size during the API migration.
const ZERO_COUNT_SECTORS: u64 = 64u64 * 1024 * 1024 * 1024 / 512;
pub(crate) const MAX_CHAIN_DEPTH: usize = 32;

#[derive(Debug)]
struct PreparedLayer {
    data: File,
    hash: File,
    superblock: ValidatedVeritySuperblock,
    root: Box<[u8]>,
}

impl PreparedLayer {
    fn open(layer: &Layer, root: &[u8], index: usize) -> io::Result<Self> {
        let mut hash = File::open(&layer.hash)?;
        let mut record = [0; VERITY_SUPERBLOCK_SIZE];
        hash.read_exact(&mut record)?;
        let superblock = ValidatedVeritySuperblock::parse(&record, index)?;
        Ok(Self {
            data: File::open(&layer.data)?,
            hash,
            superblock,
            root: root.into(),
        })
    }
}

impl Chain {
    /// Open and validate inputs before creating any kernel mappings. Open
    /// files pin the selected devices/backing files through attachment.
    fn prepare(&self) -> io::Result<Vec<PreparedLayer>> {
        if self.layers.is_empty() || self.layers.len() > MAX_CHAIN_DEPTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a chain needs 1..={MAX_CHAIN_DEPTH} layers"),
            ));
        }
        let mut root = self.root.clone();
        let mut algorithm = None;
        let mut prepared = Vec::with_capacity(self.layers.len());
        for (index, layer) in self.layers.iter().enumerate().rev() {
            let layer = PreparedLayer::open(layer, &root, index)?;
            let sb = &layer.superblock;
            if algorithm.is_some_and(|expected| sb.algorithm != expected) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chain algorithm mismatch",
                ));
            }
            if root.len() != sb.algorithm.digest_size() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted root length must match the hash algorithm",
                ));
            }
            algorithm = Some(sb.algorithm);
            if sb.is_base() != (index == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("scute {index}: invalid base salt sentinel"),
                ));
            }
            root = sb.full_salt()[..sb.algorithm.digest_size()].into();
            prepared.push(layer);
        }
        prepared.reverse();
        Ok(prepared)
    }

    pub(crate) fn assemble_sync(&self) -> io::Result<File> {
        let prepared = self.prepare()?;
        // All Carapace assemblers lock the same control node, including across
        // processes. This makes create/load/resume/reuse a single publication
        // operation. Closing this independent fd releases the advisory lock.
        let lock = File::open("/dev/mapper/control")?;
        lock.lock()?;
        let assembler = Assembler {
            control: Control::open()?,
        };
        let mut origin = assembler.activate("CARAPACE-z", ZERO_COUNT_SECTORS, ZeroTarget)?;
        for (index, layer) in prepared.iter().enumerate() {
            origin = assembler
                .layer(layer, origin, index)
                .map_err(|error| io::Error::new(error.kind(), format!("scute {index}: {error}")))?;
        }
        Ok(origin)
    }
}

#[derive(Debug)]
struct Assembler {
    control: Control,
}

impl Assembler {
    /// Resolve an already-open input, retaining its block handle until the
    /// verity table holds it. Loop handles are ordinary files with autoclear.
    fn resolve(file: &File) -> io::Result<File> {
        let metadata = file.metadata()?;
        if metadata.file_type().is_block_device() {
            return file.try_clone();
        }
        if metadata.is_file() {
            #[cfg(feature = "loop")]
            {
                let config = lodown::Configurable {
                    read_only: true,
                    writable: lodown::Writable {
                        autoclear: true,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let device = lodown::Control::open()?.attach(file, 0, config)?;
                return Ok(device.into());
            }
            #[cfg(not(feature = "loop"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file-backed layers need feature `loop`",
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "layer is not a block device or regular file",
        ))
    }

    fn layer(&self, layer: &PreparedLayer, origin: File, index: usize) -> io::Result<File> {
        let data = Self::resolve(&layer.data)?;
        let hash = Self::resolve(&layer.hash)?;
        let data_id = DevId::try_from(data.metadata()?)?;
        let hash_id = DevId::try_from(hash.metadata()?)?;
        let origin_id = DevId::try_from(origin.metadata()?)?;
        let verity_target = layer
            .superblock
            .header
            .builder(data_id, hash_id, layer.root.clone())?
            .build();
        // Bind names to both content and backing devices. Different loop
        // attachments of identical content can coexist without replacing a
        // live table; identical block-device inputs still share mappings.
        let name = format!(
            "CARAPACE-v{}-{data_id}-{hash_id}",
            hex_lower(&layer.root[..16])
        );
        let mut verity = self.activate(&name, verity_target.data_sectors(), verity_target)?;
        let mut header = [0; SNAPSHOT_HEADER_SIZE];
        verity.read_exact(&mut header)?;
        ValidatedSnapshotHeader::parse(&header, index)?;
        let verity_id = DevId::try_from(verity.metadata()?)?;
        let name = format!(
            "CARAPACE-s{}-{origin_id}-{verity_id}",
            hex_lower(&layer.root[16..32])
        );
        let chunk = ChunkSize::new(NonZero::new(8).unwrap()).unwrap();
        let snapshot = SnapshotTarget::new(origin_id, verity_id, Persistence::Persistent, chunk);
        // The upper mapping holds origin/verity before their files close.
        self.activate(&name, ZERO_COUNT_SECTORS, snapshot)
    }

    /// New mappings get rollback guards. Existing mappings are pinned and
    /// checked, never reloaded or put under an immediate-removal guard.
    fn activate<T>(&self, name: &str, sectors: u64, target: T) -> io::Result<File>
    where
        T: Target<Table = T> + Clone + PartialEq,
    {
        for _ in 0..8 {
            match self.control.create(name) {
                Ok(device) => {
                    let guard = device.guard();
                    guard
                        .builder()
                        .read_only()
                        .add(0, sectors, target.clone())?
                        .load()?;
                    guard.resume()?;
                    return guard.defer(OpenOptions::new().read(true));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AlreadyExists | io::ErrorKind::ResourceBusy
                    ) => {}
                Err(error) => return Err(error),
            }
            // Deferred removal can race lookup/open even under the setup lock:
            // existing consumers close their files without acquiring it.
            let existing = self.control.by_name(name).and_then(|(device, _)| {
                let file = File::open(device.node_path())?;
                Ok((device, file))
            });
            let (device, file) = match existing {
                Ok(existing) => existing,
                Err(error) if matches!(error.raw_os_error(), Some(2 | 6 | 19)) => continue,
                Err(error) => return Err(error),
            };
            let status = device.status()?;
            let required = Status::READ_ONLY | Status::ACTIVE_TABLE;
            if status.flags & required != required
                || status.flags & (Status::SUSPENDED | Status::INACTIVE_TABLE) != 0
                || DevId::try_from(file.metadata()?)? != device.id()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("existing mapping {name} is not an active read-only device"),
                ));
            }
            let mut rows = device.table()?;
            let matches = match rows.next() {
                Some(row) => {
                    row.start() == 0 && row.length() == sectors && row.parse::<T>()? == target
                }
                None => false,
            };
            if !matches || rows.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("existing mapping {name} has a different table"),
                ));
            }
            drop(rows);
            device.remove(true)?;
            return Ok(file);
        }
        Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("mapping {name} is being removed; retry assembly"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn layer(dir: &Path, index: usize, algorithm: &str, salt: &[u8]) -> Layer {
        let data = dir.join(format!("data-{index}"));
        let hash = dir.join(format!("hash-{index}"));
        let mut bytes = [0; VERITY_SUPERBLOCK_SIZE];
        bytes[..8].copy_from_slice(b"verity\0\0");
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..32 + algorithm.len()].copy_from_slice(algorithm.as_bytes());
        bytes[64..68].copy_from_slice(&4096u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&4096u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&1u64.to_le_bytes());
        bytes[80..82].copy_from_slice(&(salt.len() as u16).to_le_bytes());
        bytes[88..88 + salt.len()].copy_from_slice(salt);
        std::fs::write(&data, [0; 4096]).unwrap();
        std::fs::write(&hash, bytes).unwrap();
        Layer { data, hash }
    }

    #[test]
    fn direct_chains_reject_empty_and_excessive_depth_before_io() {
        let mut chain = Chain {
            root: vec![1; 32].into(),
            layers: vec![],
        };
        assert_eq!(
            chain.prepare().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        chain.layers = vec![
            Layer {
                data: "/missing".into(),
                hash: "/missing".into()
            };
            MAX_CHAIN_DEPTH + 1
        ];
        assert_eq!(
            chain.prepare().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn direct_chains_require_exact_root_length_and_base_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        for length in [0, 31, 33, 64, 65] {
            let chain = Chain {
                root: vec![1; length].into(),
                layers: vec![layer(dir.path(), 0, "sha256", &[0; 32])],
            };
            assert_eq!(
                chain.prepare().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let chain = Chain {
            root: vec![1; 32].into(),
            layers: vec![layer(dir.path(), 0, "sha256", &[1; 32])],
        };
        let error = chain.prepare().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("sentinel"));
    }

    #[test]
    fn direct_chains_validate_algorithm_and_derive_parent_roots() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = Chain {
            root: vec![2; 32].into(),
            layers: vec![
                layer(dir.path(), 0, "sha256", &[0; 32]),
                layer(dir.path(), 1, "sha256", &[1; 32]),
            ],
        };
        let prepared = chain.prepare().unwrap();
        assert_eq!(&*prepared[0].root, &[1; 32]);
        assert_eq!(&*prepared[1].root, &[2; 32]);
        chain.layers[0] = layer(dir.path(), 0, "sha512", &[0; 64]);
        let error = chain.prepare().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("algorithm mismatch"));
        chain.layers[0] = layer(dir.path(), 0, "sha256", &[0; 32]);
        chain.layers[1] = layer(dir.path(), 1, "sha256", &[0; 32]);
        assert!(chain
            .prepare()
            .unwrap_err()
            .to_string()
            .contains("sentinel"));
    }
}
