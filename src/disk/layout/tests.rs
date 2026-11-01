// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::Cursor;

#[test]
fn writes_aligned_native_roots_and_optional_esp() {
    for architecture in [Architecture::X86_64, Architecture::Aarch64] {
        for esp in [None, Some(1024 * 1024), Some(1024 * 1024 + 4096)] {
            let layout = Layout::new(architecture, 2 * 1024 * 1024, esp).unwrap();
            let mut source = Cursor::new(Vec::new());
            let disk = layout.write(&mut source, crate::ZERO_SIZE_BYTES).unwrap();
            let root = disk.root(architecture).unwrap();
            assert_eq!(root.sectors, 2 * 1024 * 1024 / SECTOR_SIZE);
            assert_eq!(root.start % ALIGNMENT, 0);
            assert_eq!(source.get_ref().len() as u64, layout.bytes());
            assert_eq!(disk.esp().unwrap().map(|p| p.sectors * SECTOR_SIZE), esp);
            let other = match architecture {
                Architecture::X86_64 => Architecture::Aarch64,
                Architecture::Aarch64 => Architecture::X86_64,
            };
            assert!(disk.root(other).is_err());
        }
    }
}

#[test]
fn metadata_writes_preserve_partition_contents_and_backing_tail() {
    let layout = Layout::new(Architecture::X86_64, 1024 * 1024, Some(1024 * 1024)).unwrap();
    let capacity = layout.bytes() + 4096;
    let mut source = Cursor::new(vec![0x5a; capacity as usize]);
    let disk = layout.write(&mut source, capacity).unwrap();
    for partition in [
        disk.root(Architecture::X86_64).unwrap(),
        disk.esp().unwrap().unwrap(),
    ] {
        let start = (partition.start * SECTOR_SIZE) as usize;
        let end = start + (partition.sectors * SECTOR_SIZE) as usize;
        assert!(source.get_ref()[start..end]
            .iter()
            .all(|byte| *byte == 0x5a));
    }
    assert!(source.get_ref()[layout.bytes() as usize..]
        .iter()
        .all(|byte| *byte == 0x5a));
}

#[test]
fn rejects_invalid_sizes_without_writing() {
    for size in [0, 512, u64::MAX, crate::ZERO_SIZE_BYTES] {
        assert!(Layout::new(Architecture::X86_64, size, None).is_err());
        assert!(Layout::new(Architecture::X86_64, 1024 * 1024, Some(size)).is_err());
    }
    let layout = Layout::new(Architecture::X86_64, 1024 * 1024, None).unwrap();
    let mut source = Cursor::new(vec![0x5a; 512]);
    for capacity in [
        0,
        layout.bytes() - 512,
        crate::ZERO_SIZE_BYTES + 512,
        layout.bytes() + 1,
    ] {
        assert!(layout.write(&mut source, capacity).is_err());
        assert_eq!(source.get_ref(), &[0x5a; 512]);
    }
}

#[test]
fn disk_and_partition_ids_are_new_and_distinct() {
    let layout = Layout::new(Architecture::X86_64, 1024 * 1024, Some(1024 * 1024)).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let mut source = Cursor::new(Vec::new());
        layout.write(&mut source, layout.bytes()).unwrap();
        let disk = gpt::GptConfig::new()
            .only_valid_headers(true)
            .open_from_device(source)
            .unwrap();
        let disk_id = disk.primary_header().unwrap().disk_guid;
        assert!(!disk_id.is_nil());
        assert!(ids.insert(disk_id));
        for partition in disk.partitions().values() {
            assert!(!partition.part_guid.is_nil());
            assert!(ids.insert(partition.part_guid));
        }
    }
}
