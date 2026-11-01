// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use gpt::{partition::Partition as Entry, partition_types};
use std::io::Write;

const SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct Fixture {
    bytes: Cursor<Vec<u8>>,
}

impl Fixture {
    fn new(types: &[gpt::partition_types::Type]) -> Self {
        let mut bytes = Cursor::new(vec![0; SIZE]);
        gpt::mbr::ProtectiveMBR::with_lb_size((SIZE / 512 - 1) as u32)
            .overwrite_lba0(&mut bytes)
            .unwrap();
        let mut disk = gpt::GptConfig::new()
            .writable(true)
            .create_from_device(bytes, None)
            .unwrap();
        for kind in types {
            disk.add_partition("root", 1024 * 1024, kind.clone(), 0, Some(2048))
                .unwrap();
        }
        Self {
            bytes: disk.write().unwrap(),
        }
    }

    fn read(&mut self) -> io::Result<Disk> {
        Disk::read(&mut self.bytes, SIZE as u64)
    }

    fn headers(&mut self, edit: impl FnOnce(&mut Header, &mut Header)) {
        let mut primary = Disk::header(&mut self.bytes, 1).unwrap();
        let mut backup = Disk::header(&mut self.bytes, primary.backup_lba).unwrap();
        edit(&mut primary, &mut backup);
        primary.write_primary(&mut self.bytes, BLOCK_SIZE).unwrap();
        backup.write_backup(&mut self.bytes, BLOCK_SIZE).unwrap();
    }

    fn entries(&mut self, edit: impl FnOnce(&mut BTreeMap<u32, Entry>)) {
        let disk = gpt::GptConfig::new()
            .writable(true)
            .open_from_device(&mut self.bytes)
            .unwrap();
        let primary = disk.primary_header().unwrap().clone();
        let backup = disk.backup_header().unwrap().clone();
        let mut entries = disk.partitions().clone();
        drop(disk);
        edit(&mut entries);
        for (index, entry) in entries {
            for start in [primary.part_start, backup.part_start] {
                entry
                    .write_to_device(
                        &mut self.bytes,
                        u64::from(index - 1),
                        start,
                        BLOCK_SIZE,
                        128,
                    )
                    .unwrap();
            }
        }
        self.headers(|_, _| {});
    }
}

#[test]
fn selects_native_root_and_optional_esp() {
    let mut fixture = Fixture::new(&[
        partition_types::LINUX_ROOT_X64,
        partition_types::EFI,
        partition_types::LINUX_ROOT_ARM_64,
    ]);
    let disk = fixture.read().unwrap();
    assert_eq!(disk.sectors(), SIZE as u64 / 512);
    assert_eq!(
        disk.root(Architecture::X86_64).unwrap(),
        Partition {
            start: 2048,
            sectors: 2048
        }
    );
    assert_eq!(disk.esp().unwrap().unwrap().start, 4096);
    assert_eq!(disk.root(Architecture::Aarch64).unwrap().start, 6144);

    let disk = Fixture::new(&[partition_types::LINUX_ROOT_ARM_64])
        .read()
        .unwrap();
    assert!(disk.root(Architecture::X86_64).is_err());
    assert!(disk.esp().unwrap().is_none());
}

#[test]
fn bounded_disk_can_live_inside_a_larger_carapace() {
    let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
    let disk = Disk::read(&mut fixture.bytes, crate::ZERO_SIZE_BYTES).unwrap();
    assert_eq!(disk.sectors(), SIZE as u64 / 512);
    // No read may depend on the enormous tail of the backing device.
    assert_eq!(fixture.bytes.get_ref().len(), SIZE);
    assert!(Disk::read(&mut fixture.bytes, SIZE as u64 - 512).is_err());
    assert!(Disk::read(&mut fixture.bytes, crate::ZERO_SIZE_BYTES + 512).is_err());
    assert!(Disk::read(&mut fixture.bytes, SIZE as u64 + 1).is_err());
}

#[test]
fn rejects_ambiguous_roots_and_honors_no_auto() {
    let mut fixture = Fixture::new(&[
        partition_types::LINUX_ROOT_X64,
        partition_types::LINUX_ROOT_X64,
    ]);
    assert!(fixture.read().unwrap().root(Architecture::X86_64).is_err());
    fixture.entries(|entries| entries.get_mut(&1).unwrap().flags = NO_AUTO);
    assert_eq!(
        fixture
            .read()
            .unwrap()
            .root(Architecture::X86_64)
            .unwrap()
            .start,
        4096
    );
    fixture.entries(|entries| entries.get_mut(&2).unwrap().flags = NO_AUTO);
    assert!(fixture.read().unwrap().root(Architecture::X86_64).is_err());
    let disk = Fixture::new(&[partition_types::EFI, partition_types::EFI])
        .read()
        .unwrap();
    assert!(disk.esp().is_err());
}

#[test]
fn checks_both_headers_and_tables_without_repair() {
    for offset in [512 + 56, SIZE - 512 + 56, 1024, SIZE - 33 * 512] {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
        fixture.bytes.get_mut()[offset] ^= 1;
        let before = fixture.bytes.get_ref().clone();
        assert!(fixture.read().is_err(), "accepted corruption at {offset}");
        assert_eq!(*fixture.bytes.get_ref(), before);
    }
    let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
    fixture.headers(|_, backup| backup.disk_guid = uuid::Uuid::new_v4());
    assert!(fixture
        .read()
        .unwrap_err()
        .to_string()
        .contains("headers disagree"));
}

#[test]
fn rejects_unsupported_geometry_before_partition_decoding() {
    // These headers have correct CRCs; their entry geometry is still invalid.
    for (size, count) in [(64, 128), (256, 128), (128, 0), (128, MAX_ENTRIES + 1)] {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
        // Only update the primary: the writer reads count*size bytes to compute
        // its checksum, so this fixture leaves ample readable zero-filled space.
        let mut primary = Disk::header(&mut fixture.bytes, 1).unwrap();
        primary.part_size = size;
        primary.num_parts = count;
        primary
            .write_primary(&mut fixture.bytes, BLOCK_SIZE)
            .unwrap();
        assert!(fixture.read().unwrap_err().to_string().contains("geometry"));
    }
}

#[test]
fn rejects_out_of_bounds_overlapping_and_nonunique_partitions() {
    for mode in 0..5 {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64, partition_types::EFI]);
        fixture.entries(|entries| {
            let first = entries[&1].clone();
            let entry = entries.get_mut(&2).unwrap();
            match mode {
                0 => entry.first_lba = first.last_lba,
                1 => entry.last_lba = SIZE as u64 / 512,
                2 => entry.first_lba = entry.last_lba + 1,
                3 => entry.part_guid = first.part_guid,
                4 => entry.part_guid = uuid::Uuid::nil(),
                _ => unreachable!(),
            }
        });
        assert!(
            fixture.read().is_err(),
            "accepted malformed partition case {mode}"
        );
    }
}

#[test]
fn rejects_metadata_inside_partitions_and_unbounded_addresses() {
    for mode in 0..4 {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
        let mut primary = Disk::header(&mut fixture.bytes, 1).unwrap();
        match mode {
            0 => primary.first_usable = 2,
            1 => primary.last_usable = SIZE as u64 / 512 - 1,
            2 => primary.backup_lba = u64::MAX,
            3 => primary.revision = (2, 0),
            _ => unreachable!(),
        }
        primary
            .write_primary(&mut fixture.bytes, BLOCK_SIZE)
            .unwrap();
        assert!(fixture.read().is_err());
    }
}

#[test]
fn rejects_truncated_and_nonprotective_disks() {
    for length in [0, 512, 1023, SIZE - 1] {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
        fixture.bytes.get_mut().truncate(length);
        assert!(fixture.read().is_err());
    }
    for offset in [510, 446 + 4, 446 + 8, 446 + 12, 462 + 4] {
        let mut fixture = Fixture::new(&[partition_types::LINUX_ROOT_X64]);
        fixture.bytes.seek(SeekFrom::Start(offset)).unwrap();
        fixture.bytes.write_all(&[0x83]).unwrap();
        assert!(fixture.read().is_err(), "accepted invalid MBR at {offset}");
    }
}
