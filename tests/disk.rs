// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Interoperability with an independent GPT implementation; no mounts required.
#![cfg(feature = "disk")]

use carapace::disk::{Architecture, Disk, Layout};
use std::process::Command;

#[test]
#[ignore = "requires sgdisk"]
fn standard_tools_read_and_update_the_disk() {
    let layout = Layout::new(
        Architecture::X86_64,
        16 * 1024 * 1024,
        Some(64 * 1024 * 1024),
    )
    .unwrap();
    let mut image = tempfile::NamedTempFile::new().unwrap();
    layout.write(image.as_file_mut(), layout.bytes()).unwrap();
    let verify = Command::new("sgdisk")
        .arg("--verify")
        .arg(image.path())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("No problems found"),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );

    // Change architecture with the independent tool, then read its checksums
    // and partition data through the production reader.
    let update = Command::new("sgdisk")
        .arg("--typecode=2:b921b045-1df0-41c3-af44-4c6f280d3fae")
        .arg(image.path())
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "{}",
        String::from_utf8_lossy(&update.stderr)
    );
    let disk = Disk::read(image.as_file_mut(), layout.bytes()).unwrap();
    assert!(disk.root(Architecture::X86_64).is_err());
    assert_eq!(
        disk.root(Architecture::Aarch64).unwrap().sectors,
        16 * 1024 * 1024 / 512
    );
    assert_eq!(disk.esp().unwrap().unwrap().sectors, 64 * 1024 * 1024 / 512);
}
