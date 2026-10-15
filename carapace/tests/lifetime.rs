// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! File ownership, shared mappings, caller-managed async assembly, and writable derivation.
#![cfg(all(target_os = "linux", feature = "gpt"))]

mod common;

use carapace::{Assemble, Chain, DevId, FromGpt};
use common::{build_chain, carapace_devices_present, decode_hex, with_mounted, AttachedImage};
use devmap_linux::records::Records;
use serial_test::serial;
use std::fs::{File, OpenOptions};
use std::io::Seek;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::Duration;

fn available() -> bool {
    let available =
        devmap_linux::Control::open().is_ok() && File::open("/dev/loop-control").is_ok();
    if !available {
        eprintln!("skip: requires device-mapper and loop access");
    }
    available
}

fn fixture(layers: usize) -> (tempfile::TempDir, AttachedImage, Chain) {
    let dir = tempfile::tempdir().unwrap();
    let built = build_chain(&dir.path().join("image"), layers);
    let attached = AttachedImage::attach(&built.image);
    let chain = Chain::from_gpt(&decode_hex(&built.trusted_root_hex).unwrap()).unwrap();
    (dir, attached, chain)
}

fn node(file: &File) -> PathBuf {
    let id = DevId::try_from(file.metadata().unwrap()).unwrap();
    PathBuf::from(format!("/dev/dm-{}", id.minor()))
}

fn torn_down() {
    assert!(
        !carapace_devices_present(Duration::from_secs(5)),
        "mapping leaked"
    );
}

#[test]
#[serial]
fn clones_repeated_assembly_and_mount_retain_the_device() {
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(2);
    let mut first = chain.assemble().unwrap();
    assert_eq!(first.stream_position().unwrap(), 0);
    let clone = first.try_clone().unwrap();
    let second = chain.assemble().unwrap();
    assert_eq!(node(&first), node(&second));
    assert!(first.write_all_at(&[0; 512], 0).is_err());
    // Some kernels allow a writable open of a read-only block device and
    // enforce the restriction at write time instead.
    if let Ok(writer) = OpenOptions::new().write(true).open(node(&first)) {
        assert!(writer.write_all_at(&[0; 512], 0).is_err());
    }
    drop(first);
    drop(second);
    let path = node(&clone);
    with_mounted(&path, move |mount| {
        drop(clone);
        assert_eq!(
            std::fs::read_to_string(mount.join("scute0.txt")).unwrap(),
            "modified by scute1\n"
        );
    });
    torn_down();
}

#[test]
#[serial]
fn overlapping_chains_share_lower_mappings() {
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(2);
    let mut parent_root = [0; 32];
    File::open(&chain.layers[1].hash)
        .unwrap()
        .read_exact_at(&mut parent_root, 88)
        .unwrap();
    let parent = Chain {
        root: parent_root.into(),
        layers: chain.layers[..1].to_vec(),
    };
    let lower = parent.assemble().unwrap();
    let upper = chain.assemble().unwrap();
    let control = devmap_linux::Control::open().unwrap();
    let upper_id = DevId::try_from(upper.metadata().unwrap()).unwrap();
    let lower_id = DevId::try_from(lower.metadata().unwrap()).unwrap();
    let mut deps = control.deps::<4096>(upper_id).unwrap();
    let mut found = false;
    while let Some(dep) = deps.next() {
        if dep.unwrap() == lower_id {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "upper mapping must depend on the shared lower device"
    );
    drop(lower);
    with_mounted(&node(&upper), |mount| {
        assert!(mount.join("scute1.txt").exists());
    });
    drop(upper);
    torn_down();
}

#[test]
#[serial]
fn concurrent_assembly_publishes_one_stack() {
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(2);
    let files = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| chain.assemble().unwrap()))
            .collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    for file in &files {
        assert_eq!(node(file), node(&files[0]));
    }
    drop(files);
    torn_down();
}

#[test]
#[serial]
fn failure_after_creating_a_lower_layer_cleans_up() {
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(2);
    // Change only the trusted top root; direct construction bypasses GPT
    // lookup, so lower mappings are created before the verified read fails.
    let mut wrong = chain.clone();
    wrong.root[0] ^= 1;
    assert!(wrong.assemble().is_err());
    torn_down();
    // A failed second assembly must not tear down another caller's stack.
    let good = chain.assemble().unwrap();
    assert!(wrong.assemble().is_err());
    with_mounted(&node(&good), |mount| {
        assert!(mount.join("scute1.txt").exists());
    });
    drop(good);
    torn_down();
}

#[cfg(feature = "loop")]
#[test]
#[serial]
fn file_backed_layers_autoclear_on_last_close() {
    if !available() {
        return;
    }
    let (dir, attached, mut chain) = fixture(1);
    let data = dir.path().join("data");
    let hash = dir.path().join("hash");
    std::io::copy(
        &mut File::open(&chain.layers[0].data).unwrap(),
        &mut File::create(&data).unwrap(),
    )
    .unwrap();
    std::io::copy(
        &mut File::open(&chain.layers[0].hash).unwrap(),
        &mut File::create(&hash).unwrap(),
    )
    .unwrap();
    chain.layers[0] = carapace::Layer {
        data: data.clone(),
        hash: hash.clone(),
    };
    drop(attached);
    let first = chain.assemble().unwrap();
    let second = chain.assemble().unwrap();
    drop(first);
    with_mounted(&node(&second), |mount| {
        assert!(mount.join("scute0.txt").exists());
    });
    drop(second);
    torn_down();
    assert!(!common::loop_bound_to(&data, Duration::from_secs(5)));
    assert!(!common::loop_bound_to(&hash, Duration::from_secs(5)));
}

#[cfg(feature = "loop")]
#[test]
#[serial]
fn writable_snapshot_keeps_origin_immutable_and_alive() {
    use devmap_core::{BlockSize, Span};
    use devmap_linux::targets::Target;
    use devmap_linux::Table;
    use devmap_snapshot::{
        Discard, Parameters as SnapshotParameters, Persistence, Persistent, Snapshot,
    };

    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(1);
    let origin = chain.assemble().unwrap();
    let mut original = [0; 4096];
    origin.read_exact_at(&mut original, 4096).unwrap();
    let backing = tempfile::tempfile().unwrap();
    backing.set_len(16 * 1024 * 1024).unwrap();
    let config = lodown::Configurable {
        writable: lodown::Writable {
            autoclear: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let cow = lodown::Control::open()
        .unwrap()
        .attach(&backing, 0, config)
        .unwrap();
    let origin_id = DevId::try_from(origin.metadata().unwrap()).unwrap();
    let snapshot = Snapshot::from(SnapshotParameters {
        origin: origin_id,
        cow: DevId::try_from(cow.as_ref().metadata().unwrap()).unwrap(),
        persistence: Persistence::Persistent(Persistent::Standard),
        chunk_size: BlockSize::default(),
        discard: Discard::Disabled,
    });
    let control = devmap_linux::Control::open().unwrap();
    let id = control.create("CARAPACE-test-writable").unwrap();
    let version = control.version(Snapshot::NAME).unwrap();
    let table = Table::<4096>::default()
        .add(Span::new(0, 2048), &snapshot, version)
        .unwrap();
    control.load(id, table, false).unwrap();
    control.suspend(id, false).unwrap();
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{}", id.minor()))
        .unwrap();
    control.remove(id, true).unwrap();
    drop(cow);
    let changed = original.map(|byte| byte ^ 0xff);
    writable.write_all_at(&changed, 4096).unwrap();
    writable.sync_all().unwrap();
    let mut actual = [0; 4096];
    writable.read_exact_at(&mut actual, 4096).unwrap();
    assert_eq!(actual, changed);
    origin.read_exact_at(&mut actual, 4096).unwrap();
    assert_eq!(actual, original);
    drop(origin);
    let retained_origin = File::open(format!("/dev/dm-{}", origin_id.minor())).unwrap();
    retained_origin.read_exact_at(&mut actual, 4096).unwrap();
    assert_eq!(actual, original);
    drop(retained_origin);
    drop(writable);
    torn_down();
}

#[cfg(feature = "tokio")]
#[test]
#[serial]
fn async_discovery_and_caller_managed_assembly() {
    use carapace::AsyncFromGpt;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(2);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let discovered = <Chain as AsyncFromGpt>::from_gpt(&chain.root)
            .await
            .unwrap();
        assert_eq!(discovered.root, chain.root);
        for (actual, expected) in discovered.layers.iter().zip(&chain.layers) {
            assert_eq!(actual.data, expected.data);
            assert_eq!(actual.hash, expected.hash);
        }
        let file = tokio::task::spawn_blocking(move || discovered.assemble())
            .await
            .unwrap()
            .unwrap();
        let mut file = tokio::fs::File::from_std(file);
        let id = DevId::try_from(file.metadata().await.unwrap()).unwrap();
        assert_eq!(file.stream_position().await.unwrap(), 0);
        let mut bytes = [0; 4096];
        file.read_exact(&mut bytes).await.unwrap();
        with_mounted(&PathBuf::from(format!("/dev/dm-{}", id.minor())), |mount| {
            assert!(mount.join("scute1.txt").exists());
        });
        drop(file);
    });
    torn_down();
}

#[test]
#[serial]
fn conflicting_mapping_is_rejected_without_reloading_or_removing_it() {
    use devmap_core::Span;
    use devmap_linux::records::Records;
    use devmap_linux::targets::{Target, Zero};
    use devmap_linux::Table;
    if !available() {
        return;
    }
    let (_dir, _attached, chain) = fixture(1);
    let control = devmap_linux::Control::open().unwrap();
    let id = control.create("CARAPACE-z").unwrap();
    // An existing device with the expected name but the wrong extent.
    let version = control.version(Zero::NAME).unwrap();
    let table = Table::<4096>::default()
        .add(Span::new(0, 8), &Zero, version)
        .unwrap();
    control.load(id, table, true).unwrap();
    control.suspend(id, false).unwrap();
    let error = chain.assemble().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("different table"));
    let mut rows = control.table::<4096>(id).unwrap();
    assert_eq!(rows.next().unwrap().unwrap().span().length, 8);
    control.remove(id, false).unwrap();
    torn_down();
}
