// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Kernel UAPI mirrors + iocuddle ioctl-number declarations. This is
//! the ONLY file in the crate that needs `#![allow(unsafe_code)]` — all
//! 4 unsafe blocks are iocuddle const constructors.
//!
//! Raw structs (`dm_ioctl_raw`, `dm_target_spec_raw`) are `pub(super)`
//! so the safe wrappers in `dm::mod` can use them, but they remain
//! invisible to the rest of the crate. The wrappers (`DmHeader`,
//! `DmTableBuf`) uphold every invariant iocuddle requires of the
//! ioctl-argument types.
//!
//! The loop-device ioctls (`<linux/loop.h>`) live here too — same
//! confinement: the raw `loop_config_raw` / `loop_info64_raw` mirrors
//! are `pub(super)`, and `loopdev.rs` drives them through safe wrappers.

#![allow(unsafe_code)]

use core::ffi::c_void;
use iocuddle::{Group, Ioctl, Write, WriteRead};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub(super) const DM_NAME_LEN: usize = 128;
pub(super) const DM_UUID_LEN: usize = 129;
pub(super) const DM_MAX_TYPE_NAME: usize = 16;

pub(super) const DM_IOCTL_VERSION_MAJOR: u32 = 4;

/// Mirror of `struct dm_ioctl` from `<linux/dm-ioctl.h>`. Visible only
/// to the parent `dm` module (raw types do NOT cross the dm boundary).
/// Sizeof locked at 312 bytes by the unit test in `dm::mod`.
///
/// Field order is byte-for-byte identical to the kernel UAPI; `name` /
/// `uuid` / `data` are `[u8; N]` rather than `[c_char; N]` because we
/// target Linux only (carapace's IMP-05 floor).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(super) struct dm_ioctl_raw {
    pub version: [u32; 3],
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; DM_NAME_LEN],
    pub uuid: [u8; DM_UUID_LEN],
    pub data: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<dm_ioctl_raw>() == 312);

/// Mirror of `struct dm_target_spec` from `<linux/dm-ioctl.h>`.
/// Sizeof locked at 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(super) struct dm_target_spec_raw {
    pub sector_start: u64,
    pub length: u64,
    pub status: i32,
    pub next: u32,
    pub target_type: [u8; DM_MAX_TYPE_NAME],
}

const _: () = assert!(core::mem::size_of::<dm_target_spec_raw>() == 40);

/// `sizeof(dm_target_spec)` — 40 bytes. Exposed so the
/// `DM_TABLE_STATUS` reply parser in `device` can step over the fixed
/// per-target spec record to reach the trailing status string without
/// re-deriving the layout.
pub(super) const DM_TARGET_SPEC_SIZE: usize = core::mem::size_of::<dm_target_spec_raw>();

pub(super) mod dm_flags {
    pub(crate) const READONLY: u32 = 1 << 0;
    pub(crate) const SUSPEND: u32 = 1 << 1;
}

const DM_IOCTL_GROUP: Group = Group::new(0xfd);

// SAFETY: every dm-ioctl is `_IOWR(0xfd, N, struct dm_ioctl)` per
// `<linux/dm-ioctl.h>`. We declare against `&DmHeader` (defined in
// dm::mod) which is `#[repr(transparent)]` over `dm_ioctl_raw` — same
// memory layout, but the newtype confines mutation to its safe
// constructors. This satisfies iocuddle's "T provides safe wrappers
// around its raw contents" contract.
pub(super) const DM_DEV_CREATE: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(3) };
pub(super) const DM_DEV_REMOVE: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(4) };
pub(super) const DM_DEV_SUSPEND: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(6) };
pub(super) const DM_TABLE_LOAD: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(9) };
pub(super) const DM_LIST_DEVICES: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(2) };
pub(super) const DM_TABLE_STATUS: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(12) };

/// `DM_BUFFER_FULL_FLAG` from `<linux/dm-ioctl.h>`. Set in
/// `dm_ioctl.flags` by the kernel when our supplied payload buffer
/// for `DM_LIST_DEVICES` (or `DM_TABLE_STATUS`) was too small to hold
/// the full reply.
pub(super) const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;

// ---------------------------------------------------------------------
// loop-device UAPI (`<linux/loop.h>`)
//
// conglobate backs the dm-snapshot COW exception store with a RAM-held
// file (tmpfs) exposed as a block device via a loop device — `loop` is
// in every kernel, unlike `brd`. carapace-dm already owns the block/dm
// ioctls, so loop setup lives here under the same iocuddle paradigm:
// the raw struct mirrors are `pub(super)`, and `loopdev.rs` drives them
// through a safe wrapper.
// ---------------------------------------------------------------------

pub(super) const LO_NAME_SIZE: usize = 64;
pub(super) const LO_KEY_SIZE: usize = 32;

/// 4096-byte logical block size for the loop device. Matches the
/// dm-snapshot / erofs page granularity conglobate works in.
pub(super) const LOOP_BLOCK_SIZE: u32 = 4096;

/// Mirror of `struct loop_info64` from `<linux/loop.h>`. Field order is
/// byte-for-byte identical to the kernel UAPI. Sizeof locked at 200
/// bytes by the unit test in `loopdev`.
///
/// `loopdev.rs` zeroes the whole struct and sets nothing — offset 0,
/// no flags — so the only fields that ever carry meaning here are the
/// kernel-set read-only ones (which we ignore). Kept as a complete
/// mirror so `loop_config_raw` has the correct overall size/layout.
///
/// Sizeof is 232 bytes (5×u64 + 4×u32 + 64 + 64 + 32 + 2×u64).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(super) struct loop_info64_raw {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: u32,
    pub lo_file_name: [u8; LO_NAME_SIZE],
    pub lo_crypt_name: [u8; LO_NAME_SIZE],
    pub lo_encrypt_key: [u8; LO_KEY_SIZE],
    pub lo_init: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<loop_info64_raw>() == 232);

/// Mirror of `struct loop_config` from `<linux/loop.h>` — the argument
/// to `LOOP_CONFIGURE`. Sizeof locked at 272 bytes.
///
/// `fd` is the backing-file descriptor, `block_size` the logical block
/// size, `info` an embedded `loop_info64`, and `__reserved` zeroed.
/// Visible only to the parent crate; `loopdev::LoopConfig` is the safe
/// `#[repr(transparent)]` newtype iocuddle's typed call references.
///
/// Sizeof is 304 bytes (u32 + u32 + 232 + 8×u64).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(super) struct loop_config_raw {
    pub fd: u32,
    pub block_size: u32,
    pub info: loop_info64_raw,
    pub __reserved: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<loop_config_raw>() == 304);

// The loop ioctls are `_IO('L', N)` — bare request numbers with no
// size/direction encoding (the kernel does NOT use `_IOR`/`_IOW` for
// them). iocuddle's `Group::{none,read,write,write_read}` would all
// re-encode size+dir into the request, producing the wrong number, so
// we construct each via `Ioctl::classic(request)` with the literal
// value from `<linux/loop.h>` and pick the typed wrapper that matches
// the kernel's actual argument convention.

/// `LOOP_CTL_GET_FREE` on `/dev/loop-control`. Takes no argument; the
/// free loop index is the (positive) ioctl return value.
///
/// SAFETY: `_IO(0x4C, 0x82)` per `<linux/loop.h>` — no argument is read
/// or written through a pointer, so the `c_void` (null-arg) typed call
/// is the correct, sound binding. The return value is the loop number.
pub(super) const LOOP_CTL_GET_FREE: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x4C82) };

/// `LOOP_CONFIGURE` on `/dev/loopN`. Atomically attaches a backing file
/// and applies status in one call (preferred over `LOOP_SET_FD` +
/// `LOOP_SET_STATUS64`).
///
/// SAFETY: `_IO(0x4C, 0x0A)` per `<linux/loop.h>`. The kernel reads a
/// `struct loop_config` through the argument pointer; we declare it
/// against `&LoopConfig`, a `#[repr(transparent)]` newtype over
/// `loop_config_raw` (same layout) whose safe constructor confines all
/// field writes. This satisfies iocuddle's "T provides safe wrappers"
/// contract.
pub(super) const LOOP_CONFIGURE: Ioctl<Write, &super::loopdev::LoopConfig> =
    unsafe { Ioctl::classic(0x4C0A) };

/// `LOOP_CLR_FD` on `/dev/loopN`. Detaches the backing file. Takes no
/// argument.
///
/// SAFETY: `_IO(0x4C, 0x01)` per `<linux/loop.h>` — no pointer
/// argument, so the `c_void` (null-arg) typed call is sound.
pub(super) const LOOP_CLR_FD: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x4C01) };
