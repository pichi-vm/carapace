// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `LoopDevice`: RAII-ish handle over an attached `/dev/loopN`.
//!
//! conglobate backs the dm-snapshot COW exception store with a RAM-held
//! file (a tmpfs file, pre-sized by the caller) exposed as a block
//! device. The historical choice — `/dev/ram{N}` (brd) — is unusable
//! because no Alpine kernel ships both `erofs` and `brd`; `loop` is in
//! every kernel. This module attaches such a file to a free loop device
//! and hands back the `/dev/loopN` path for use as a dm-table operand.
//!
//! Iocuddle paradigm (see [`crate::uapi`]): the raw `loop_config` /
//! `loop_info64` mirrors and the typed ioctl declarations live in
//! `uapi` (the only `#![allow(unsafe_code)]` module). Everything here
//! is safe code: it constructs the [`LoopConfig`] newtype through a
//! checked builder and issues the ioctls via the iocuddle wrappers.
//!
//! Attaching a loop device requires `CAP_SYS_ADMIN`; the unit tests
//! here therefore cover only layout/struct invariants, never a real
//! attach (that is exercised in the build VM / CI).

use super::uapi::{
    loop_config_raw, loop_info64_raw, LOOP_BLOCK_SIZE, LOOP_CLR_FD, LOOP_CONFIGURE,
    LOOP_CTL_GET_FREE,
};
use crate::DmError;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Safe wrapper over `struct loop_config` — the `LOOP_CONFIGURE`
/// argument. Hides the UAPI; the only constructor zeroes the whole
/// struct (offset 0, no flags, no encryption) and sets just `fd` and
/// `block_size`, the two fields conglobate's RAM-backed store needs.
///
/// `#[repr(transparent)]` guarantees identical layout to
/// `loop_config_raw` — required so iocuddle can pass `&LoopConfig` as
/// the ioctl argument.
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub(super) struct LoopConfig {
    inner: loop_config_raw,
}

impl LoopConfig {
    /// Configure a loop device backed by descriptor `fd` with a 4096-
    /// byte logical block size. `info` is fully zeroed: `lo_offset = 0`
    /// (the whole file), `lo_sizelimit = 0` (max available), no flags.
    fn new(fd: i32) -> Self {
        Self {
            inner: loop_config_raw {
                // The kernel reads `fd` as a __u32; descriptors are
                // small non-negative ints, so the cast is exact.
                fd: fd as u32,
                block_size: LOOP_BLOCK_SIZE,
                info: loop_info64_raw {
                    lo_device: 0,
                    lo_inode: 0,
                    lo_rdevice: 0,
                    lo_offset: 0,
                    lo_sizelimit: 0,
                    lo_number: 0,
                    lo_encrypt_type: 0,
                    lo_encrypt_key_size: 0,
                    lo_flags: 0,
                    lo_file_name: [0; super::uapi::LO_NAME_SIZE],
                    lo_crypt_name: [0; super::uapi::LO_NAME_SIZE],
                    lo_encrypt_key: [0; super::uapi::LO_KEY_SIZE],
                    lo_init: [0; 2],
                },
                __reserved: [0; 8],
            },
        }
    }
}

/// Open `/dev/loop-control` — the loop subsystem's allocator entry
/// point. One open per [`LoopDevice::attach`]; closed when this `File`
/// drops (we hold it only for the `LOOP_CTL_GET_FREE` call).
fn open_loop_control() -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
}

/// RAII handle over an attached `/dev/loopN`. Holds the open loop fd
/// (kept alive so the device node stays usable for its lifetime) and
/// the `/dev/loopN` path.
///
/// Cleanup is **explicit**: there is no `Drop`. The caller chooses
/// between [`LoopDevice::detach`] (issue `LOOP_CLR_FD`) and
/// [`LoopDevice::forget`] (leak the handle — the loop attachment
/// persists). conglobate runs as PID 1 in a VM that powers off rather
/// than tearing down, so the common path is `forget`; making cleanup
/// explicit (no silent best-effort `Drop`) keeps the detach failure
/// visible when it does matter.
#[derive(Debug)]
pub struct LoopDevice {
    /// Open fd on `/dev/loopN`. Kept for the lifetime of the handle so
    /// the configured device stays attached and addressable.
    dev: File,
    path: PathBuf,
}

impl LoopDevice {
    /// Attach `backing` — an existing, already-sized file — to a free
    /// loop device. Acquires a free index via `/dev/loop-control`
    /// `LOOP_CTL_GET_FREE`, opens `/dev/loopN`, and configures it with
    /// `LOOP_CONFIGURE` (offset 0, 4096-byte blocks).
    ///
    /// The backing file is opened read-write here only to obtain a
    /// descriptor for the configure call; the kernel dups what it needs
    /// and our handle is dropped before returning.
    pub fn attach(backing: &Path) -> Result<LoopDevice, DmError> {
        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(backing)
            .map_err(DmError::Io)?;

        let mut control = open_loop_control().map_err(DmError::Io)?;

        // LOOP_CTL_GET_FREE returns the free loop index as the ioctl
        // return value (no argument).
        let index = LOOP_CTL_GET_FREE
            .ioctl(&mut control)
            .map_err(|source| DmError::DmIoctl {
                op: "LOOP_CTL_GET_FREE",
                source,
                table_line: None,
            })?;

        let path = PathBuf::from(format!("/dev/loop{index}"));
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(DmError::Io)?;

        let config = LoopConfig::new(backing_file.as_raw_fd());
        LOOP_CONFIGURE
            .ioctl(&mut dev, &config)
            .map_err(|source| DmError::DmIoctl {
                op: "LOOP_CONFIGURE",
                source,
                table_line: None,
            })?;

        Ok(LoopDevice { dev, path })
    }

    /// The `/dev/loopN` device path. Use as a dm-table operand (e.g. the
    /// `cow` device of a `snapshot` target).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Detach the backing file via `LOOP_CLR_FD`, then close the device
    /// fd. Consumes the handle. Surfaces an error if the kernel refuses
    /// (e.g. the device is still in use by a dm target).
    pub fn detach(mut self) -> Result<(), DmError> {
        LOOP_CLR_FD
            .ioctl(&mut self.dev)
            .map_err(|source| DmError::DmIoctl {
                op: "LOOP_CLR_FD",
                source,
                table_line: None,
            })?;
        Ok(())
    }

    /// Opt out of cleanup: leak the handle so the loop attachment
    /// persists past this object. The device fd is intentionally
    /// dropped without `LOOP_CLR_FD` — conglobate's PID-1 caller powers
    /// the VM off rather than detaching.
    pub fn forget(self) {
        // Dropping `self` closes the held fd but issues no ioctl; the
        // loop device remains attached to its backing file.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizeof_loop_info64_raw() {
        assert_eq!(core::mem::size_of::<loop_info64_raw>(), 232);
    }

    #[test]
    fn sizeof_loop_config_raw() {
        assert_eq!(core::mem::size_of::<loop_config_raw>(), 304);
    }

    #[test]
    fn loopconfig_is_layout_identical_to_raw() {
        // #[repr(transparent)] guarantees this; assertion is a witness
        // to prevent future drift.
        assert_eq!(
            core::mem::size_of::<LoopConfig>(),
            core::mem::size_of::<loop_config_raw>()
        );
        assert_eq!(
            core::mem::align_of::<LoopConfig>(),
            core::mem::align_of::<loop_config_raw>()
        );
    }

    #[test]
    fn loopconfig_new_sets_fd_and_block_size_zeroes_rest() {
        let c = LoopConfig::new(7);
        assert_eq!(c.inner.fd, 7);
        assert_eq!(c.inner.block_size, LOOP_BLOCK_SIZE);
        assert_eq!(c.inner.info.lo_offset, 0);
        assert_eq!(c.inner.info.lo_flags, 0);
        assert_eq!(c.inner.__reserved, [0; 8]);
    }
}
