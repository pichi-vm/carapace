// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! dm-verity superblock parser.
//!
//! Parse-and-validate in one step — `RawVeritySuperblock` is private; the
//! only path from `&[u8]` to a typed view is
//! [`ValidatedVeritySuperblock::parse`], which enforces the entire RDP
//! whitelist before returning. Downstream code never sees partially-
//! validated data (PITFALLS CRITICAL-2 / CRITICAL-3 prevention).
//!
//! On-disk layout (mirrors cryptsetup `lib/verity/verity.c`, total 512 B,
//! all numeric fields little-endian):
//!
//!   signature[8] | version u32 | hash_type u32 | uuid[16] | algorithm[32]
//!   | data_block_size u32 | hash_block_size u32 | data_blocks u64
//!   | salt_size u16 | _pad1[6] | salt[256] | _pad2[168]

use crate::verity::algorithm::{self, Algorithm};
use std::io;
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub(crate) const VERITY_SUPERBLOCK_SIZE: usize = 512;
pub(crate) const VERITY_SIGNATURE: [u8; 8] = *b"verity\0\0";

/// RDP-locked v1 chain parameters.
const RDP_DATA_BLOCK_SIZE: u32 = 4096;
const RDP_HASH_BLOCK_SIZE: u32 = 4096;
const RDP_HASH_TYPE: u32 = 1;
const RDP_VERSION: u32 = 1;

#[derive(FromBytes, KnownLayout, Immutable, Debug, Clone, Copy)]
#[repr(C)]
struct RawVeritySuperblock {
    signature: [u8; 8],
    version: U32,
    hash_type: U32,
    uuid: [u8; 16],
    algorithm: [u8; 32],
    data_block_size: U32,
    hash_block_size: U32,
    data_blocks: U64,
    salt_size: U16,
    _pad1: [u8; 6],
    salt: [u8; 256],
    _pad2: [u8; 168],
}

const _: () = assert!(core::mem::size_of::<RawVeritySuperblock>() == VERITY_SUPERBLOCK_SIZE);

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatedVeritySuperblock {
    pub algorithm: Algorithm,
    pub data_blocks: u64,
    salt_size: u16,
    salt_buf: [u8; 256],
}

impl ValidatedVeritySuperblock {
    /// Parse a 512-byte superblock buffer and enforce the full v1 RDP
    /// whitelist.
    ///
    /// `scute_index` is the chain position used for error attribution.
    pub(crate) fn parse(bytes: &[u8], scute_index: usize) -> io::Result<Self> {
        let invalid_data = |reason: String| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("scute {scute_index}: {reason}"),
            )
        };

        if bytes.len() < VERITY_SUPERBLOCK_SIZE {
            return Err(invalid_data(format!(
                "superblock: need {VERITY_SUPERBLOCK_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let raw = RawVeritySuperblock::ref_from_bytes(&bytes[..VERITY_SUPERBLOCK_SIZE])
            .map_err(|_| invalid_data("superblock: alignment / size".into()))?;

        if raw.signature != VERITY_SIGNATURE {
            return Err(invalid_data(format!(
                "superblock: signature {:?} != {:?}",
                raw.signature, VERITY_SIGNATURE
            )));
        }

        // -- whitelist (RDP equality on every scute) --
        let version = raw.version.get();
        if version != RDP_VERSION {
            return Err(invalid_data(format!(
                "whitelist: version = {version} (must be {RDP_VERSION})"
            )));
        }
        let hash_type = raw.hash_type.get();
        if hash_type != RDP_HASH_TYPE {
            return Err(invalid_data(format!(
                "whitelist: hash_type = {hash_type} (must be {RDP_HASH_TYPE})"
            )));
        }
        let dbs = raw.data_block_size.get();
        if dbs != RDP_DATA_BLOCK_SIZE {
            return Err(invalid_data(format!(
                "whitelist: data_block_size = {dbs} (must be {RDP_DATA_BLOCK_SIZE})"
            )));
        }
        let hbs = raw.hash_block_size.get();
        if hbs != RDP_HASH_BLOCK_SIZE {
            return Err(invalid_data(format!(
                "whitelist: hash_block_size = {hbs} (must be {RDP_HASH_BLOCK_SIZE})"
            )));
        }

        // Algorithm: parse cstring then check whitelist.
        let alg_str = cstr_to_str(&raw.algorithm)
            .map_err(|e| invalid_data(format!("superblock: algorithm field: {e}")))?;
        let algorithm = algorithm::parse(alg_str).map_err(|_| {
            invalid_data(format!(
                "whitelist: algorithm = {alg_str} (not whitelisted)"
            ))
        })?;
        let digest_size = algorithm.digest_size();

        // Salt size: digest_size <= salt_size <= 256.
        let salt_size = raw.salt_size.get();
        if salt_size as usize > raw.salt.len() {
            return Err(invalid_data(format!(
                "superblock: salt_size {salt_size} > salt field length {}",
                raw.salt.len()
            )));
        }
        if (salt_size as usize) < digest_size {
            return Err(invalid_data(format!(
                "whitelist: salt_size = {salt_size} < digest_size {digest_size}"
            )));
        }

        let data_blocks = raw.data_blocks.get();
        if data_blocks == 0 {
            return Err(invalid_data("superblock: data_blocks must be > 0".into()));
        }
        if data_blocks
            .checked_mul(RDP_DATA_BLOCK_SIZE as u64)
            .is_none()
        {
            return Err(invalid_data(format!(
                "superblock: data_blocks {data_blocks} * {RDP_DATA_BLOCK_SIZE} overflows u64"
            )));
        }

        Ok(Self {
            algorithm,
            data_blocks,
            salt_size,
            salt_buf: raw.salt,
        })
    }

    /// Full salt as fed to dm-verity hashing. Length = `salt_size`.
    pub(crate) fn full_salt(&self) -> &[u8] {
        &self.salt_buf[..self.salt_size as usize]
    }

    /// True iff this scute is the chain's base — detected by the
    /// `digest_size`-byte zero-prefix sentinel in the salt.
    #[cfg(feature = "gpt")]
    pub(crate) fn is_base(&self) -> bool {
        self.salt_buf[..self.algorithm.digest_size()]
            .iter()
            .all(|&b| b == 0)
    }
}

/// Read a NUL-terminated ASCII string out of a fixed-length field.
fn cstr_to_str(buf: &[u8]) -> Result<&str, &'static str> {
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("missing NUL terminator")?;
    std::str::from_utf8(&buf[..end]).map_err(|_| "non-UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth(
        algorithm: &str,
        version: u32,
        hash_type: u32,
        data_block_size: u32,
        hash_block_size: u32,
        salt_size: u16,
        salt_prefix: &[u8],
    ) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[..8].copy_from_slice(&VERITY_SIGNATURE);
        buf[8..12].copy_from_slice(&version.to_le_bytes());
        buf[12..16].copy_from_slice(&hash_type.to_le_bytes());
        let alg_bytes = algorithm.as_bytes();
        buf[32..32 + alg_bytes.len()].copy_from_slice(alg_bytes);
        buf[64..68].copy_from_slice(&data_block_size.to_le_bytes());
        buf[68..72].copy_from_slice(&hash_block_size.to_le_bytes());
        buf[72..80].copy_from_slice(&1u64.to_le_bytes()); // data_blocks
        buf[80..82].copy_from_slice(&salt_size.to_le_bytes());
        buf[88..88 + salt_prefix.len()].copy_from_slice(salt_prefix);
        buf
    }

    #[test]
    fn parses_canonical_sha256_non_base() {
        let prefix = [0xAA; 32];
        let sb = synth("sha256", 1, 1, 4096, 4096, 32, &prefix);
        let v = ValidatedVeritySuperblock::parse(&sb, 0).unwrap();
        assert_eq!(v.algorithm, Algorithm::Sha256);
        assert_eq!(v.full_salt().len(), 32);
        assert_eq!(&v.full_salt()[..32], &prefix[..]);
        assert!(!v.is_base(), "non-zero prefix means non-base");
    }

    #[test]
    fn parses_sha256_base_with_zero_prefix_and_random_suffix() {
        let mut salt = [0u8; 64];
        for (i, b) in salt[32..].iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let sb = synth("sha256", 1, 1, 4096, 4096, 64, &salt);
        let v = ValidatedVeritySuperblock::parse(&sb, 0).unwrap();
        assert!(v.is_base(), "all-zero prefix is the base sentinel");
        assert_eq!(v.full_salt().len(), 64);
    }

    #[test]
    fn parses_sha512_with_suffix() {
        let mut prefix = [0u8; 80];
        for (i, b) in prefix.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sb = synth("sha512", 1, 1, 4096, 4096, 80, &prefix);
        let v = ValidatedVeritySuperblock::parse(&sb, 1).unwrap();
        assert_eq!(v.algorithm, Algorithm::Sha512);
        assert_eq!(v.full_salt().len(), 80);
        assert_eq!(v.algorithm.digest_size(), 64);
        assert!(!v.is_base());
    }

    #[test]
    fn rejects_blocklisted_algorithms() {
        for alg in ["md5", "sha1", "sha224", "sha384", "sha3-256", "blake3"] {
            let prefix = [0xAA; 32];
            let sb = synth(alg, 1, 1, 4096, 4096, 32, &prefix);
            let r = ValidatedVeritySuperblock::parse(&sb, 0);
            assert!(
                matches!(r, Err(ref e) if e.kind() == io::ErrorKind::InvalidData),
                "{alg} should be rejected with InvalidData, got {r:?}"
            );
        }
    }

    #[test]
    fn rejects_off_rdp_block_size() {
        let prefix = [0xAA; 32];
        for dbs in [512u32, 1024, 2048, 8192, 0, 7] {
            let sb = synth("sha256", 1, 1, dbs, 4096, 32, &prefix);
            let e = ValidatedVeritySuperblock::parse(&sb, 0).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn rejects_hash_type_zero() {
        let prefix = [0xAA; 32];
        let sb = synth("sha256", 1, 0, 4096, 4096, 32, &prefix);
        let e = ValidatedVeritySuperblock::parse(&sb, 0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_version_zero() {
        let prefix = [0xAA; 32];
        let sb = synth("sha256", 0, 1, 4096, 4096, 32, &prefix);
        let e = ValidatedVeritySuperblock::parse(&sb, 0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_short_salt_uniformly() {
        let sb = synth("sha256", 1, 1, 4096, 4096, 0, &[]);
        let e = ValidatedVeritySuperblock::parse(&sb, 0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // sha512 needs salt_size >= 64.
        let sb = synth("sha512", 1, 1, 4096, 4096, 32, &[0; 32]);
        let e = ValidatedVeritySuperblock::parse(&sb, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_wrong_signature() {
        let mut sb = synth("sha256", 1, 1, 4096, 4096, 32, &[0xAA; 32]);
        sb[0..8].copy_from_slice(b"badmagic");
        let e = ValidatedVeritySuperblock::parse(&sb, 0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_data_blocks_overflow_on_block_size_multiply() {
        let mut sb = synth("sha256", 1, 1, 4096, 4096, 32, &[0xAA; 32]);
        sb[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        let r = ValidatedVeritySuperblock::parse(&sb, 0);
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("overflow")),
            "expected InvalidData('...overflow...'), got {r:?}"
        );
    }

    #[test]
    fn rejects_data_blocks_zero() {
        let mut sb = synth("sha256", 1, 1, 4096, 4096, 32, &[0xAA; 32]);
        sb[72..80].copy_from_slice(&0u64.to_le_bytes());
        let r = ValidatedVeritySuperblock::parse(&sb, 0);
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("data_blocks")),
            "expected InvalidData('...data_blocks...'), got {r:?}"
        );
    }

    #[test]
    fn rejects_algorithm_field_without_nul_terminator() {
        let mut sb = synth("sha256", 1, 1, 4096, 4096, 32, &[0xAA; 32]);
        for b in &mut sb[32..64] {
            *b = b'x';
        }
        let r = ValidatedVeritySuperblock::parse(&sb, 0);
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("NUL")),
            "expected InvalidData('...NUL...'), got {r:?}"
        );
    }
}
