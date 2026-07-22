// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Init mode — the entire initramfs PID1, distro-agnostic.
//!
//! When the `carapace` binary is the initramfs init (`rdinit=/init`, the kernel
//! default), it does exactly four things and nothing else:
//!
//!   1. mount `/proc`, `/sys`, `/dev` (devtmpfs) and reopen the console;
//!   2. load every module the initramfs ships (whatever this kernel lacks);
//!   3. read `carapacehash=` (+ `root`/`rootfstype`/`init`) from the cmdline;
//!   4. assemble the carapace into `/dev/mapper/root` and `switch_root` into it.
//!
//! Optionally, when `carapace.timing` is on the cmdline, it prints one boot
//! timing marker just before the pivot (otherwise it is silent except on the
//! fatal path).
//!
//! No systemd, no udev: carapace resolves partitions from `/sys` (kernel GPT
//! partscan) and makes its own `/dev/mapper` node, so the whole initramfs is
//! this one static binary plus a handful of `.ko`. The heavy lifting reuses the
//! library ([`carapace::attach`]); this module only orchestrates and parses.

use std::process::ExitCode;
use std::time::{Duration, Instant};

mod modules;
mod sys;

/// dm name / mount contract: `root=/dev/mapper/root`.
const DEV_NAME: &str = "root";
/// How long to wait for the block layer to partscan the carapace partitions
/// (device probe is asynchronous; PARTUUIDs appear in `/sys` shortly after).
const PARTITION_WAIT: Duration = Duration::from_secs(5);

/// True when the kernel ran us as the initramfs init (arg0 `/init`, or any
/// path whose basename is `init`).
pub(crate) fn invoked_as_init(arg0: &str) -> bool {
    arg0 == "/init"
        || std::path::Path::new(arg0)
            .file_name()
            .and_then(|s| s.to_str())
            == Some("init")
}

/// Init entry point. On success it never returns (it `execv`s the real init);
/// on any failure PID1 must not exit, so we log to the console and power off.
pub(crate) fn run() -> ExitCode {
    if let Err(e) = boot() {
        sys::write_console(&format!("\ncarapace init: FATAL: {e}\npowering off.\n"));
        sys::poweroff();
    }
    ExitCode::FAILURE // unreachable: boot() execs, or poweroff() diverges
}

fn boot() -> Result<(), String> {
    sys::mount_api()?;
    sys::reopen_console();
    modules::load_all("/usr/lib/modules")?;

    let cmdline =
        std::fs::read_to_string("/proc/cmdline").map_err(|e| format!("read /proc/cmdline: {e}"))?;

    let hash = value(&cmdline, "carapacehash")
        .or_else(|| value(&cmdline, "root.carapace"))
        .ok_or("no carapacehash= on the kernel command line")?;
    if hash.len() < 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "carapacehash must be lowercase hex of at least 64 chars, got {hash:?}"
        ));
    }
    let rootfstype = value(&cmdline, "rootfstype").unwrap_or("ext4");
    let init = value(&cmdline, "init").unwrap_or("/sbin/init");
    // Opt-in boot timing: silent by default (a minimal PID1 speaks only on the
    // fatal path); `carapace.timing` on the cmdline prints the switch_root mark.
    let timing = has_flag(&cmdline, "carapace.timing");

    attach_with_retry(hash)?;
    sys::mount_root(&format!("/dev/mapper/{DEV_NAME}"), "/sysroot", rootfstype)?;
    if timing {
        sys::mark_switch_root(); // timing boundary: launch → root ready
    }
    sys::switch_root("/sysroot", init)?; // never returns on success
    Err("switch_root returned unexpectedly".into())
}

/// Assemble the carapace, retrying only while the partitions haven't been
/// partscanned yet. `attach` scans `/sys` before touching dm, so a
/// `PartitionNotFound` early in boot is a race we can wait out; any other error
/// (bad hash, chain rejection, ioctl failure) fails immediately.
fn attach_with_retry(hash: &str) -> Result<(), String> {
    let deadline = Instant::now() + PARTITION_WAIT;
    loop {
        match carapace::attach(DEV_NAME, hash) {
            Ok(_) => return Ok(()),
            Err(e) if is_partition_not_found(&e) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("carapace attach: {e}")),
        }
    }
}

fn is_partition_not_found(e: &carapace::CarapaceError) -> bool {
    matches!(e, carapace::CarapaceError::PartitionNotFound { .. })
}

/// Last-occurrence-wins `key=value` lookup on the kernel command line (systemd
/// convention). The explicit `=` check keeps `root` from matching `rootfstype`.
fn value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    let mut found = None;
    for tok in cmdline.split_whitespace() {
        if let Some(v) = tok.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            if !v.is_empty() {
                found = Some(v);
            }
        }
    }
    found
}

/// True if a bare boolean flag is present on the command line — either as a lone
/// token (`carapace.timing`) or with a value (`carapace.timing=1`). Exact token
/// match, so it is not confused by a longer key that shares the prefix.
fn has_flag(cmdline: &str, key: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|tok| tok == key || tok.strip_prefix(key).is_some_and(|r| r.starts_with('=')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_dispatch() {
        assert!(invoked_as_init("/init"));
        assert!(invoked_as_init("init"));
        assert!(!invoked_as_init("/usr/bin/carapace"));
        assert!(!invoked_as_init("carapace"));
    }

    #[test]
    fn cmdline_value_last_wins_and_exact_key() {
        let c = "console=hvc0 root=/dev/mapper/root rootfstype=ext4 carapacehash=dead carapacehash=beef";
        assert_eq!(value(c, "carapacehash"), Some("beef")); // last wins
        assert_eq!(value(c, "rootfstype"), Some("ext4"));
        assert_eq!(value(c, "root"), Some("/dev/mapper/root")); // not confused by rootfstype
        assert_eq!(value(c, "init"), None);
        assert_eq!(value("carapacehash=", "carapacehash"), None); // empty ignored
    }

    #[test]
    fn cmdline_flag_bare_and_valued_and_exact() {
        assert!(has_flag("quiet carapace.timing ro", "carapace.timing")); // bare
        assert!(has_flag("carapace.timing=1", "carapace.timing")); // with value
        assert!(!has_flag("quiet ro", "carapace.timing")); // absent
        assert!(!has_flag("carapace.timingx", "carapace.timing")); // not a prefix match
    }
}
