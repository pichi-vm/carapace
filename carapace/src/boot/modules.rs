// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Load every kernel module the initramfs ships — distro-agnostic. The image
//! build put in exactly what this kernel does NOT build in (for a stock Fedora
//! kernel that's ~just dm-verity; other distros ship more), so we simply load
//! them all.
//!
//! Dependency order is discovered by iteration rather than parsed from
//! `modules.dep`: each pass tries every not-yet-loaded module; ones whose
//! dependencies aren't loaded yet fail and are retried on the next pass. This
//! converges without shipping or parsing dep metadata. `finit_module` reports
//! `EEXIST` for already-loaded/builtin modules (treated as success by
//! [`super::sys::finit_module`]).

use std::path::{Path, PathBuf};

use super::sys;

/// Load all modules under `modroot` (typically `/usr/lib/modules`). A no-op if
/// the initramfs ships none (everything the kernel needs is builtin).
pub(super) fn load_all(modroot: &str) -> Result<(), String> {
    let mut pending = collect_kos(Path::new(modroot));
    while !pending.is_empty() {
        let before = pending.len();
        // Retain only the modules that still fail to load this pass.
        let mut still: Vec<PathBuf> = Vec::new();
        let mut last_err = String::new();
        for ko in pending {
            let compressed = ko
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "xz" | "gz" | "zst"));
            match sys::finit_module(&ko, compressed) {
                Ok(()) => {}
                Err(e) => {
                    last_err = e;
                    still.push(ko);
                }
            }
        }
        if still.len() == before {
            // No progress: the remaining modules have unsatisfiable deps or are
            // genuinely broken. Fail closed with the last kernel error.
            return Err(format!(
                "{} module(s) failed to load (unresolved deps?); last: {last_err}",
                still.len()
            ));
        }
        pending = still;
    }
    Ok(())
}

/// Recursively collect every `*.ko*` file under `root` (plain or compressed).
fn collect_kos(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.contains(".ko"))
            {
                out.push(p);
            }
        }
    }
    out
}
