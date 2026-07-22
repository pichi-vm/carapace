// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! carapace assembler CLI — read-side only.
//!
//! A thin command-line wrapper over the `carapace` library (see `lib.rs` /
//! `SPEC.md`): it parses the `attach` / `detach` verbs and delegates to
//! [`carapace::attach`] / [`carapace::detach`]. All chain-walk, validation, and
//! dm-stack logic lives in the library so in-process consumers can reuse it.

#![deny(unsafe_code)]
#![cfg(target_os = "linux")]

mod boot;
mod cli;
mod generator;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Multi-call dispatch on argv[0]:
    //   * as the initramfs init (`rdinit=/init`, the kernel default) → be PID1:
    //     mount, load modules, assemble the carapace, and switch_root — no
    //     systemd/udev in the initramfs (see `boot`);
    //   * as the `systemd-carapace-generator` symlink → emit the attach unit
    //     (the legacy systemd-in-initramfs path);
    //   * otherwise → the normal `attach` / `detach` CLI.
    let arg0 = std::env::args().next().unwrap_or_default();
    if boot::invoked_as_init(&arg0) {
        return boot::run();
    }
    if generator::invoked_as_generator(&arg0) {
        return generator::run();
    }
    cli::run()
}
