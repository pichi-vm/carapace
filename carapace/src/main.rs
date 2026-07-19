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

mod cli;
mod generator;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Multi-call dispatch: when invoked as the systemd generator (via the
    // `systemd-carapace-generator` symlink dracut installs into
    // `/usr/lib/systemd/system-generators/`), systemd passes three output
    // directories and expects unit files written — not the normal CLI.
    let arg0 = std::env::args().next().unwrap_or_default();
    if generator::invoked_as_generator(&arg0) {
        return generator::run();
    }
    cli::run()
}
