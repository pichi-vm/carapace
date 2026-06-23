// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CLI entry point. Two verbs: `attach` and `detach`. All-named
//! arguments, no positionals (matches v1 spec). Hand-rolled parser —
//! lane 04 found the `clap` derive feature pulled 16 transitive crates
//! and ~38% of the release `.text` for two verbs and three flags;
//! that's the textbook case for not earning its keep.
//!
//! This module is the binary's CLI shell only: it parses arguments and
//! delegates to the `carapace` library ([`carapace::attach`] /
//! [`carapace::detach`]), then handles process-level concerns (stdout/stderr,
//! exit codes). No chain or dm logic lives here.

use carapace::{validate_dm_name, CarapaceError};
use std::process::ExitCode;

const HELP: &str = "\
carapace — assemble (read) and produce (import) carapace block-device chains.

USAGE:
    carapace attach --name <NAME> --root <HEX>
    carapace detach --name <NAME>
    carapace import --image <RAW> --out <DIR> --tag <REF>
    carapace --help
    carapace --version

FLAGS:
    -n, --name <NAME>    Operator-visible /dev/mapper/<NAME>
    -r, --root <HEX>     Trusted chain root, lowercase hex (\u{2265} 64 chars)
    -i, --image <RAW>    Raw block image to import (import)
    -o, --out <DIR>      Output OCI image-layout directory (import)
    -t, --tag <REF>      Reference written as org.opencontainers.image.ref.name (import)

import converts a raw image into a single-scute base carapace and writes it as
an OCI image layout in <DIR>, pushable with `skopeo copy oci:<DIR>:<REF>
docker://…`. Verity trees are not shipped — the consumer reconstructs them.

attach walks the chain backward from --root, validates parameters
against the RDP whitelist, builds the dm stack, and prints the
operator-visible /dev/dm-<minor> path on success. Partitions are
discovered by PARTUUID lookup against /sys/class/block/*/uevent —
every visible GPT-partscanned block device contributes; no --storage
flag and no GPT parser.

detach is best-effort removal of every dm device prefixed <NAME>.
";

pub(crate) fn run() -> ExitCode {
    let result = parse_and_dispatch(std::env::args().skip(1));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("carapace: {e}");
            // 2 for chain-rejection (initrd can fail-closed cleanly);
            // 1 for operational failure (kernel ioctl, I/O, CLI usage).
            if e.is_adversary_rejection() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn parse_and_dispatch(mut args: impl Iterator<Item = String>) -> Result<(), CarapaceError> {
    let Some(verb) = args.next() else {
        eprint!("{HELP}");
        return Err(CarapaceError::Usage("missing verb".into()));
    };
    match verb.as_str() {
        "-h" | "--help" => {
            print!("{HELP}");
            Ok(())
        }
        "-V" | "--version" => {
            println!("carapace {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "attach" => {
            let (name, root) = parse_attach(args)?;
            let path = carapace::attach(&name, &root)?;
            println!("{}", path.display());
            Ok(())
        }
        "detach" => {
            let name = parse_detach(args)?;
            // detach is best-effort; print any residual per-device problems
            // (the library returns them rather than printing) and still
            // succeed, matching `dmsetup remove -f`.
            for problem in carapace::detach(&name)? {
                eprintln!("carapace detach: {problem}");
            }
            Ok(())
        }
        "import" => {
            let (image, out, tag) = parse_import(args)?;
            // The producer path returns anyhow errors; print the chain and
            // exit rather than forcing it through the read-side error enum.
            match carapace_import::oci::import_raw(&image, &out, &tag, None) {
                Ok(digest) => {
                    println!("{digest}");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("carapace import: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        other => Err(CarapaceError::Usage(format!(
            "unknown verb {other:?} (expected `attach`, `detach`, `--help`, or `--version`)"
        ))),
    }
}

fn parse_attach(args: impl Iterator<Item = String>) -> Result<(String, String), CarapaceError> {
    let mut name: Option<String> = None;
    let mut root: Option<String> = None;
    let mut iter = args.peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-n" | "--name" => name = Some(value_for(&arg, iter.next())?),
            "-r" | "--root" => root = Some(value_for(&arg, iter.next())?),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => {
                return Err(CarapaceError::Usage(format!(
                    "attach: unexpected argument {other:?}"
                )));
            }
        }
    }
    let name = name.ok_or_else(|| CarapaceError::Usage("attach: --name is required".into()))?;
    validate_dm_name(&name)?;
    let root = root.ok_or_else(|| CarapaceError::Usage("attach: --root is required".into()))?;
    Ok((name, root))
}

fn parse_detach(args: impl Iterator<Item = String>) -> Result<String, CarapaceError> {
    let mut name: Option<String> = None;
    let mut iter = args.peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-n" | "--name" => name = Some(value_for(&arg, iter.next())?),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => {
                return Err(CarapaceError::Usage(format!(
                    "detach: unexpected argument {other:?}"
                )));
            }
        }
    }
    let name = name.ok_or_else(|| CarapaceError::Usage("detach: --name is required".into()))?;
    validate_dm_name(&name)?;
    Ok(name)
}

/// Parse `import --image <raw> --out <dir> --tag <ref>`.
fn parse_import(
    args: impl Iterator<Item = String>,
) -> Result<(std::path::PathBuf, std::path::PathBuf, String), CarapaceError> {
    let mut image: Option<String> = None;
    let mut out: Option<String> = None;
    let mut tag: Option<String> = None;
    let mut iter = args.peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-i" | "--image" => image = Some(value_for(&arg, iter.next())?),
            "-o" | "--out" => out = Some(value_for(&arg, iter.next())?),
            "-t" | "--tag" => tag = Some(value_for(&arg, iter.next())?),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => {
                return Err(CarapaceError::Usage(format!(
                    "import: unexpected argument {other:?}"
                )));
            }
        }
    }
    let image = image.ok_or_else(|| CarapaceError::Usage("import: --image is required".into()))?;
    let out = out.ok_or_else(|| CarapaceError::Usage("import: --out is required".into()))?;
    let tag = tag.ok_or_else(|| CarapaceError::Usage("import: --tag is required".into()))?;
    Ok((image.into(), out.into(), tag))
}

fn value_for(flag: &str, value: Option<String>) -> Result<String, CarapaceError> {
    value.ok_or_else(|| CarapaceError::Usage(format!("{flag} requires a value")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> std::vec::IntoIter<String> {
        items
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parse_attach_long_form() {
        let (n, r) = parse_attach(args(&["--name", "root", "--root", "deadbeef"])).unwrap();
        assert_eq!(n, "root");
        assert_eq!(r, "deadbeef");
    }

    #[test]
    fn parse_attach_short_form() {
        let (n, r) = parse_attach(args(&["-n", "root", "-r", "deadbeef"])).unwrap();
        assert_eq!(n, "root");
        assert_eq!(r, "deadbeef");
    }

    #[test]
    fn parse_attach_flag_order_is_arbitrary() {
        let (n, r) = parse_attach(args(&["--root", "deadbeef", "--name", "root"])).unwrap();
        assert_eq!(n, "root");
        assert_eq!(r, "deadbeef");
    }

    #[test]
    fn parse_attach_rejects_missing_required() {
        assert!(matches!(
            parse_attach(args(&["--name", "root"])),
            Err(CarapaceError::Usage(_))
        ));
        assert!(matches!(
            parse_attach(args(&["--root", "deadbeef"])),
            Err(CarapaceError::Usage(_))
        ));
    }

    #[test]
    fn parse_attach_rejects_unknown_flag() {
        assert!(matches!(
            parse_attach(args(&["--name", "x", "--root", "y", "--bogus"])),
            Err(CarapaceError::Usage(_))
        ));
    }

    #[test]
    fn parse_attach_rejects_value_missing_for_flag() {
        assert!(matches!(
            parse_attach(args(&["--name"])),
            Err(CarapaceError::Usage(_))
        ));
    }

    #[test]
    fn parse_detach_requires_name() {
        assert_eq!(parse_detach(args(&["--name", "root"])).unwrap(), "root");
        assert!(matches!(
            parse_detach(args(&[])),
            Err(CarapaceError::Usage(_))
        ));
    }
}
