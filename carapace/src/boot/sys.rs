// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Raw Linux syscalls for the initramfs PID1 (`carapace` init mode). This is
//! the ONE file in the boot path that needs `#![allow(unsafe_code)]` — every
//! unsafe block is a single libc syscall with a checked errno, mirroring the
//! `dm/uapi.rs` boundary in the library. Wrappers return `Result<_, String>`
//! for the orchestrator in `boot/mod.rs`, which stays `deny(unsafe_code)`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io::Error;
use std::os::fd::AsRawFd;
use std::path::Path;

/// `MODULE_INIT_COMPRESSED_FILE` (linux/module.h) — let the kernel inflate a
/// `.ko.xz`/`.gz`/`.zst` at `finit_module` time (kernel >= 5.17).
const MODULE_INIT_COMPRESSED_FILE: libc::c_int = 4;

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| format!("NUL byte in {s:?}"))
}

fn mount_one(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let (csrc, ctgt, cfs) = (cstr(src)?, cstr(target)?, cstr(fstype)?);
    let cdata = data.map(cstr).transpose()?;
    let dptr = cdata.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: all pointers are valid NUL-terminated CStrings (data may be null,
    // which mount(2) accepts); flags is a plain bitmask.
    let rc = unsafe {
        libc::mount(
            csrc.as_ptr(),
            ctgt.as_ptr(),
            cfs.as_ptr(),
            flags,
            dptr.cast(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "mount {fstype} on {target}: {}",
            Error::last_os_error()
        ))
    }
}

/// Mount the API filesystems the rest of boot needs: `/proc` (cmdline),
/// `/sys` (carapace's PARTUUID lookup), and `/dev` (devtmpfs — device nodes
/// without udev).
pub(super) fn mount_api() -> Result<(), String> {
    for d in ["/proc", "/sys", "/dev"] {
        let _ = std::fs::create_dir_all(d);
    }
    mount_one("proc", "/proc", "proc", 0, None)?;
    mount_one("sysfs", "/sys", "sysfs", 0, None)?;
    mount_one("devtmpfs", "/dev", "devtmpfs", 0, None)?;
    Ok(())
}

/// Point stdio at `/dev/console` now that devtmpfs is mounted (the kernel may
/// have started us without a console if the initramfs shipped no `/dev`).
/// Best-effort: boot proceeds even if the console can't be opened.
pub(super) fn reopen_console() {
    let Ok(cpath) = cstr("/dev/console") else {
        return;
    };
    // SAFETY: cpath is a valid CString; O_RDWR open of the console device.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return;
    }
    for target in 0..3 {
        // SAFETY: fd is open; dup2 onto stdin/stdout/stderr.
        unsafe { libc::dup2(fd, target) };
    }
    if fd > 2 {
        // SAFETY: fd is open and no longer needed after dup2.
        unsafe { libc::close(fd) };
    }
}

/// Best-effort diagnostic write to `/dev/console` (used on the fatal path).
pub(super) fn write_console(msg: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = f.write_all(msg.as_bytes());
    }
}

/// Load one kernel module via `finit_module(2)`. Treats `EEXIST` (already
/// loaded / builtin) as success; other errors (notably unresolved deps) are
/// returned so the caller can retry in dependency order.
pub(super) fn finit_module(path: &Path, compressed: bool) -> Result<(), String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let params = cstr("")?;
    let flags = if compressed {
        MODULE_INIT_COMPRESSED_FILE
    } else {
        0
    };
    // SAFETY: f is an open, owned fd valid for the call; params is an empty
    // NUL-terminated CString; flags is a plain bitmask.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_finit_module,
            f.as_raw_fd(),
            params.as_ptr(),
            flags,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Ok(()); // already present or built into the kernel
    }
    Err(format!("finit_module {}: {err}", path.display()))
}

/// Read a POSIX clock as whole microseconds. Returns 0 if the clock read
/// fails (this is a best-effort diagnostic, never a boot-critical value).
fn clock_us(clk: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the pointer targets a valid, writable timespec; clk is a plain
    // clock id.
    if unsafe { libc::clock_gettime(clk, &raw mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
}

/// Emit a timing marker to the console immediately before `switch_root`, when
/// opted in via the `carapace.timing` cmdline flag (off by default — a minimal
/// PID1 is otherwise silent except on the fatal path). This is the boundary of
/// the "launch → root ready" interval we optimize: it prints `boot_us`
/// (CLOCK_MONOTONIC, time since the guest kernel started, i.e. the
/// kernel+initramfs slice) and `epoch_us` (CLOCK_REALTIME, for diffing against
/// the host-recorded launch time). The clock is sampled first, so the console
/// write's own latency is not counted.
pub(super) fn mark_switch_root() {
    let boot_us = clock_us(libc::CLOCK_MONOTONIC);
    let epoch_us = clock_us(libc::CLOCK_REALTIME);
    write_console(&format!(
        "carapace: switch_root boot_us={boot_us} epoch_us={epoch_us}\n"
    ));
}

/// Mount the assembled carapace root read-only at `target`.
pub(super) fn mount_root(dev: &str, target: &str, fstype: &str) -> Result<(), String> {
    let _ = std::fs::create_dir_all(target);
    mount_one(dev, target, fstype, libc::MS_RDONLY, None)
}

/// Pivot into `newroot` and exec the real init — the classic initramfs
/// `switch_root`: move the API mounts in, `mount --move newroot /`, `chroot .`,
/// then `execv(init)`. Only returns (as `Err`) if a step fails; on success it
/// never returns.
pub(super) fn switch_root(newroot: &str, init: &str) -> Result<(), String> {
    for m in ["/proc", "/sys", "/dev"] {
        let tgt = format!("{newroot}{m}");
        let _ = std::fs::create_dir_all(&tgt);
        mount_one(m, &tgt, "", libc::MS_MOVE, None).map_err(|e| format!("move {m}: {e}"))?;
    }
    std::env::set_current_dir(newroot).map_err(|e| format!("chdir {newroot}: {e}"))?;
    mount_one(".", "/", "", libc::MS_MOVE, None).map_err(|e| format!("move newroot to /: {e}"))?;
    let dot = cstr(".")?;
    // SAFETY: chroot to the current directory (the moved new root).
    if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
        return Err(format!("chroot: {}", Error::last_os_error()));
    }
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    let cinit = cstr(init)?;
    let argv = [cinit.as_ptr(), std::ptr::null()];
    // SAFETY: cinit is a valid CString; argv is NULL-terminated. execv only
    // returns on failure.
    unsafe { libc::execv(cinit.as_ptr(), argv.as_ptr()) };
    Err(format!("execv {init}: {}", Error::last_os_error()))
}

/// Sync and power the machine off — the fatal-path exit for PID1 (which must
/// never simply return, or the kernel panics).
pub(super) fn poweroff() -> ! {
    // SAFETY: sync() and reboot() take no pointer arguments.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    // reboot(POWER_OFF) does not return; loop as a belt-and-suspenders guard.
    loop {
        // SAFETY: pause() takes no arguments and only returns on signal.
        unsafe { libc::pause() };
    }
}
