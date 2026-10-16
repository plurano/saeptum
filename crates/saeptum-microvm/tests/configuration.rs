// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The per-microVM Firecracker configuration file.
//!
//! Positive: the file names the kernel, the initramfs, one vCPU, the admitted
//! memory and one vsock device, and no drive and no network interface.
//! Negative: a socket path the kernel would refuse, and a path that is not
//! UTF-8, are refused before any process starts. Boundary: 107 bytes of socket
//! path is the longest admitted.

mod common;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use saeptum_capsule::{GuestMemoryMib, VsockCid};
use saeptum_microvm::{
    BOOT_ARGS, MAX_SOCKET_PATH_BYTES, MicroVmError, VCPU_COUNT, VmConfig, check_socket_path, render,
};
use serde_json::Value;

use common::{FIRST_CID, Fallible};

/// Renders a configuration around `socket`.
fn rendered(socket: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let text = render(&VmConfig {
        kernel: Path::new("/cache/kernel/vmlinux-6.18.44"),
        initrd: Path::new("/cache/runs/r1/initramfs.cpio"),
        memory: GuestMemoryMib::new(64)?,
        cid: VsockCid::new(FIRST_CID)?,
        socket,
    })?;
    Ok(serde_json::from_str(&text)?)
}

/// A socket path of exactly `length` bytes.
fn socket_of(length: usize) -> PathBuf {
    let stem = "/s/".len().saturating_add("v.sock".len());
    PathBuf::from(format!(
        "/s/{}v.sock",
        "d".repeat(length.saturating_sub(stem))
    ))
}

// --- Positive -------------------------------------------------------------

/// Positive: the file carries exactly the devices the run needs.
#[test]
fn the_configuration_names_what_the_run_needs() -> Fallible {
    let config = rendered(Path::new("/cache/runs/r1/vms/vm-100/v.sock"))?;
    let boot = config.get("boot-source").ok_or("boot-source")?;
    assert_eq!(
        boot.get("boot_args").and_then(Value::as_str),
        Some(BOOT_ARGS)
    );
    assert_eq!(
        boot.get("initrd_path").and_then(Value::as_str),
        Some("/cache/runs/r1/initramfs.cpio")
    );
    let machine = config.get("machine-config").ok_or("machine-config")?;
    assert_eq!(
        machine.get("mem_size_mib").and_then(Value::as_u64),
        Some(64)
    );
    assert_eq!(
        machine.get("vcpu_count").and_then(Value::as_u64),
        Some(u64::from(VCPU_COUNT))
    );
    let vsock = config.get("vsock").ok_or("vsock")?;
    assert_eq!(
        vsock.get("guest_cid").and_then(Value::as_u64),
        Some(u64::from(FIRST_CID))
    );
    Ok(())
}

/// Positive: no drive and no network interface, so no tap device is needed.
#[test]
fn there_is_no_drive_and_no_network_interface() -> Fallible {
    let config = rendered(Path::new("/cache/v.sock"))?;
    for key in ["drives", "network-interfaces"] {
        let empty = config.get(key).and_then(Value::as_array).map(Vec::is_empty);
        assert_eq!(empty, Some(true), "{key}");
    }
    assert!(BOOT_ARGS.contains("reboot=k"));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a socket path past the kernel's limit is refused.
#[test]
fn a_long_socket_path_is_refused() {
    let long = socket_of(MAX_SOCKET_PATH_BYTES.saturating_add(1));
    assert!(matches!(
        check_socket_path(&long),
        Err(MicroVmError::Refused(_))
    ));
    assert!(rendered(&long).is_err());
}

/// Negative: a path that is not UTF-8 is refused rather than mangled.
#[test]
fn a_path_that_is_not_utf8_is_refused() -> Fallible {
    let foreign = Path::new(OsStr::from_bytes(b"/cache/\xff/v.sock"));
    let refused = render(&VmConfig {
        kernel: Path::new("/k"),
        initrd: Path::new("/i"),
        memory: GuestMemoryMib::new(64)?,
        cid: VsockCid::new(FIRST_CID)?,
        socket: foreign,
    });
    assert!(matches!(refused, Err(MicroVmError::Refused(_))));
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: 107 bytes of socket path is admitted, 108 is not.
#[test]
fn the_socket_path_bound_is_closed_at_its_edge() {
    let at = socket_of(MAX_SOCKET_PATH_BYTES);
    assert_eq!(at.as_os_str().len(), 107);
    assert!(check_socket_path(&at).is_ok());
    let over = socket_of(108);
    assert_eq!(over.as_os_str().len(), 108);
    assert!(check_socket_path(&over).is_err());
}
