// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The per-microVM Firecracker configuration file.
//!
//! Firecracker 1.17.0 boots a microVM from one JSON file with `--no-api
//! --config-file` (its `docs/getting-started.md`), so no API socket exists and
//! nothing can be reconfigured after the boot. The file names the kernel, the
//! initramfs, one vCPU, the admitted guest memory and one vsock device, and
//! nothing else: `drives` and `network-interfaces` are empty arrays, so no
//! block device is attached and no tap device is needed or created.

use std::path::Path;

use saeptum_capsule::{GuestMemoryMib, VsockCid};

use crate::error::MicroVmError;

/// The guest kernel command line.
///
/// `console=ttyS0` sends the guest console to Firecracker's standard output,
/// which the host keeps in the microVM's `console.log`; `reboot=k` makes the
/// guest init's restart a keyboard-controller reset, which Firecracker
/// answers by exiting; `panic=1` turns a guest panic into the same exit a
/// second later; `pci=off` because the microVM has no PCI bus.
pub const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// The vCPU count every microVM is given.
pub const VCPU_COUNT: u32 = 1;

/// The longest `AF_UNIX` socket path the kernel accepts, in bytes.
///
/// `sun_path` is 108 bytes and carries a terminating NUL, so 107 bytes of
/// path. Firecracker refuses a longer `uds_path` at boot ("path must be
/// shorter than `SUN_LEN`"); this crate refuses it before a process starts.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;

/// What one microVM's configuration names.
#[derive(Debug, Clone, Copy)]
pub struct VmConfig<'a> {
    /// The uncompressed guest kernel.
    pub kernel: &'a Path,
    /// The initramfs holding the guest init.
    pub initrd: &'a Path,
    /// The admitted guest memory.
    pub memory: GuestMemoryMib,
    /// The guest's vsock context identifier, from the controller's row.
    pub cid: VsockCid,
    /// The host-side Unix socket the vsock device listens on.
    pub socket: &'a Path,
}

/// Returns `path` as UTF-8, refusing anything else.
fn text<'p>(path: &'p Path, what: &str) -> Result<&'p str, MicroVmError> {
    path.to_str()
        .ok_or_else(|| MicroVmError::Refused(format!("the {what} path is not UTF-8")))
}

/// Refuses a socket path the kernel would refuse.
///
/// # Errors
///
/// Returns [`MicroVmError::Refused`] past [`MAX_SOCKET_PATH_BYTES`].
pub fn check_socket_path(socket: &Path) -> Result<(), MicroVmError> {
    let length = socket.as_os_str().len();
    if length > MAX_SOCKET_PATH_BYTES {
        return Err(MicroVmError::Refused(format!(
            "the vsock socket path is {length} bytes; AF_UNIX allows {MAX_SOCKET_PATH_BYTES}"
        )));
    }
    Ok(())
}

/// Renders the configuration file.
///
/// # Errors
///
/// Returns [`MicroVmError::Refused`] for a path that is not UTF-8 or a socket
/// path the kernel would refuse, and [`MicroVmError::Protocol`] if the
/// document does not serialise.
pub fn render(config: &VmConfig<'_>) -> Result<String, MicroVmError> {
    check_socket_path(config.socket)?;
    let document = serde_json::json!({
        "boot-source": {
            "kernel_image_path": text(config.kernel, "kernel")?,
            "initrd_path": text(config.initrd, "initramfs")?,
            "boot_args": BOOT_ARGS,
        },
        "drives": [],
        "machine-config": {
            "vcpu_count": VCPU_COUNT,
            "mem_size_mib": config.memory.get(),
            "smt": false,
        },
        "network-interfaces": [],
        "vsock": {
            "guest_cid": config.cid.get(),
            "uds_path": text(config.socket, "vsock socket")?,
        },
    });
    serde_json::to_string_pretty(&document).map_err(|error| {
        MicroVmError::Protocol(format!("the configuration does not encode: {error}"))
    })
}
