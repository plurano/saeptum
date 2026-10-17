// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The guest's boot-complete signal to Firecracker's boot timer.
//!
//! With `boot-timer` enabled, Firecracker places a one-page MMIO device at
//! the start of its boot device memory and logs `Guest-boot-time = <n> us`
//! when the guest writes the byte [`BOOT_COMPLETE_MAGIC`] at offset 0 of
//! it. Firecracker v1.17.0 places that page at `0xc000_0000` on `x86_64`
//! (`MMIO32_MEM_START`, `arch/src/x86_64/layout.rs`) and at `0x4000_0000`
//! on `aarch64` (`arch/src/aarch64/layout.rs`); the device itself is
//! `devices/src/pseudo/boot_timer.rs`.
//!
//! A `write(2)` to `/dev/mem` at that address fails with `EFAULT`, since the
//! kernel accepts it only below the end of RAM (`valid_phys_addr_range`,
//! `drivers/char/mem.c`). [`signal_boot_complete`] therefore maps the page
//! through `/dev/mem` and writes the byte through the mapping, which needs
//! the crate's one `unsafe` block ([`write_through_mapping`]).

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::MicroVmError;

/// The byte Firecracker's boot timer reads as "boot complete".
pub const BOOT_COMPLETE_MAGIC: u8 = 123;

/// The device node [`signal_boot_complete`] maps the boot timer through.
pub const DEV_MEM: &str = "/dev/mem";

/// The guest-physical address of Firecracker's boot timer page on this
/// architecture, or `None` where Firecracker places none.
#[cfg(target_arch = "x86_64")]
pub const BOOT_TIMER_ADDRESS: Option<u64> = Some(0xc000_0000);

/// The guest-physical address of Firecracker's boot timer page on this
/// architecture, or `None` where Firecracker places none.
#[cfg(target_arch = "aarch64")]
pub const BOOT_TIMER_ADDRESS: Option<u64> = Some(0x4000_0000);

/// The guest-physical address of Firecracker's boot timer page on this
/// architecture, or `None` where Firecracker places none.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const BOOT_TIMER_ADDRESS: Option<u64> = None;

/// Tells Firecracker's boot timer that the guest has booted.
///
/// Call it once, as the first act of the guest's init; the host's
/// Firecracker log then carries one `Guest-boot-time` line. Without
/// `boot-timer` in the VM configuration nothing listens at the address and
/// the write has no effect.
///
/// # Errors
///
/// Returns [`MicroVmError::Refused`] on an architecture without a boot
/// timer, and [`MicroVmError::Io`] when `/dev/mem` cannot be opened or the
/// page cannot be mapped, for example in a guest kernel without
/// `CONFIG_DEVMEM`.
pub fn signal_boot_complete() -> Result<(), MicroVmError> {
    let address = BOOT_TIMER_ADDRESS.ok_or_else(|| {
        MicroVmError::Refused("Firecracker places no boot timer on this architecture".to_owned())
    })?;
    write_marker(Path::new(DEV_MEM), address)
}

/// Writes [`BOOT_COMPLETE_MAGIC`] at byte `offset` of `path` through a
/// shared mapping of it.
///
/// [`signal_boot_complete`] passes `/dev/mem` and the boot timer's address;
/// the tests pass a regular file, which a host without a guest can map. A
/// regular file must reach past `offset`, so the write cannot fall outside
/// it; `offset` must be a multiple of the page size, as `mmap(2)` requires.
pub(crate) fn write_marker(path: &Path, offset: u64) -> Result<(), MicroVmError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
        .open(path)
        .map_err(|error| MicroVmError::io("opening the boot timer's memory", error))?;
    check_reach(&file, offset)?;
    let offset = libc::off_t::try_from(offset).map_err(|_| {
        MicroVmError::Refused(format!("offset {offset} does not fit the mapping offset"))
    })?;
    write_through_mapping(&file, offset)
        .map_err(|error| MicroVmError::io("writing the boot-complete byte", error))
}

/// Refuses a regular file that ends at or before `offset`: a write through
/// a mapping past its end raises `SIGBUS`. A device node reports length 0
/// and is not checked.
fn check_reach(file: &File, offset: u64) -> Result<(), MicroVmError> {
    let metadata = file
        .metadata()
        .map_err(|error| MicroVmError::io("reading the boot timer's memory", error))?;
    if metadata.is_file() && metadata.len() <= offset {
        return Err(MicroVmError::Refused(format!(
            "the file ends at byte {}, at or before offset {offset}",
            metadata.len()
        )));
    }
    Ok(())
}

// Exception (category D, entered 2026-10-17, expires 2027-02-14): this is
// the one function of the workspace that may hold `unsafe` code, to map the
// boot timer page and write one byte to it. The crate restates the
// workspace lints with `unsafe_code = "deny"` for it, and
// `tests/unsafe_exception.rs` fails once the date passes or a second
// `unsafe` appears. Re-check it then, or remove it with the boot timer.
/// Maps one byte of `file` at `offset` shared and writable, writes
/// [`BOOT_COMPLETE_MAGIC`] to it with a volatile store, and unmaps it.
#[allow(unsafe_code)]
fn write_through_mapping(file: &File, offset: libc::off_t) -> std::io::Result<()> {
    // SAFETY: `mmap` gets a null hint, length 1, write access, a descriptor
    // `file` keeps open, and an offset the kernel checks (EINVAL unaligned);
    // MAP_FAILED is checked before any use. On success `mapped` is one
    // writable byte shared with `file`, inside it (`check_reach` refused a
    // regular file ending at or before `offset`), so the store cannot raise
    // SIGBUS. The pointer serves one volatile store (an MMIO write the
    // compiler must keep), never escapes, and is unmapped at the same length.
    unsafe {
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            1,
            libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            offset,
        );
        if mapped == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        std::ptr::write_volatile(mapped.cast::<u8>(), BOOT_COMPLETE_MAGIC);
        if libc::munmap(mapped, 1) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The marker write on a regular file: a host without a guest maps one
    //! the same way the guest maps `/dev/mem`.

    use std::path::PathBuf;

    use super::{BOOT_COMPLETE_MAGIC, write_marker};
    use crate::error::MicroVmError;

    type Fallible = Result<(), Box<dyn std::error::Error>>;

    /// One page on every architecture Firecracker supports.
    const PAGE: u64 = 4096;

    /// A fresh file path for `name`, unique to this process.
    fn file_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("saeptum-boot-{name}-{}.bin", std::process::id()))
    }

    /// A zeroed file of `len` bytes at a fresh path for `name`.
    fn zeroed(name: &str, len: u64) -> Result<PathBuf, std::io::Error> {
        let path = file_path(name);
        let file = std::fs::File::create(&path)?;
        file.set_len(len)?;
        Ok(path)
    }

    /// Positive: the magic byte lands at the page offset and nowhere else.
    #[test]
    fn the_marker_lands_at_the_offset() -> Fallible {
        let path = zeroed("second-page", PAGE.saturating_mul(2))?;
        let written = write_marker(&path, PAGE);
        let bytes = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        assert!(written.is_ok(), "{written:?}");
        let marked: Vec<usize> = bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte != 0)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(marked, vec![4096]);
        assert_eq!(bytes.get(4096), Some(&BOOT_COMPLETE_MAGIC));
        Ok(())
    }

    /// Negative: a missing node is an I/O error naming the open.
    #[test]
    fn a_missing_node_is_an_io_error() {
        let written = write_marker(&file_path("missing"), 0);
        assert!(
            matches!(
                written,
                Err(MicroVmError::Io {
                    what: "opening the boot timer's memory",
                    ..
                })
            ),
            "{written:?}"
        );
    }

    /// Negative: an offset off the page grid is refused by `mmap` and
    /// leaves the file unchanged.
    #[test]
    fn an_unaligned_offset_is_an_io_error() -> Fallible {
        let path = zeroed("unaligned", PAGE.saturating_mul(2))?;
        let written = write_marker(&path, 1);
        let bytes = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        assert!(
            matches!(
                written,
                Err(MicroVmError::Io {
                    what: "writing the boot-complete byte",
                    ..
                })
            ),
            "{written:?}"
        );
        assert!(bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    /// Boundary: a file of one byte takes the marker at offset 0.
    #[test]
    fn a_one_byte_file_takes_the_marker() -> Fallible {
        let path = zeroed("one-byte", 1)?;
        let written = write_marker(&path, 0);
        let bytes = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(bytes, vec![BOOT_COMPLETE_MAGIC]);
        Ok(())
    }

    /// Boundary: a file that ends exactly at the offset is refused before
    /// any mapping, so the store cannot raise `SIGBUS`.
    #[test]
    fn a_file_ending_at_the_offset_is_refused() -> Fallible {
        let path = zeroed("short", PAGE)?;
        let written = write_marker(&path, PAGE);
        std::fs::remove_file(&path)?;
        assert!(
            matches!(&written, Err(MicroVmError::Refused(reason)) if reason.contains("ends at byte 4096")),
            "{written:?}"
        );
        Ok(())
    }

    /// Boundary: an offset past `off_t` is refused, not wrapped.
    #[test]
    fn an_offset_past_off_t_is_refused() {
        let written = write_marker(std::path::Path::new("/dev/null"), u64::MAX);
        assert!(
            matches!(&written, Err(MicroVmError::Refused(reason)) if reason.contains("does not fit")),
            "{written:?}"
        );
    }
}
