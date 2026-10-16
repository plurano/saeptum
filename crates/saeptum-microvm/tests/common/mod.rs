// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Fixtures shared by the integration tests.
//!
//! Nothing here uses `unwrap` or `expect`: a fixture that cannot build its
//! input returns the failure. The only processes started are shell-script
//! stand-ins for Firecracker that this module writes, never Firecracker.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use saeptum_capsule::{
    FIRST_GUEST_CID, GuestMemoryMib, Label, MicroVmController, MicroVmInstance, MicroVmRequest,
    VmmIdentity,
};

/// What every test in this suite returns.
pub type Fallible = Result<(), Box<dyn std::error::Error>>;

/// The first sandbox identifier the controller hands out.
pub const FIRST_VM: u32 = 100;

/// The context identifier the controller derives for [`FIRST_VM`].
pub const FIRST_CID: u32 = FIRST_GUEST_CID + FIRST_VM;

/// The guest port the tests exchange on.
pub const PORT: u32 = 5210;

/// A stand-in that stays up until it is killed.
pub const STAYS_UP: &str = "exec sleep 30";

/// A stand-in that exits at once with status 3.
pub const EXITS_AT_ONCE: &str = "exit 3";

/// Serialises writing a stand-in and starting processes: a script written
/// while another thread forks can be held open for writing in the child,
/// which makes its own execution fail with `ETXTBSY`.
static SPAWN: Mutex<()> = Mutex::new(());

/// Takes the spawn lock.
///
/// # Errors
///
/// Returns an error when another test panicked while holding it.
pub fn spawn_lock() -> Result<MutexGuard<'static, ()>, String> {
    SPAWN
        .lock()
        .map_err(|_| "the spawn lock is poisoned".to_owned())
}

/// Admits one microVM row and returns it.
///
/// # Errors
///
/// Propagates the controller's refusals.
pub fn admitted() -> Result<MicroVmInstance, Box<dyn std::error::Error>> {
    let mut controller = MicroVmController::new();
    let request = MicroVmRequest::new(
        Label::parse("microvm-test-01")?,
        GuestMemoryMib::new(64)?,
        false,
        VmmIdentity::Firecracker,
    )?;
    let vm_id = controller.spawn(request)?;
    controller
        .get(vm_id)
        .ok_or_else(|| "the admitted row is missing".into())
}

/// Creates a fresh, short scratch directory for one test.
///
/// # Errors
///
/// Returns the I/O error when it cannot be created.
pub fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let dir = std::env::temp_dir().join(format!("saeptum-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Writes an executable shell stand-in for Firecracker running `body`.
///
/// Call it with [`spawn_lock`] held.
///
/// # Errors
///
/// Returns the I/O error when it cannot be written.
pub fn stand_in(dir: &Path, body: &str) -> Result<PathBuf, std::io::Error> {
    let path = dir.join("firecracker");
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path)
}
