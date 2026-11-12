// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Fixtures shared by the integration tests.
//!
//! Everything here reaches `saeptum-capsule` through its public API only, and
//! nothing here uses `unwrap` or `expect`: a test that cannot build its own
//! input returns the failure instead of panicking through a lint the workspace
//! denies.

#![allow(dead_code)]

use saeptum_capsule::{
    Capability, CapabilitySet, CapsuleMemoryLimit, CapsuleRegistry, CorrelationId, GuestMemoryMib,
    Label, MicroVmController, MicroVmRequest, VmmIdentity,
};

/// What every test in this suite returns.
#[allow(unused_imports)]
pub use test_support::Fallible;

/// The correlation identifier the fixtures thread through every payload.
pub const CORRELATION: &str = "fixture-0001";

/// The sandbox name the scaffold spawns.
pub const SANDBOX: &str = "agent-microvm-01";

/// The capsule name the scaffold registers.
pub const CAPSULE: &str = "extism-capsule-01";

/// The guest memory size the scaffold asks for, in mebibytes.
pub const GUEST_MIB: u32 = 4;

/// The capsule memory limit the scaffold asks for, in bytes.
pub const CAPSULE_BYTES: u64 = 16 * 1024 * 1024;

/// Returns the fixture correlation identifier.
///
/// # Errors
///
/// Propagates [`CorrelationId::parse`].
pub fn correlation() -> Result<CorrelationId, Box<dyn std::error::Error>> {
    Ok(CorrelationId::parse(CORRELATION)?)
}

/// Returns a label, so a fixture that stops parsing fails the suite.
///
/// # Errors
///
/// Propagates [`Label::parse`].
pub fn label(raw: &str) -> Result<Label, Box<dyn std::error::Error>> {
    Ok(Label::parse(raw)?)
}

/// Returns the scaffold's sandbox request under `vmm`.
///
/// # Errors
///
/// Propagates the field constructors and the accelerator refusal.
pub fn sandbox_request(vmm: VmmIdentity) -> Result<MicroVmRequest, Box<dyn std::error::Error>> {
    Ok(MicroVmRequest::new(
        label(SANDBOX)?,
        GuestMemoryMib::new(GUEST_MIB)?,
        false,
        vmm,
    )?)
}

/// Returns a controller holding `count` sandboxes.
///
/// # Errors
///
/// Propagates the request constructors and the table's capacity refusal.
pub fn filled_controller(count: usize) -> Result<MicroVmController, Box<dyn std::error::Error>> {
    let mut controller = MicroVmController::new();
    for _ in 0..count {
        controller.spawn(sandbox_request(VmmIdentity::Firecracker)?)?;
    }
    Ok(controller)
}

/// Returns the capability set the scaffold grants its capsule.
#[must_use]
pub fn scaffold_capabilities() -> CapabilitySet {
    CapabilitySet::new()
        .with(Capability::FilesystemRead)
        .with(Capability::ZenohIpc)
}

/// Returns a registry holding `count` capsules.
///
/// # Errors
///
/// Propagates the field constructors and the table's capacity refusal.
pub fn filled_registry(count: usize) -> Result<CapsuleRegistry, Box<dyn std::error::Error>> {
    let mut registry = CapsuleRegistry::new();
    for _ in 0..count {
        registry.register(
            label(CAPSULE)?,
            CapsuleMemoryLimit::new(CAPSULE_BYTES)?,
            scaffold_capabilities(),
        )?;
    }
    Ok(registry)
}

/// Shared fail-closed source walker.
#[allow(unused_imports)]
pub use test_support::rust_sources;

/// Scalar bound on the lines read from any one source file.
pub const LINE_BOUND: usize = 4096;

/// Returns the `"<file>:<line>: <identifier>"` hits `text` carries.
fn hits(name: &str, number: usize, text: &str, watched: &[&str]) -> Vec<String> {
    watched
        .iter()
        .filter(|needle| text.contains(**needle))
        .map(|needle| format!("{name}:{}: {needle}", number.saturating_add(1)))
        .collect()
}

/// Returns the hits one body of text carries, skipping comment lines.
///
/// Comment lines are skipped whole: the crate documentation names the very
/// identifiers a sweep watches for, precisely in order to say it does not use
/// them, so a sweep that read comments would fail on its own documentation.
///
/// This is public so a watched list can be exercised against planted text.
pub fn scan_text(name: &str, body: &str, watched: &[&str]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for (number, line) in body.lines().take(LINE_BOUND).enumerate() {
        let text = line.trim();
        if text.starts_with("//") {
            continue;
        }
        found.extend(hits(name, number, text, watched));
    }
    found
}

/// Returns every watched identifier the sources under `root` carry.
///
/// # Errors
///
/// Propagates [`rust_sources`], so a sweep cannot pass by reading nothing.
pub fn scan_sources(
    root: &std::path::Path,
    watched: &[&str],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut found: Vec<String> = Vec::new();
    for (name, body) in rust_sources(root)? {
        found.extend(scan_text(&name, &body, watched));
    }
    Ok(found)
}
