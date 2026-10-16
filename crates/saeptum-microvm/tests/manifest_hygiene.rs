// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on this crate's manifest.
//!
//! `saeptum-microvm` is a locked workspace member, takes `socket2` once from
//! the workspace table, depends on `saeptum-capsule` by path, and takes **no
//! async runtime, no monitor binding, no build script and no dependency on
//! the operating system it moved from**. Each is asserted here.

use std::path::{Path, PathBuf};

/// Returns the workspace root, two directories above this crate's manifest.
fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

/// Reads a workspace file, returning an empty string when it is missing.
fn read(name: &str) -> String {
    workspace_root()
        .and_then(|root| std::fs::read_to_string(root.join(name)).ok())
        .unwrap_or_default()
}

/// The crate's own manifest.
const MANIFEST: &str = "crates/saeptum-microvm/Cargo.toml";

// --- Positive -------------------------------------------------------------

/// Positive: the crate is a named member with a lock entry.
#[test]
fn the_crate_is_a_locked_member() {
    assert!(read("Cargo.toml").contains("\"crates/saeptum-microvm\""));
    assert!(read("Cargo.lock").contains("name = \"saeptum-microvm\""));
}

/// Positive: every dependency comes from the workspace or the sibling crate.
#[test]
fn the_dependencies_are_the_workspace_ones() {
    let manifest = read(MANIFEST);
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for expected in ["serde_json", "socket2", "thiserror"] {
        assert!(manifest.contains(&format!("{expected}.workspace = true")));
    }
    assert!(manifest.contains("saeptum-capsule = { path = \"../saeptum-capsule\" }"));
}

// --- Negative -------------------------------------------------------------

/// Negative: no runtime, binding, build script or host-OS dependency.
#[test]
fn the_crate_declares_no_runtime_or_binding() {
    let manifest = read(MANIFEST);
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for refused in [
        "tokio",
        "async-std",
        "kvm-ioctls",
        "firecracker-",
        "libc",
        "bindgen",
        "\ncc",
        "aegis-",
    ] {
        assert!(
            !manifest.contains(refused),
            "{refused} is not a dependency of this crate"
        );
    }
    assert!(!manifest.contains("[build-dependencies]"));
    assert!(!manifest.contains("[[bin]]"));
    assert!(manifest.contains("publish = false"));
}

// --- Boundary -------------------------------------------------------------

/// Boundary: `socket2` is pinned once, at the workspace root, and locked.
#[test]
fn socket2_is_pinned_once_and_locked() {
    let root = read("Cargo.toml");
    let pins = root
        .lines()
        .filter(|line| line.starts_with("socket2 = "))
        .count();
    assert_eq!(pins, 1, "socket2 is pinned exactly once");
    assert!(root.contains("socket2 = { version = \"0.6.5\""));
    assert!(read("Cargo.lock").contains("name = \"socket2\""));
    assert!(!read(MANIFEST).contains("socket2 = {"));
}

/// Boundary: the crate inherits the workspace lints rather than restating them.
#[test]
fn the_crate_inherits_the_workspace_lints() {
    let manifest = read(MANIFEST);
    assert!(manifest.contains("[lints]"));
    assert!(!manifest.contains("[lints.rust]"));
    assert!(!manifest.contains("[lints.clippy]"));
}
