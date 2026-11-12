// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on this crate's manifest.
//!
//! `saeptum-microvm` is a locked workspace member, takes `socket2` and `libc`
//! once from the workspace table, depends on `saeptum-capsule` by path, and
//! takes **no async runtime, no monitor binding, no build script and no
//! dependency on the operating system it moved from**. Each is asserted here.
//! `libc` serves the boot timer's one `unsafe` block alone; the crate's lint
//! tables are held by `tests/unsafe_exception.rs`.

use test_support::{Fallible, read};

/// The crate's own manifest.
const MANIFEST: &str = "crates/saeptum-microvm/Cargo.toml";

// --- Positive -------------------------------------------------------------

/// Positive: the crate is a named member with a lock entry.
#[test]
fn the_crate_is_a_locked_member() -> Fallible {
    assert!(read("Cargo.toml")?.contains("\"crates/saeptum-microvm\""));
    assert!(read("Cargo.lock")?.contains("name = \"saeptum-microvm\""));
    Ok(())
}

/// Positive: every dependency comes from the workspace or the sibling crate.
#[test]
fn the_dependencies_are_the_workspace_ones() -> Fallible {
    let manifest = read(MANIFEST)?;
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for expected in ["libc", "serde_json", "socket2", "thiserror"] {
        assert!(manifest.contains(&format!("{expected}.workspace = true")));
    }
    assert!(manifest.contains("saeptum-capsule = { path = \"../saeptum-capsule\" }"));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: no runtime, binding, build script or host-OS dependency.
#[test]
fn the_crate_declares_no_runtime_or_binding() -> Fallible {
    let manifest = read(MANIFEST)?;
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for refused in [
        "tokio",
        "async-std",
        "kvm-ioctls",
        "firecracker-",
        "libc = {",
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
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: `socket2` is pinned once, at the workspace root, and locked.
#[test]
fn socket2_is_pinned_once_and_locked() -> Fallible {
    let root = read("Cargo.toml")?;
    let pins = root
        .lines()
        .filter(|line| line.starts_with("socket2 = "))
        .count();
    assert_eq!(pins, 1, "socket2 is pinned exactly once");
    assert!(root.contains("socket2 = { version = \"0.6.5\""));
    assert!(read("Cargo.lock")?.contains("name = \"socket2\""));
    assert!(!read(MANIFEST)?.contains("socket2 = {"));
    Ok(())
}

/// Boundary: `libc` is pinned once, at the workspace root, at the version
/// `socket2` already locks.
#[test]
fn libc_is_pinned_once_and_locked() -> Fallible {
    let root = read("Cargo.toml")?;
    let pins = root
        .lines()
        .filter(|line| line.starts_with("libc = "))
        .count();
    assert_eq!(pins, 1, "libc is pinned exactly once");
    assert!(root.contains("libc = { version = \"0.2.191\""));
    assert!(read("Cargo.lock")?.contains("name = \"libc\"\nversion = \"0.2.191\""));
    Ok(())
}
