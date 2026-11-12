// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on the workspace manifests.
//!
//! Three of this crate's claims are about files rather than about code:
//! `saeptum-capsule` is a workspace member with a lock entry, the member list
//! is written out rather than globbed, and **the crate takes no `WebAssembly`
//! engine, no monitor binding, no `io_uring` dependency and no dependency on
//! the operating system it moved from**. Each is asserted here rather than
//! left as prose.

use std::path::Path;
use test_support::{Fallible, directory_entries, read, workspace_root};

/// Distinguishes an absent manifest from metadata that could not be read.
fn has_manifest(directory: &Path) -> Result<bool, std::io::Error> {
    let path = directory.join("Cargo.toml");
    match std::fs::metadata(&path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        )),
    }
}

/// The member list is checked against this rather than against a literal
/// count. A count has to be edited every time a milestone activates a crate,
/// and hard-coding it in several crates at once makes all of them fail when
/// one member is added. What actually needs holding is
/// the invariant behind the count: every crate directory that has a manifest
/// is a workspace member, and nothing else is.
fn crate_directories_with_a_manifest() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let root = workspace_root()
        .ok_or("workspace root not found")?
        .join("crates");
    let mut found = Vec::new();
    for path in directory_entries(&root)? {
        if has_manifest(&path)? {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("{}: crate directory name is not UTF-8", path.display()))?;
            found.push(name.to_owned());
        }
    }
    found.sort_unstable();
    Ok(found)
}

// --- Positive -------------------------------------------------------------

/// Positive: the workspace names this crate as a member.
#[test]
fn the_workspace_names_this_crate() -> Fallible {
    let manifest = read("Cargo.toml")?;
    assert!(!manifest.is_empty(), "the workspace manifest must exist");
    assert!(manifest.contains("\"crates/saeptum-capsule\""));
    Ok(())
}

/// Positive: the lock file carries an entry for this crate.
#[test]
fn the_lock_file_carries_an_entry_for_this_crate() -> Fallible {
    let lock = read("Cargo.lock")?;
    assert!(!lock.is_empty(), "Cargo.lock must be committed");
    assert!(lock.contains("name = \"saeptum-capsule\""));
    Ok(())
}

/// Positive: the crate declares the workspace's own three dependencies and
/// takes each from the workspace table.
#[test]
fn the_crate_declares_the_workspace_dependencies() -> Fallible {
    let manifest = read("crates/saeptum-capsule/Cargo.toml")?;
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for expected in ["serde", "serde_json", "thiserror"] {
        assert!(manifest.contains(&format!("{expected}.workspace = true")));
    }
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: the member list is written out, never globbed.
#[test]
fn the_member_list_is_written_out_and_not_globbed() -> Fallible {
    let manifest = read("Cargo.toml")?;
    assert!(manifest.contains("\"crates/saeptum-capsule\""));
    for glob in ["crates/*", "crates/**", "\"*\""] {
        assert!(
            !manifest.contains(glob),
            "the member list must be written out, not globbed with {glob}"
        );
    }
    Ok(())
}

/// Negative: no engine, monitor or host-operating-system dependency.
///
/// What a violation would look like is a binding crate, a foreign-function
/// build script, a Rust engine pinned here without a recorded admission, or
/// a path back into the operating system this code moved from. Each is
/// refused.
#[test]
fn the_crate_manifest_declares_no_runtime_or_monitor_dependency() -> Fallible {
    let manifest = read("crates/saeptum-capsule/Cargo.toml")?;
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    for deferred in [
        "wasmtime",
        "wasmer",
        "wasmi",
        "extism",
        "wazero",
        "kvm-ioctls",
        "firecracker",
        "vsock",
        "io-uring",
        "tokio",
        "libc",
        "bindgen",
        "cc",
        "aegis-",
    ] {
        assert!(
            !manifest.contains(deferred),
            "{deferred} is not a dependency of this crate"
        );
    }
    assert!(
        !manifest.contains("[build-dependencies]"),
        "a build script is how a foreign runtime would arrive"
    );
    Ok(())
}

/// Negative: this crate ships a library, so there is no binary target.
#[test]
fn the_crate_declares_no_binary_target() -> Fallible {
    let manifest = read("crates/saeptum-capsule/Cargo.toml")?;
    assert!(!manifest.contains("[[bin]]"));
    assert!(manifest.contains("[lib]"));
    assert!(manifest.contains("publish = false"));
    Ok(())
}

/// Negative: a metadata error other than an absent manifest propagates
/// instead of reading as "no manifest here".
///
/// Unix only: a path component longer than 255 bytes fails there with
/// `ENAMETOOLONG`; Windows limits and reports long names differently.
#[cfg(unix)]
#[test]
fn has_manifest_propagates_other_metadata_errors() -> Fallible {
    let root = workspace_root().ok_or("workspace root must resolve")?;
    let error = has_manifest(&root.join("x".repeat(256)))
        .err()
        .ok_or("an over-long name must not read as an absent manifest")?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidFilename);
    assert!(error.to_string().contains("Cargo.toml"));
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: missing manifests and non-directories are absent, existing files present.
#[test]
fn has_manifest_distinguishes_absent_and_present_manifests() -> Fallible {
    let root = workspace_root().ok_or("workspace root must resolve")?;
    assert!(!has_manifest(&root.join("Cargo.toml"))?);
    assert!(!has_manifest(&root.join("crates"))?);
    assert!(has_manifest(&root.join("crates/saeptum-capsule"))?);
    Ok(())
}

/// Boundary: the workspace lists exactly the crate directories that have a
/// manifest, no more and no fewer.
///
/// Not a hard-coded count: the number changes every time a crate is added. What must not change is that a directory with a manifest is a
/// member and nothing else is, so a new crate cannot be built by the workspace
/// without being named, and a named member cannot vanish from the tree.
#[test]
fn the_workspace_lists_every_crate_with_a_manifest() -> Fallible {
    let manifest = read("Cargo.toml")?;
    let members: Vec<String> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("\"crates/"))
        .map(|line| line.trim_matches(|c| c == '"' || c == ',').to_owned())
        .collect();
    let directories = crate_directories_with_a_manifest()?;
    assert!(!directories.is_empty(), "crates/ must hold manifests");
    assert_eq!(
        members.len(),
        directories.len(),
        "members {members:?} against directories {directories:?}"
    );
    for name in &directories {
        assert!(
            members
                .iter()
                .any(|member| member == &format!("crates/{name}")),
            "the member list must name {name}"
        );
    }
    Ok(())
}

/// Boundary: the crate inherits the workspace lints rather than restating them.
#[test]
fn the_crate_inherits_the_workspace_lints() -> Fallible {
    let manifest = read("crates/saeptum-capsule/Cargo.toml")?;
    assert!(manifest.contains("[lints]"));
    assert!(manifest.contains("workspace = true"));
    assert!(!manifest.contains("[lints.rust]"));
    assert!(!manifest.contains("[lints.clippy]"));
    let root = read("Cargo.toml")?;
    assert!(root.contains("unsafe_code = \"forbid\""));
    Ok(())
}
