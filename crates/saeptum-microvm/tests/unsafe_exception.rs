// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on the workspace's one `unsafe` exception.
//!
//! `src/guest/boot.rs` maps Firecracker's boot timer page and writes one
//! byte to it, which takes one `unsafe` block. The exception is category D,
//! entered 2026-10-17 and expiring 2027-02-14: this file fails once the date
//! passes, when `unsafe` appears anywhere else in the crate, or when the
//! crate's restated lint tables drift from the workspace ones.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use test_support::{Fallible, read, rust_sources};

/// The file that holds the exception.
const EXCEPTION_FILE: &str = "guest/boot.rs";

/// The exception's expiry, 2027-02-14T00:00:00Z, since the epoch
/// (1 802 563 200 seconds).
const EXPIRES: Duration = Duration::from_hours(500_712);

/// Counts the lines of `text` that open an `unsafe` block or allow
/// `unsafe_code`, ignoring comments.
fn unsafe_lines(text: &str) -> (usize, usize) {
    let code = text
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"));
    code.fold((0, 0), |(blocks, allows), line| {
        (
            blocks.saturating_add(usize::from(line.contains("unsafe {"))),
            allows.saturating_add(usize::from(line.contains("allow(unsafe_code)"))),
        )
    })
}

/// The lines of the `[header]` table of a manifest, up to the next table.
fn table<'a>(manifest: &'a str, header: &str) -> Vec<&'a str> {
    manifest
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .collect()
}

// --- Positive -------------------------------------------------------------

/// Positive: the exception file holds exactly one `unsafe` block, allowed
/// on exactly one function, with its `SAFETY:` proof.
#[test]
fn the_exception_file_holds_one_proven_block() -> Fallible {
    let text = read(&format!("crates/saeptum-microvm/src/{EXCEPTION_FILE}"))?;
    assert!(!text.is_empty(), "src/{EXCEPTION_FILE} must exist");
    assert_eq!(unsafe_lines(&text), (1, 1));
    assert!(text.contains("// SAFETY: "));
    assert!(text.contains("category D, entered 2026-10-17, expires 2027-02-14"));
    Ok(())
}

/// Positive: the crate denies unsafe code and restates every other
/// workspace lint unchanged.
#[test]
fn the_restated_lints_match_the_workspace() -> Fallible {
    let root = read("Cargo.toml")?;
    let manifest = read("crates/saeptum-microvm/Cargo.toml")?;
    let rust = table(&manifest, "[lints.rust]");
    assert!(rust.contains(&"unsafe_code = \"deny\""), "{rust:?}");
    let expected: Vec<String> = table(&root, "[workspace.lints.rust]")
        .iter()
        .map(|line| line.replace("unsafe_code = \"forbid\"", "unsafe_code = \"deny\""))
        .collect();
    assert_eq!(rust, expected);
    let clippy = table(&manifest, "[lints.clippy]");
    assert!(clippy.contains(&"undocumented_unsafe_blocks = \"deny\""));
    assert_eq!(clippy, table(&root, "[workspace.lints.clippy]"));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: no other source of the crate holds `unsafe` code or allows it.
#[test]
fn no_other_source_holds_unsafe_code() -> Fallible {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_sources(&root)?;
    assert!(
        files.iter().any(|(file, _)| file == EXCEPTION_FILE),
        "src/{EXCEPTION_FILE} must be scanned"
    );
    for (file, body) in files.iter().filter(|(file, _)| file != EXCEPTION_FILE) {
        assert_eq!(unsafe_lines(body), (0, 0), "src/{file}");
    }
    Ok(())
}

/// Negative: the counter sees a block and an allow that a comment does not
/// hide, so a second one elsewhere would fail the check above.
#[test]
fn the_counter_sees_code_and_skips_comments() {
    let text = "// unsafe { in a comment }\n#[allow(unsafe_code)]\nfn f() { unsafe { g() } }\n";
    assert_eq!(unsafe_lines(text), (1, 1));
    assert_eq!(unsafe_lines("// allow(unsafe_code)\n"), (0, 0));
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the exception holds until its expiry and fails from then on.
#[test]
fn the_exception_has_not_expired() -> Fallible {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    assert!(
        now < EXPIRES,
        "the unsafe exception in src/{EXCEPTION_FILE} expired on 2027-02-14: re-check it and renew it, or remove it"
    );
    Ok(())
}
