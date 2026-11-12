// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Internal test fixtures and workspace manifest inspection helpers.

use std::io;
use std::path::{Path, PathBuf};

/// What every fallible test in this workspace returns.
pub type Fallible = Result<(), Box<dyn std::error::Error>>;

/// Scalar bound on directories visited and entries read per directory.
pub const WALK_BOUND: usize = 64;

/// Returns the workspace root, two directories above this crate's manifest.
#[must_use]
pub fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

/// Reads a workspace file without concealing missing or unreadable input.
///
/// # Errors
///
/// Returns `NotFound` when the workspace root cannot resolve. File errors
/// preserve their kind and name the full path, including invalid UTF-8 input.
pub fn read(name: &str) -> Result<String, io::Error> {
    let root = workspace_root()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workspace root not found"))?;
    let path = root.join(name);
    std::fs::read_to_string(&path).map_err(|error| path_error(&path, &error))
}

/// Adds the failing path while retaining the operating system's error kind.
fn path_error(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

/// Returns the entries of `directory`, refusing to drop any.
///
/// Reads at most [`WALK_BOUND`] entries and then checks that nothing remains
/// unread, so a directory that outgrows the bound fails instead of being
/// silently truncated.
///
/// # Errors
///
/// Names `directory` when it cannot be read, when an entry cannot be read,
/// or when it holds more than [`WALK_BOUND`] entries.
pub fn directory_entries(directory: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut entries =
        std::fs::read_dir(directory).map_err(|error| path_error(directory, &error))?;
    let mut paths = Vec::new();
    for _ in 0..WALK_BOUND {
        let Some(entry) = entries.next() else {
            return Ok(paths);
        };
        paths.push(entry.map_err(|error| path_error(directory, &error))?.path());
    }
    if let Some(entry) = entries.next() {
        entry.map_err(|error| path_error(directory, &error))?;
        return Err(io::Error::other(format!(
            "{}: more than {WALK_BOUND} entries",
            directory.display()
        )));
    }
    Ok(paths)
}

/// Returns sorted `.rs` files as (relative path, body) pairs using `/` separators.
///
/// Visits at most [`WALK_BOUND`] directories, each with at most that many entries.
/// The walk is iterative; exceeding either bound is an error.
///
/// # Errors
///
/// Names the failing path on directory, entry, metadata or UTF-8 read errors.
/// Also fails if a bound is exceeded or no Rust source was read under `root`.
pub fn rust_sources(root: &Path) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    for _ in 0..WALK_BOUND {
        let Some(directory) = pending.pop() else {
            break;
        };
        for path in directory_entries(&directory)? {
            let metadata = path.metadata().map_err(|error| path_error(&path, &error))?;
            if metadata.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let name = path
                    .strip_prefix(root)
                    .map_err(|error| format!("{}: {error}", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                let body =
                    std::fs::read_to_string(&path).map_err(|error| path_error(&path, &error))?;
                out.push((name, body));
            }
        }
    }
    if !pending.is_empty() {
        return Err(format!(
            "{}: more than {WALK_BOUND} directories; pending: {pending:?}",
            root.display()
        )
        .into());
    }
    if out.is_empty() {
        return Err(format!("no Rust source was read under {}", root.display()).into());
    }
    out.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Distinguishes fixtures that parallel test threads create in the same
    /// nanosecond.
    static FIXTURES: AtomicUsize = AtomicUsize::new(0);

    /// Runs a fixture and removes it even when the operation returns an error.
    fn fixture<T>(
        run: impl FnOnce(&Path) -> Result<T, Box<dyn std::error::Error>>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = FIXTURES.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "saeptum-sources-{}-{stamp}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root)?;
        let result = run(&root);
        std::fs::remove_dir_all(&root)?;
        result
    }

    #[test]
    fn workspace_root_resolves() -> Fallible {
        let root = workspace_root().ok_or("workspace root must resolve")?;
        assert!(root.join("Cargo.toml").is_file());
        Ok(())
    }

    #[test]
    fn read_returns_file_content() -> Fallible {
        let content = read("Cargo.toml")?;
        assert_ne!(content, "");
        assert!(content.contains("[workspace]"));
        Ok(())
    }

    #[test]
    fn read_rejects_missing_file_with_path_and_kind() -> Fallible {
        let name = "nonexistent-file-37d2a.txt";
        let error = read(name).err().ok_or("missing file must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let root = workspace_root().ok_or("workspace root must resolve")?;
        assert!(
            error
                .to_string()
                .contains(&root.join(name).display().to_string())
        );
        Ok(())
    }

    #[test]
    fn read_rejects_directory() -> Fallible {
        let error = read("crates").err().ok_or("directory must fail")?;
        assert!(error.to_string().contains("crates"));
        Ok(())
    }

    #[test]
    fn read_rejects_non_utf8() -> Fallible {
        let error = fixture(|root| {
            let path = root.join("invalid.rs");
            std::fs::write(&path, [0xff])?;
            Ok(read(path.to_str().ok_or("fixture path must be UTF-8")?))
        })?
        .err()
        .ok_or("invalid UTF-8 must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid.rs"));
        Ok(())
    }

    #[test]
    fn rust_sources_reads_crate_sources() -> Fallible {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sources = rust_sources(&root)?;
        assert!(
            sources
                .iter()
                .any(|(name, body)| name == "lib.rs" && body.contains("pub fn read("))
        );
        assert!(
            sources
                .iter()
                .all(|(name, _)| !Path::new(name).is_absolute() && !name.contains('\\'))
        );
        assert!(
            sources
                .windows(2)
                .all(|pair| matches!(pair, [left, right] if left.0 < right.0))
        );
        Ok(())
    }

    #[test]
    fn rust_sources_rejects_missing_directory() -> Fallible {
        let error = fixture(|root| Ok(rust_sources(&root.join("missing"))))?
            .err()
            .ok_or("missing directory must fail")?;
        assert!(error.to_string().contains("missing"));
        Ok(())
    }

    #[test]
    fn rust_sources_rejects_directory_without_rust() -> Fallible {
        let (result, name) = fixture(|root| {
            std::fs::write(root.join("note.txt"), "not Rust")?;
            Ok((rust_sources(root), root.display().to_string()))
        })?;
        let error = result.err().ok_or("no Rust source must fail")?;
        assert!(error.to_string().contains(&name));
        Ok(())
    }

    /// Fills one directory with a scalar number of readable sources.
    fn fill(root: &Path, count: usize) -> Fallible {
        for index in 0..count {
            std::fs::write(root.join(format!("{index:03}.rs")), "// source")?;
        }
        Ok(())
    }

    #[test]
    fn rust_sources_rejects_entry_overflow() -> Fallible {
        let (result, name) = fixture(|root| {
            fill(root, WALK_BOUND.saturating_add(1))?;
            Ok((rust_sources(root), root.display().to_string()))
        })?;
        let error = result.err().ok_or("entry overflow must fail")?;
        assert!(error.to_string().contains(&name));
        Ok(())
    }

    #[test]
    fn rust_sources_accepts_exact_entry_bound() -> Fallible {
        let sources = fixture(|root| {
            fill(root, WALK_BOUND)?;
            rust_sources(root)
        })?;
        assert_eq!(sources.len(), WALK_BOUND);
        Ok(())
    }

    #[test]
    fn rust_sources_preserves_nested_paths_and_sorts() -> Fallible {
        let sources = fixture(|root| {
            std::fs::create_dir(root.join("sub"))?;
            std::fs::write(root.join("sub/x.rs"), "nested")?;
            std::fs::write(root.join("z.rs"), "last")?;
            std::fs::write(root.join("x.rs"), "top")?;
            std::fs::write(root.join("ignored.txt"), "ignored")?;
            rust_sources(root)
        })?;
        assert_eq!(
            sources,
            [
                ("sub/x.rs".into(), "nested".into()),
                ("x.rs".into(), "top".into()),
                ("z.rs".into(), "last".into())
            ]
        );
        Ok(())
    }

    /// Builds `count` subdirectories, each with one Rust source.
    fn directories(root: &Path, count: usize) -> Fallible {
        for index in 0..count {
            let directory = root.join(format!("{index:03}"));
            std::fs::create_dir(&directory)?;
            std::fs::write(directory.join("lib.rs"), "// nested")?;
        }
        Ok(())
    }

    #[test]
    fn rust_sources_accepts_exact_directory_bound() -> Fallible {
        let sources = fixture(|root| {
            directories(root, WALK_BOUND.saturating_sub(1))?;
            rust_sources(root)
        })?;
        assert_eq!(sources.len(), WALK_BOUND.saturating_sub(1));
        Ok(())
    }

    #[test]
    fn rust_sources_rejects_directory_overflow() -> Fallible {
        let (result, name) = fixture(|root| {
            directories(root, WALK_BOUND)?;
            Ok((rust_sources(root), root.display().to_string()))
        })?;
        let error = result.err().ok_or("directory overflow must fail")?;
        assert!(error.to_string().contains(&name));
        Ok(())
    }

    #[test]
    fn rust_sources_rejects_non_utf8_source() -> Fallible {
        let error = fixture(|root| {
            std::fs::write(root.join("invalid.rs"), [0xff])?;
            Ok(rust_sources(root))
        })?
        .err()
        .ok_or("unreadable Rust source must fail")?;
        assert!(error.to_string().contains("invalid.rs"));
        Ok(())
    }
}
