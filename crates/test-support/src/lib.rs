// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Internal test fixtures and workspace manifest inspection helpers.

use std::path::{Path, PathBuf};

/// What every fallible test in this workspace returns.
pub type Fallible = Result<(), Box<dyn std::error::Error>>;

/// Returns the workspace root, two directories above this crate's manifest.
#[must_use]
pub fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

/// Reads a workspace file, returning an empty string when it is missing.
#[must_use]
pub fn read(name: &str) -> String {
    workspace_root()
        .and_then(|root| std::fs::read_to_string(root.join(name)).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_resolves() {
        assert!(workspace_root().is_some(), "workspace root must resolve");
        assert!(
            workspace_root().is_some_and(|root| root.join("Cargo.toml").is_file()),
            "workspace root must contain Cargo.toml"
        );
    }

    #[test]
    fn read_returns_file_content() {
        let content = read("Cargo.toml");
        assert!(!content.is_empty(), "Cargo.toml must not be empty");
        assert!(
            content.contains("[workspace]"),
            "Cargo.toml must contain [workspace]"
        );
    }

    #[test]
    fn read_returns_empty_for_missing_file() {
        assert_eq!(read("nonexistent-file-37d2a.txt"), "");
    }
}
