// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Why a microVM step was refused or could not complete.

use saeptum_capsule::SandboxError;

/// Reasons a microVM step fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MicroVmError {
    /// A bounded value of `saeptum-capsule` was refused.
    #[error(transparent)]
    Capsule(#[from] SandboxError),
    /// An operating-system call failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A step did not finish within its deadline (HISS-02).
    #[error("{what} missed its {millis} ms deadline")]
    Deadline {
        /// What was waited for.
        what: &'static str,
        /// The deadline, in milliseconds.
        millis: u128,
    },
    /// A message on the wire broke the protocol.
    #[error("{0}")]
    Protocol(String),
    /// A check this crate holds, or the guest, refused a value.
    #[error("{0}")]
    Refused(String),
}

impl MicroVmError {
    /// Wraps an I/O error with what was being done.
    #[must_use]
    pub const fn io(what: &'static str, source: std::io::Error) -> Self {
        Self::Io { what, source }
    }
}
