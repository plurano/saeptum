// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bounded, allocation-free identifiers.
//!
//! `docs/integration/stack.md` asks every crossing to carry a correlation
//! identifier, and both P10 payloads also name the sandbox or capsule they are
//! about. Each is validated on construction and stored inline via
//! [`ArrayString`], so no decision path allocates for one and none can be
//! silently truncated or sanitised: a malformed input is refused.
//!
//! The scaffold (export-037 `ce490c88081f`) carried names as `[u8; 32]`
//! written from a padded string literal, which cannot refuse anything and
//! cannot say how long the name actually is. [`Label`] keeps the inline
//! storage and adds the refusal.

use arrayvec::ArrayString;
use core::fmt;

/// Scalar upper bound, in bytes, on a correlation identifier.
pub const MAX_CORRELATION_LEN: usize = 64;

/// Scalar upper bound, in bytes, on a sandbox or capsule label.
///
/// Thirty-two is the scaffold's own array width for `MicroVmInstance.name` and
/// `WasmCapsule.name`, kept so a name that fits the imported shape still fits
/// this one.
pub const MAX_LABEL_LEN: usize = 32;

/// Reasons an identifier is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The identifier was empty.
    #[error("an identifier is empty")]
    Empty,
    /// The identifier was longer than its bound.
    #[error("an identifier of {actual} bytes exceeds the bound of {max}")]
    TooLong {
        /// The bound it passed.
        max: usize,
        /// The length observed.
        actual: usize,
    },
    /// The identifier carries a byte outside the permitted character set.
    #[error("an identifier carries a byte outside the permitted character set")]
    Charset,
}

/// Returns `true` for the bytes permitted inside an identifier.
const fn permitted(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@' | b'/')
}

fn validate(raw: &str, max: usize) -> Result<(), IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty);
    }
    if raw.len() > max {
        return Err(IdError::TooLong {
            max,
            actual: raw.len(),
        });
    }
    for &byte in raw.as_bytes() {
        if !permitted(byte) {
            return Err(IdError::Charset);
        }
    }
    Ok(())
}

/// A validated correlation identifier of at most [`MAX_CORRELATION_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CorrelationId {
    inner: ArrayString<MAX_CORRELATION_LEN>,
}

impl CorrelationId {
    /// Parses `raw` into a correlation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] when `raw` is empty, longer than
    /// [`MAX_CORRELATION_LEN`] bytes, or carries a byte outside the permitted
    /// character set. The input is never truncated or sanitised.
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        validate(raw, MAX_CORRELATION_LEN)?;
        let mut inner = ArrayString::new();
        if inner.try_push_str(raw).is_err() {
            return Err(IdError::TooLong {
                max: MAX_CORRELATION_LEN,
                actual: raw.len(),
            });
        }
        Ok(Self { inner })
    }

    /// Returns the validated bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Returns the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `false`; an identifier is never empty by construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl From<CorrelationId> for String {
    fn from(id: CorrelationId) -> Self {
        id.inner.as_str().to_owned()
    }
}

impl TryFrom<String> for CorrelationId {
    type Error = &'static str;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw).map_err(|_| "a bounded correlation identifier")
    }
}

/// A validated sandbox or capsule label of at most [`MAX_LABEL_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label {
    inner: ArrayString<MAX_LABEL_LEN>,
}

impl Label {
    /// Parses `raw` into a label.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] under the same rules as [`CorrelationId::parse`]:
    /// empty, over-long, or outside the permitted character set. The input is
    /// never truncated or sanitised.
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        validate(raw, MAX_LABEL_LEN)?;
        let mut inner = ArrayString::new();
        if inner.try_push_str(raw).is_err() {
            return Err(IdError::TooLong {
                max: MAX_LABEL_LEN,
                actual: raw.len(),
            });
        }
        Ok(Self { inner })
    }

    /// Returns the validated bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Returns the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `false`; a label is never empty by construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl From<Label> for String {
    fn from(label: Label) -> Self {
        label.inner.as_str().to_owned()
    }
}

impl TryFrom<String> for Label {
    type Error = &'static str;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw).map_err(|_| "a bounded sandbox or capsule label")
    }
}
