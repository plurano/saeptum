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

/// Admits `raw` into inline storage of `CAP` bytes, refusing an empty value,
/// one longer than `CAP` and one carrying a byte outside the permitted set,
/// in that order. The storage's own capacity check is the length check.
fn admit<const CAP: usize>(raw: &str) -> Result<ArrayString<CAP>, IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty);
    }
    let inner = ArrayString::from(raw).map_err(|_| IdError::TooLong {
        max: CAP,
        actual: raw.len(),
    })?;
    if !raw.bytes().all(permitted) {
        return Err(IdError::Charset);
    }
    Ok(inner)
}

macro_rules! bounded_id {
    ($Type:ident, $cap:ident, $type_doc:literal, $parse_doc:literal, $err_msg:literal) => {
        #[doc = $type_doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $Type {
            inner: ArrayString<$cap>,
        }

        impl $Type {
            #[doc = $parse_doc]
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] when `raw` is empty, longer than the bound,
            /// or carries a byte outside the permitted character set. The input
            /// is never truncated or sanitised.
            pub fn parse(raw: &str) -> Result<Self, IdError> {
                Ok(Self {
                    inner: admit::<$cap>(raw)?,
                })
            }

            /// Returns the validated bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                self.inner.as_bytes()
            }

            /// Returns the length in bytes.
            #[must_use]
            pub const fn len(&self) -> usize {
                self.inner.len()
            }

            /// Returns `false`; an identifier is never empty by construction.
            #[must_use]
            pub const fn is_empty(&self) -> bool {
                self.inner.is_empty()
            }
        }

        impl fmt::Display for $Type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.inner)
            }
        }

        impl From<$Type> for String {
            fn from(id: $Type) -> Self {
                id.inner.as_str().to_owned()
            }
        }

        impl TryFrom<String> for $Type {
            type Error = &'static str;

            fn try_from(raw: String) -> Result<Self, Self::Error> {
                Self::parse(&raw).map_err(|_| $err_msg)
            }
        }
    };
}

bounded_id!(
    CorrelationId,
    MAX_CORRELATION_LEN,
    "A validated correlation identifier of at most [`MAX_CORRELATION_LEN`] bytes.",
    "Parses `raw` into a correlation identifier.",
    "a bounded correlation identifier"
);

bounded_id!(
    Label,
    MAX_LABEL_LEN,
    "A validated sandbox or capsule label of at most [`MAX_LABEL_LEN`] bytes.",
    "Parses `raw` into a label.",
    "a bounded sandbox or capsule label"
);
