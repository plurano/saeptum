// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! A literal that must not read as a measurement.
//!
//! The imported P10 scaffold writes `boot_time_ms: 112` into every sandbox it
//! creates, with the comment "Sub-125ms cold boot speed", and the crate header
//! lists "under 125ms boot and under 5MB RAM" among its standards targets.
//! REQ-P10-05 records what those figures are: **the values are unmeasured**.
//! The scaffold's 112 is gone: Aegis OS measured the boot time and footprint
//! under Firecracker (M22, decision D71), and those figures are
//! [`Measured`](crate::Measured) values that name their monitor. The two
//! targets stay what they were. This crate starts no process at all.
//!
//! A bare `u32` field cannot carry that. [`Unmeasured<T>`] is the wrapper that
//! does: a value of this type is a recorded target and never an
//! observation, its [`Display`](core::fmt::Display) renders the
//! provenance next to the number, and reading the number is the explicit call
//! [`Unmeasured::get`] rather than a field access.
//!
//! What it is not: a unit. It carries no dimension and does not know
//! milliseconds from mebibytes, so the constant that holds one says which.
//! What it also is not: proof that no measurement is recorded anywhere -- it is
//! the type the two recorded P10 targets use, and `tests/measured_figures.rs`
//! checks the ones this crate declares.

use core::fmt;

/// A recorded literal that has never been measured.
///
/// # Example
///
/// ```
/// use saeptum_capsule::{BOOT_TIME_TARGET_MS, Unmeasured};
///
/// let target: Unmeasured<u32> = BOOT_TIME_TARGET_MS;
/// assert_eq!(target.get(), 125);
/// assert_eq!(target.to_string(), "125 (unmeasured)");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unmeasured<T> {
    value: T,
}

impl<T> Unmeasured<T> {
    /// Records `value` as a target or scaffold literal, not as an observation.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Returns the recorded number.
    ///
    /// Deliberately a call rather than a public field: reading the number is a
    /// step a reviewer can see, and the type it came from says what the number
    /// is worth.
    #[must_use]
    pub const fn get(&self) -> T
    where
        T: Copy,
    {
        self.value
    }
}

impl<T: fmt::Display> fmt::Display for Unmeasured<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (unmeasured)", self.value)
    }
}
