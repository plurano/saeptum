// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! A figure that was measured, carrying the monitor and the run behind it.
//!
//! Decision D58 requires every boot time and footprint to record which
//! monitor produced it, and never to present Firecracker and `QEMU` microvm
//! numbers as interchangeable. [`Measured<T>`] is the type that makes that
//! structural: its fields are private, and the one constructor takes the
//! value, the [`VmmIdentity`] and the run identifier together, so a measured
//! figure without a monitor cannot be written.
//!
//! ```compile_fail
//! use saeptum_capsule::Measured;
//!
//! // A figure naming no monitor does not compile.
//! let figure: Measured<u32> = Measured::new(306, "r20261017T124857-0027");
//! ```
//!
//! ```compile_fail
//! use saeptum_capsule::Measured;
//!
//! // A bare number is not a measured figure.
//! let figure: Measured<u32> = 306;
//! ```
//!
//! ```compile_fail
//! use saeptum_capsule::Measured;
//!
//! // Nor is one built from its fields.
//! let figure = Measured { value: 306u32 };
//! ```
//!
//! What it is not: a unit, like [`Unmeasured`](crate::Unmeasured); the
//! constant that holds one says which. Nor is it proof of the run: the run
//! identifier names where the evidence is kept, and the evidence itself lives
//! in the consumer that ran the measurement.

use core::fmt;

use crate::vmm::VmmIdentity;

/// A figure measured on a named monitor, in a named run.
///
/// # Example
///
/// ```
/// use saeptum_capsule::{MEASURED_BOOT_TIME_MS, Measured, VmmIdentity};
///
/// let figure: Measured<u32> = MEASURED_BOOT_TIME_MS;
/// assert_eq!(figure.vmm(), VmmIdentity::Firecracker);
/// assert_eq!(
///     figure.to_string(),
///     "306 (measured on firecracker 1.17.0, run r20261017T124857-0027)"
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measured<T> {
    value: T,
    vmm: VmmIdentity,
    run: &'static str,
}

impl<T> Measured<T> {
    /// Records `value` as measured on `vmm` in the run named `run`.
    #[must_use]
    pub const fn new(value: T, vmm: VmmIdentity, run: &'static str) -> Self {
        Self { value, vmm, run }
    }

    /// Returns the measured number.
    #[must_use]
    pub const fn get(&self) -> T
    where
        T: Copy,
    {
        self.value
    }

    /// Returns the monitor that produced the figure.
    #[must_use]
    pub const fn vmm(&self) -> VmmIdentity {
        self.vmm
    }

    /// Returns the identifier of the run that produced the figure.
    #[must_use]
    pub const fn run(&self) -> &'static str {
        self.run
    }

    /// Returns the figure if it was produced on `vmm`, and `None` otherwise.
    ///
    /// The one way to read a figure for a given monitor: a `QEMU` microvm row
    /// asking for a Firecracker figure gets none rather than a borrowed one.
    #[must_use]
    pub fn for_vmm(self, vmm: VmmIdentity) -> Option<Self> {
        (self.vmm == vmm).then_some(self)
    }
}

impl<T: fmt::Display> fmt::Display for Measured<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (measured on {} {}, run {})",
            self.value,
            self.vmm.tag(),
            self.vmm.pinned_version(),
            self.run
        )
    }
}
