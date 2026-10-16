// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The boot-time literal is marked unmeasured.
//!
//! Positive: the three recorded figures are [`Unmeasured`] values, and every
//! sandbox row carries the scaffold's literal as one. Negative: no value this
//! crate serialises carries a measurement field at all, so an unmeasured
//! number cannot reach a consumer dressed as an observation. Boundary: the literal sits
//! below the target it is compared against, and saying so is a statement about
//! two recorded numbers rather than about any sandbox.
//!
//! What this file does not claim: that no measurement exists anywhere. It
//! checks the three literals this crate declares and the values it
//! serialises.

mod common;

use saeptum_capsule::{
    BOOT_TIME_TARGET_MS, FOOTPRINT_TARGET_MIB, SCAFFOLD_BOOT_TIME_MS, Unmeasured, VmmIdentity,
};

use saeptum_capsule::VmId;

use common::Fallible;

/// Accepts only a value that says it was never measured.
fn assert_unmeasured<T: Copy>(_value: Unmeasured<T>) {}

// --- Positive -------------------------------------------------------------

/// Positive: the three recorded figures are unmeasured values.
///
/// This is the falsifier. Changing any of these constants to a bare integer
/// stops this file compiling, which fails the gate.
#[test]
fn the_recorded_figures_are_unmeasured() {
    assert_unmeasured(SCAFFOLD_BOOT_TIME_MS);
    assert_unmeasured(BOOT_TIME_TARGET_MS);
    assert_unmeasured(FOOTPRINT_TARGET_MIB);
    assert_eq!(SCAFFOLD_BOOT_TIME_MS.get(), 112);
    assert_eq!(BOOT_TIME_TARGET_MS.get(), 125);
    assert_eq!(FOOTPRINT_TARGET_MIB.get(), 5);
}

/// Positive: an unmeasured value renders its provenance next to the number,
/// so a figure copied into a report carries the caveat with it.
#[test]
fn an_unmeasured_value_renders_its_provenance() {
    assert_eq!(SCAFFOLD_BOOT_TIME_MS.to_string(), "112 (unmeasured)");
    assert_eq!(BOOT_TIME_TARGET_MS.to_string(), "125 (unmeasured)");
    assert_eq!(Unmeasured::new(0u32).to_string(), "0 (unmeasured)");
}

/// Positive: every sandbox row carries the scaffold's literal as an unmeasured
/// value rather than as a number.
#[test]
fn every_sandbox_row_carries_the_literal_as_unmeasured() -> Fallible {
    let controller = common::filled_controller(3)?;
    for raw in [100u32, 101, 102] {
        let row = controller
            .get(saeptum_capsule::VmId::new(raw))
            .ok_or("the table must hold the sandbox")?;
        assert_unmeasured(row.declared_boot_time_ms);
        assert_eq!(row.declared_boot_time_ms, SCAFFOLD_BOOT_TIME_MS);
    }
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: no serialisable value carries a measurement, so no unmeasured
/// figure can travel to a consumer as one.
#[test]
fn no_serialised_value_carries_a_measurement() -> Fallible {
    let vmm = serde_json::to_string(&VmmIdentity::Firecracker)?;
    let vm = serde_json::to_string(&VmId::new(100))?;
    for payload in [&vmm, &vm] {
        for field in ["boot", "112", "footprint", "latency", "measured"] {
            assert!(
                !payload.contains(field),
                "no serialised value may carry {field}: {payload}"
            );
        }
    }
    assert_eq!(vmm, "\"firecracker\"");
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the scaffold literal is below the target it is written against,
/// which is a relation between two recorded numbers and evidence about
/// neither.
#[test]
fn the_literal_sits_below_the_target_it_is_written_against() {
    assert!(SCAFFOLD_BOOT_TIME_MS.get() < BOOT_TIME_TARGET_MS.get());
    assert_eq!(
        BOOT_TIME_TARGET_MS
            .get()
            .saturating_sub(SCAFFOLD_BOOT_TIME_MS.get()),
        13,
        "thirteen milliseconds of headroom that nobody has observed"
    );
    assert_ne!(
        SCAFFOLD_BOOT_TIME_MS, BOOT_TIME_TARGET_MS,
        "the scaffold literal and the target are different recorded figures"
    );
}
